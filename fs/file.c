/*
 *  linux/fs/file.c
 *
 *  Copyright (C) 1998-1999, Stephen Tweedie and Bill Hawes
 *
 *  Manage the dynamic fd arrays in the process files_struct.
 */

#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/bio.h>
#include <linux/kfifo.h>
#include <trace/events/fsdbg.h>


unsigned int sysctl_nr_open __read_mostly = 1024*1024;
unsigned int sysctl_nr_open_min = BITS_PER_LONG;
/* our min() is unusable in constant expressions ;-/ */
#define __const_min(x, y) ((x) < (y) ? (x) : (y))
unsigned int sysctl_nr_open_max =
	__const_min(INT_MAX, ~(size_t)0/sizeof(void *)) & -BITS_PER_LONG;
unsigned int fs_dump;

static void *alloc_fdmem(size_t size)
{
	/*
	 * Very large allocations can stress page reclaim, so fall back to
	 * vmalloc() if the allocation size will be considered "large" by the VM.
	 */
	if (size <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)) {
		void *data = kmalloc(size, GFP_KERNEL_ACCOUNT |
				     __GFP_NOWARN | __GFP_NORETRY);
		if (data != NULL)
			return data;
	}
	return __vmalloc(size, GFP_KERNEL_ACCOUNT | __GFP_HIGHMEM, PAGE_KERNEL);
}

static void __free_fdtable(struct fdtable *fdt)
{
	kvfree(fdt->fd);
	kvfree(fdt->open_fds);
	kfree(fdt);
}

static void free_fdtable_rcu(struct rcu_head *rcu)
{
	__free_fdtable(container_of(rcu, struct fdtable, rcu));
}

#define BITBIT_NR(nr)	BITS_TO_LONGS(BITS_TO_LONGS(nr))
#define BITBIT_SIZE(nr)	(BITBIT_NR(nr) * sizeof(long))

/*
 * Copy 'count' fd bits from the old table to the new table and clear the extra
 * space if any.  This does not copy the file pointers.  Called with the files
 * spinlock held for write.
 */
static void copy_fd_bitmaps(struct fdtable *nfdt, struct fdtable *ofdt,
			    unsigned int count)
{
	unsigned int cpy, set;

	cpy = count / BITS_PER_BYTE;
	set = (nfdt->max_fds - count) / BITS_PER_BYTE;
	memcpy(nfdt->open_fds, ofdt->open_fds, cpy);
	memset((char *)nfdt->open_fds + cpy, 0, set);
	memcpy(nfdt->close_on_exec, ofdt->close_on_exec, cpy);
	memset((char *)nfdt->close_on_exec + cpy, 0, set);

	cpy = BITBIT_SIZE(count);
	set = BITBIT_SIZE(nfdt->max_fds) - cpy;
	memcpy(nfdt->full_fds_bits, ofdt->full_fds_bits, cpy);
	memset((char *)nfdt->full_fds_bits + cpy, 0, set);
}

/*
 * Copy all file descriptors from the old table to the new, expanded table and
 * clear the extra space.  Called with the files spinlock held for write.
 */
static void copy_fdtable(struct fdtable *nfdt, struct fdtable *ofdt)
{
	unsigned int cpy, set;

	BUG_ON(nfdt->max_fds < ofdt->max_fds);

	cpy = ofdt->max_fds * sizeof(struct file *);
	set = (nfdt->max_fds - ofdt->max_fds) * sizeof(struct file *);
	memcpy(nfdt->fd, ofdt->fd, cpy);
	memset((char *)nfdt->fd + cpy, 0, set);

	copy_fd_bitmaps(nfdt, ofdt, ofdt->max_fds);
}

static struct fdtable * alloc_fdtable(unsigned int nr)
{
	struct fdtable *fdt;
	void *data;

	/*
	 * Figure out how many fds we actually want to support in this fdtable.
	 * Allocation steps are keyed to the size of the fdarray, since it
	 * grows far faster than any of the other dynamic data. We try to fit
	 * the fdarray into comfortable page-tuned chunks: starting at 1024B
	 * and growing in powers of two from there on.
	 */
	nr /= (1024 / sizeof(struct file *));
	nr = roundup_pow_of_two(nr + 1);
	nr *= (1024 / sizeof(struct file *));
	/*
	 * Note that this can drive nr *below* what we had passed if sysctl_nr_open
	 * had been set lower between the check in expand_files() and here.  Deal
	 * with that in caller, it's cheaper that way.
	 *
	 * We make sure that nr remains a multiple of BITS_PER_LONG - otherwise
	 * bitmaps handling below becomes unpleasant, to put it mildly...
	 */
	if (unlikely(nr > sysctl_nr_open))
		nr = ((sysctl_nr_open - 1) | (BITS_PER_LONG - 1)) + 1;

	fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL_ACCOUNT);
	if (!fdt)
		goto out;
	fdt->max_fds = nr;
	data = alloc_fdmem(nr * sizeof(struct file *));
	if (!data)
		goto out_fdt;
	fdt->fd = data;

	data = alloc_fdmem(max_t(size_t,
				 2 * nr / BITS_PER_BYTE + BITBIT_SIZE(nr), L1_CACHE_BYTES));
	if (!data)
		goto out_arr;
	fdt->open_fds = data;
	data += nr / BITS_PER_BYTE;
	fdt->close_on_exec = data;
	data += nr / BITS_PER_BYTE;
	fdt->full_fds_bits = data;

	return fdt;

out_arr:
	kvfree(fdt->fd);
out_fdt:
	kfree(fdt);
out:
	return NULL;
}

/*
 * Expand the file descriptor table.
 * This function will allocate a new fdtable and both fd array and fdset, of
 * the given size.
 * Return <0 error code on error; 1 on successful completion.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
static int expand_fdtable(struct files_struct *files, unsigned int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct fdtable *new_fdt, *cur_fdt;

	spin_unlock(&files->file_lock);
	new_fdt = alloc_fdtable(nr);

	/* make sure all __fd_install() have seen resize_in_progress
	 * or have finished their rcu_read_lock_sched() section.
	 */
	if (atomic_read(&files->count) > 1)
		synchronize_sched();

	spin_lock(&files->file_lock);
	if (!new_fdt)
		return -ENOMEM;
	/*
	 * extremely unlikely race - sysctl_nr_open decreased between the check in
	 * caller and alloc_fdtable().  Cheaper to catch it here...
	 */
	if (unlikely(new_fdt->max_fds <= nr)) {
		__free_fdtable(new_fdt);
		return -EMFILE;
	}
	cur_fdt = files_fdtable(files);
	BUG_ON(nr < cur_fdt->max_fds);
	copy_fdtable(new_fdt, cur_fdt);
	rcu_assign_pointer(files->fdt, new_fdt);
	if (cur_fdt != &files->fdtab)
		call_rcu(&cur_fdt->rcu, free_fdtable_rcu);
	/* coupled with smp_rmb() in __fd_install() */
	smp_wmb();
	return 1;
}

/*
 * Expand files.
 * This function will expand the file structures, if the requested size exceeds
 * the current capacity and there is room for expansion.
 * Return <0 error code on error; 0 when nothing done; 1 when files were
 * expanded and execution may have blocked.
 * The files->file_lock should be held on entry, and will be held on exit.
 */
static int expand_files(struct files_struct *files, unsigned int nr)
	__releases(files->file_lock)
	__acquires(files->file_lock)
{
	struct fdtable *fdt;
	int expanded = 0;

repeat:
	fdt = files_fdtable(files);

	/* Do we need to expand? */
	if (nr < fdt->max_fds)
		return expanded;

	/* Can we expand? */
	if (nr >= sysctl_nr_open)
		return -EMFILE;

	if (unlikely(files->resize_in_progress)) {
		spin_unlock(&files->file_lock);
		expanded = 1;
		wait_event(files->resize_wait, !files->resize_in_progress);
		spin_lock(&files->file_lock);
		goto repeat;
	}

	/* All good, so we try */
	files->resize_in_progress = true;
	expanded = expand_fdtable(files, nr);
	files->resize_in_progress = false;

	wake_up_all(&files->resize_wait);
	return expanded;
}

static inline void __set_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->close_on_exec);
}

static inline void __clear_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
	if (test_bit(fd, fdt->close_on_exec))
		__clear_bit(fd, fdt->close_on_exec);
}

static inline void __set_open_fd(unsigned int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->open_fds);
	fd /= BITS_PER_LONG;
	if (!~fdt->open_fds[fd])
		__set_bit(fd, fdt->full_fds_bits);
}

static inline void __clear_open_fd(unsigned int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->open_fds);
	__clear_bit(fd / BITS_PER_LONG, fdt->full_fds_bits);
}

static unsigned int count_open_files(struct fdtable *fdt)
{
	unsigned int size = fdt->max_fds;
	unsigned int i;

	/* Find the last open fd */
	for (i = size / BITS_PER_LONG; i > 0; ) {
		if (fdt->open_fds[--i])
			break;
	}
	i = (i + 1) * BITS_PER_LONG;
	return i;
}

/*
 * Allocate a new files structure and copy contents from the
 * passed in files structure.
 * errorp will be valid only when the returned files_struct is NULL.
 */
struct files_struct *dup_fd(struct files_struct *oldf, int *errorp)
{
	struct files_struct *newf;
	struct file **old_fds, **new_fds;
	unsigned int open_files, i;
	struct fdtable *old_fdt, *new_fdt;

	*errorp = -ENOMEM;
	newf = kmem_cache_alloc(files_cachep, GFP_KERNEL);
	if (!newf)
		goto out;

	atomic_set(&newf->count, 1);

	spin_lock_init(&newf->file_lock);
	newf->resize_in_progress = false;
	init_waitqueue_head(&newf->resize_wait);
	newf->next_fd = 0;
	new_fdt = &newf->fdtab;
	new_fdt->max_fds = NR_OPEN_DEFAULT;
	new_fdt->close_on_exec = newf->close_on_exec_init;
	new_fdt->open_fds = newf->open_fds_init;
	new_fdt->full_fds_bits = newf->full_fds_bits_init;
	new_fdt->fd = &newf->fd_array[0];

	spin_lock(&oldf->file_lock);
	old_fdt = files_fdtable(oldf);
	open_files = count_open_files(old_fdt);

	/*
	 * Check whether we need to allocate a larger fd array and fd set.
	 */
	while (unlikely(open_files > new_fdt->max_fds)) {
		spin_unlock(&oldf->file_lock);

		if (new_fdt != &newf->fdtab)
			__free_fdtable(new_fdt);

		new_fdt = alloc_fdtable(open_files - 1);
		if (!new_fdt) {
			*errorp = -ENOMEM;
			goto out_release;
		}

		/* beyond sysctl_nr_open; nothing to do */
		if (unlikely(new_fdt->max_fds < open_files)) {
			__free_fdtable(new_fdt);
			*errorp = -EMFILE;
			goto out_release;
		}

		/*
		 * Reacquire the oldf lock and a pointer to its fd table
		 * who knows it may have a new bigger fd table. We need
		 * the latest pointer.
		 */
		spin_lock(&oldf->file_lock);
		old_fdt = files_fdtable(oldf);
		open_files = count_open_files(old_fdt);
	}

	copy_fd_bitmaps(new_fdt, old_fdt, open_files);

	old_fds = old_fdt->fd;
	new_fds = new_fdt->fd;

	for (i = open_files; i != 0; i--) {
		struct file *f = *old_fds++;
		if (f) {
			get_file(f);
		} else {
			/*
			 * The fd may be claimed in the fd bitmap but not yet
			 * instantiated in the files array if a sibling thread
			 * is partway through open().  So make sure that this
			 * fd is available to the new process.
			 */
			__clear_open_fd(open_files - i, new_fdt);
		}
		rcu_assign_pointer(*new_fds++, f);
	}
	spin_unlock(&oldf->file_lock);

	/* clear the remainder */
	memset(new_fds, 0, (new_fdt->max_fds - open_files) * sizeof(struct file *));

	rcu_assign_pointer(newf->fdt, new_fdt);

	return newf;

out_release:
	kmem_cache_free(files_cachep, newf);
out:
	return NULL;
}

static struct fdtable *close_files(struct files_struct * files)
{
	/*
	 * It is safe to dereference the fd table without RCU or
	 * ->file_lock because this is the last reference to the
	 * files structure.
	 */
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);
	unsigned int i, j = 0;

	for (;;) {
		unsigned long set;
		i = j * BITS_PER_LONG;
		if (i >= fdt->max_fds)
			break;
		set = fdt->open_fds[j++];
		while (set) {
			if (set & 1) {
				struct file * file = xchg(&fdt->fd[i], NULL);
				if (file) {
					filp_close(file, files);
					cond_resched_rcu_qs();
				}
			}
			i++;
			set >>= 1;
		}
	}

	return fdt;
}

struct files_struct *get_files_struct(struct task_struct *task)
{
	struct files_struct *files;

	task_lock(task);
	files = task->files;
	if (files)
		atomic_inc(&files->count);
	task_unlock(task);

	return files;
}

void put_files_struct(struct files_struct *files)
{
	if (atomic_dec_and_test(&files->count)) {
		struct fdtable *fdt = close_files(files);

		/* free the arrays if they are not embedded */
		if (fdt != &files->fdtab)
			__free_fdtable(fdt);
		kmem_cache_free(files_cachep, files);
	}
}

void reset_files_struct(struct files_struct *files)
{
	struct task_struct *tsk = current;
	struct files_struct *old;

	old = tsk->files;
	task_lock(tsk);
	tsk->files = files;
	task_unlock(tsk);
	put_files_struct(old);
}

void exit_files(struct task_struct *tsk)
{
	struct files_struct * files = tsk->files;

	if (files) {
		task_lock(tsk);
		tsk->files = NULL;
		task_unlock(tsk);
		put_files_struct(files);
	}
}

struct files_struct init_files = {
	.count		= ATOMIC_INIT(1),
	.fdt		= &init_files.fdtab,
	.fdtab		= {
		.max_fds	= NR_OPEN_DEFAULT,
		.fd		= &init_files.fd_array[0],
		.close_on_exec	= init_files.close_on_exec_init,
		.open_fds	= init_files.open_fds_init,
		.full_fds_bits	= init_files.full_fds_bits_init,
	},
	.file_lock	= __SPIN_LOCK_UNLOCKED(init_files.file_lock),
};

static unsigned int find_next_fd(struct fdtable *fdt, unsigned int start)
{
	unsigned int maxfd = fdt->max_fds;
	unsigned int maxbit = maxfd / BITS_PER_LONG;
	unsigned int bitbit = start / BITS_PER_LONG;

	bitbit = find_next_zero_bit(fdt->full_fds_bits, maxbit, bitbit) * BITS_PER_LONG;
	if (bitbit > maxfd)
		return maxfd;
	if (bitbit > start)
		start = bitbit;
	return find_next_zero_bit(fdt->open_fds, maxfd, start);
}

/*
 * allocate a file descriptor, mark it busy.
 */
int __alloc_fd(struct files_struct *files,
	       unsigned start, unsigned end, unsigned flags)
{
	unsigned int fd;
	int error;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
repeat:
	fdt = files_fdtable(files);
	fd = start;
	if (fd < files->next_fd)
		fd = files->next_fd;

	if (fd < fdt->max_fds)
		fd = find_next_fd(fdt, fd);

	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	error = -EMFILE;
	if (fd >= end)
		goto out;

	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	/*
	 * If we needed to expand the fs array we
	 * might have blocked - try again.
	 */
	if (error)
		goto repeat;

	if (start <= files->next_fd)
		files->next_fd = fd + 1;

	__set_open_fd(fd, fdt);
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	error = fd;
#if 1
	/* Sanity check */
	if (rcu_access_pointer(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif

out:
	spin_unlock(&files->file_lock);
	return error;
}

static int alloc_fd(unsigned start, unsigned flags)
{
	return __alloc_fd(current->files, start, rlimit(RLIMIT_NOFILE), flags);
}

int get_unused_fd_flags(unsigned flags)
{
	return __alloc_fd(current->files, 0, rlimit(RLIMIT_NOFILE), flags);
}
EXPORT_SYMBOL(get_unused_fd_flags);

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__clear_open_fd(fd, fdt);
	if (fd < files->next_fd)
		files->next_fd = fd;
}

void put_unused_fd(unsigned int fd)
{
	struct files_struct *files = current->files;
	spin_lock(&files->file_lock);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
}

EXPORT_SYMBOL(put_unused_fd);

/*
 * Install a file pointer in the fd array.
 *
 * The VFS is full of places where we drop the files lock between
 * setting the open_fds bitmap and installing the file in the file
 * array.  At any such point, we are vulnerable to a dup2() race
 * installing a file in the array before us.  We need to detect this and
 * fput() the struct file we are about to overwrite in this case.
 *
 * It should never happen - if we allow dup2() do it, _really_ bad things
 * will follow.
 *
 * NOTE: __fd_install() variant is really, really low-level; don't
 * use it unless you are forced to by truly lousy API shoved down
 * your throat.  'files' *MUST* be either current->files or obtained
 * by get_files_struct(current) done by whoever had given it to you,
 * or really bad things will happen.  Normally you want to use
 * fd_install() instead.
 */

void __fd_install(struct files_struct *files, unsigned int fd,
		struct file *file)
{
	struct fdtable *fdt;

	might_sleep();
	rcu_read_lock_sched();

	while (unlikely(files->resize_in_progress)) {
		rcu_read_unlock_sched();
		wait_event(files->resize_wait, !files->resize_in_progress);
		rcu_read_lock_sched();
	}
	/* coupled with smp_wmb() in expand_fdtable() */
	smp_rmb();
	fdt = rcu_dereference_sched(files->fdt);
	BUG_ON(fdt->fd[fd] != NULL);
	rcu_assign_pointer(fdt->fd[fd], file);
	rcu_read_unlock_sched();
}

void fd_install(unsigned int fd, struct file *file)
{
	__fd_install(current->files, fd, file);
}

EXPORT_SYMBOL(fd_install);

/*
 * The same warnings as for __alloc_fd()/__fd_install() apply here...
 */
int __close_fd(struct files_struct *files, unsigned fd)
{
	struct file *file;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds)
		goto out_unlock;
	file = fdt->fd[fd];
	if (!file)
		goto out_unlock;
	rcu_assign_pointer(fdt->fd[fd], NULL);
	__clear_close_on_exec(fd, fdt);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
	return filp_close(file, files);

out_unlock:
	spin_unlock(&files->file_lock);
	return -EBADF;
}

void do_close_on_exec(struct files_struct *files)
{
	unsigned i;
	struct fdtable *fdt;

	/* exec unshares first */
	spin_lock(&files->file_lock);
	for (i = 0; ; i++) {
		unsigned long set;
		unsigned fd = i * BITS_PER_LONG;
		fdt = files_fdtable(files);
		if (fd >= fdt->max_fds)
			break;
		set = fdt->close_on_exec[i];
		if (!set)
			continue;
		fdt->close_on_exec[i] = 0;
		for ( ; set ; fd++, set >>= 1) {
			struct file *file;
			if (!(set & 1))
				continue;
			file = fdt->fd[fd];
			if (!file)
				continue;
			rcu_assign_pointer(fdt->fd[fd], NULL);
			__put_unused_fd(files, fd);
			spin_unlock(&files->file_lock);
			filp_close(file, files);
			cond_resched();
			spin_lock(&files->file_lock);
		}

	}
	spin_unlock(&files->file_lock);
}

static struct file *__fget(unsigned int fd, fmode_t mask)
{
	struct files_struct *files = current->files;
	struct file *file;

	rcu_read_lock();
loop:
	file = fcheck_files(files, fd);
	if (file) {
		/* File object ref couldn't be taken.
		 * dup2() atomicity guarantee is the reason
		 * we loop to catch the new file (or NULL pointer)
		 */
		if (file->f_mode & mask)
			file = NULL;
		else if (!get_file_rcu(file))
			goto loop;
	}
	rcu_read_unlock();

	return file;
}

struct file *fget(unsigned int fd)
{
	return __fget(fd, FMODE_PATH);
}
EXPORT_SYMBOL(fget);

struct file *fget_raw(unsigned int fd)
{
	return __fget(fd, 0);
}
EXPORT_SYMBOL(fget_raw);

/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared.
 *
 * You can use this instead of fget if you satisfy all of the following
 * conditions:
 * 1) You must call fput_light before exiting the syscall and returning control
 *    to userspace (i.e. you cannot remember the returned struct file * after
 *    returning to userspace).
 * 2) You must not call filp_close on the returned struct file * in between
 *    calls to fget_light and fput_light.
 * 3) You must not clone the current task in between the calls to fget_light
 *    and fput_light.
 *
 * The fput_needed flag returned by fget_light should be passed to the
 * corresponding fput_light.
 */
static unsigned long __fget_light(unsigned int fd, fmode_t mask)
{
	struct files_struct *files = current->files;
	struct file *file;

	if (atomic_read(&files->count) == 1) {
		file = __fcheck_files(files, fd);
		if (!file || unlikely(file->f_mode & mask))
			return 0;
		return (unsigned long)file;
	} else {
		file = __fget(fd, mask);
		if (!file)
			return 0;
		return FDPUT_FPUT | (unsigned long)file;
	}
}
unsigned long __fdget(unsigned int fd)
{
	return __fget_light(fd, FMODE_PATH);
}
EXPORT_SYMBOL(__fdget);

unsigned long __fdget_raw(unsigned int fd)
{
	return __fget_light(fd, 0);
}

unsigned long __fdget_pos(unsigned int fd)
{
	unsigned long v = __fdget(fd);
	struct file *file = (struct file *)(v & ~3);

	if (file && (file->f_mode & FMODE_ATOMIC_POS)) {
		if (file_count(file) > 1) {
			v |= FDPUT_POS_UNLOCK;
			mutex_lock(&file->f_pos_lock);
		}
	}
	return v;
}

void __f_unlock_pos(struct file *f)
{
	mutex_unlock(&f->f_pos_lock);
}

/*
 * We only lock f_pos if we have threads or if the file might be
 * shared with another process. In both cases we'll have an elevated
 * file count (done either by fdget() or by fork()).
 */

void set_close_on_exec(unsigned int fd, int flag)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (flag)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	spin_unlock(&files->file_lock);
}

bool get_close_on_exec(unsigned int fd)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	bool res;
	rcu_read_lock();
	fdt = files_fdtable(files);
	res = close_on_exec(fd, fdt);
	rcu_read_unlock();
	return res;
}

static int do_dup2(struct files_struct *files,
	struct file *file, unsigned fd, unsigned flags)
__releases(&files->file_lock)
{
	struct file *tofree;
	struct fdtable *fdt;

	/*
	 * We need to detect attempts to do dup2() over allocated but still
	 * not finished descriptor.  NB: OpenBSD avoids that at the price of
	 * extra work in their equivalent of fget() - they insert struct
	 * file immediately after grabbing descriptor, mark it larval if
	 * more work (e.g. actual opening) is needed and make sure that
	 * fget() treats larval files as absent.  Potentially interesting,
	 * but while extra work in fget() is trivial, locking implications
	 * and amount of surgery on open()-related paths in VFS are not.
	 * FreeBSD fails with -EBADF in the same situation, NetBSD "solution"
	 * deadlocks in rather amusing ways, AFAICS.  All of that is out of
	 * scope of POSIX or SUS, since neither considers shared descriptor
	 * tables and this condition does not arise without those.
	 */
	fdt = files_fdtable(files);
	tofree = fdt->fd[fd];
	if (!tofree && fd_is_open(fd, fdt))
		goto Ebusy;
	get_file(file);
	rcu_assign_pointer(fdt->fd[fd], file);
	__set_open_fd(fd, fdt);
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	spin_unlock(&files->file_lock);

	if (tofree)
		filp_close(tofree, files);

	return fd;

Ebusy:
	spin_unlock(&files->file_lock);
	return -EBUSY;
}

int replace_fd(unsigned fd, struct file *file, unsigned flags)
{
	int err;
	struct files_struct *files = current->files;

	if (!file)
		return __close_fd(files, fd);

	if (fd >= rlimit(RLIMIT_NOFILE))
		return -EBADF;

	spin_lock(&files->file_lock);
	err = expand_files(files, fd);
	if (unlikely(err < 0))
		goto out_unlock;
	return do_dup2(files, file, fd, flags);

out_unlock:
	spin_unlock(&files->file_lock);
	return err;
}

SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags)
{
	int err = -EBADF;
	struct file *file;
	struct files_struct *files = current->files;

	if ((flags & ~O_CLOEXEC) != 0)
		return -EINVAL;

	if (unlikely(oldfd == newfd))
		return -EINVAL;

	if (newfd >= rlimit(RLIMIT_NOFILE))
		return -EBADF;

	spin_lock(&files->file_lock);
	err = expand_files(files, newfd);
	file = fcheck(oldfd);
	if (unlikely(!file))
		goto Ebadf;
	if (unlikely(err < 0)) {
		if (err == -EMFILE)
			goto Ebadf;
		goto out_unlock;
	}
	return do_dup2(files, file, newfd, flags);

Ebadf:
	err = -EBADF;
out_unlock:
	spin_unlock(&files->file_lock);
	return err;
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
	if (unlikely(newfd == oldfd)) { /* corner case */
		struct files_struct *files = current->files;
		int retval = oldfd;

		rcu_read_lock();
		if (!fcheck_files(files, oldfd))
			retval = -EBADF;
		rcu_read_unlock();
		return retval;
	}
	return sys_dup3(oldfd, newfd, 0);
}

SYSCALL_DEFINE1(dup, unsigned int, fildes)
{
	int ret = -EBADF;
	struct file *file = fget_raw(fildes);

	if (file) {
		ret = get_unused_fd_flags(0);
		if (ret >= 0)
			fd_install(ret, file);
		else
			fput(file);
	}
	return ret;
}

int f_dupfd(unsigned int from, struct file *file, unsigned flags)
{
	int err;
	if (from >= rlimit(RLIMIT_NOFILE))
		return -EINVAL;
	err = alloc_fd(from, flags);
	if (err >= 0) {
		get_file(file);
		fd_install(err, file);
	}
	return err;
}

int iterate_fd(struct files_struct *files, unsigned n,
		int (*f)(const void *, struct file *, unsigned),
		const void *p)
{
	struct fdtable *fdt;
	int res = 0;
	if (!files)
		return 0;
	spin_lock(&files->file_lock);
	for (fdt = files_fdtable(files); n < fdt->max_fds; n++) {
		struct file *file;
		file = rcu_dereference_check_fdtable(files, fdt->fd[n]);
		if (!file)
			continue;
		res = f(p, file, n);
		if (res)
			break;
	}
	spin_unlock(&files->file_lock);
	return res;
}
EXPORT_SYMBOL(iterate_fd);

// get full path from inode
char *getfullpath(struct inode *inod,char* buffer,int len)
{
	struct hlist_node* plist = NULL;
	struct dentry* tmp = NULL;
	struct dentry* dent = NULL;
	char* pbuf;
	struct inode* pinode = inod;

	buffer[len - 1] = '\0';
	if(pinode == NULL)
		return NULL;

	hlist_for_each(plist,&pinode->i_dentry)
	{
		tmp = hlist_entry(plist,struct dentry,d_u.d_alias);
		if(tmp->d_inode == pinode)
		{
			dent = tmp;
			break;
		}
	}
	if(dent == NULL)
	{
		return NULL;
	}

	pbuf = dentry_path(dent, buffer, len);
	if(IS_ERR(pbuf))
		pbuf = NULL;
	 return pbuf;
}

// print in ftrace
int ftrace_print(char const *fmt, ...)
{
	char buf[512];
	int len;
	va_list ap;

	if((fs_dump&FS_LOG_FTRACE_PRINT) == 0)
		return 0;

	va_start(ap, fmt);
	len = vsprintf(buf, fmt, ap);
	va_end(ap);
	trace_fsdbg_print(buf);
	return len;
}

#ifdef CONFIG_FILESYSTEM_STATISTICS

struct delayed_work fsdbg_dw_inodes_dump;
struct delayed_work fsdbg_dw_file_write;

struct kfifo fsdbg_fifo;
#define FSDBG_FIFO_SIZE  0x10000
#define FSDBG_WRITE_BUF_SIZE  0x4000

enum {
	FSDBG_F2FS = 1<<0,
	FSDBG_EXT4 = 1<<1
};

int fsdbg_flag_last_data;
int fsdbg_flag_dump_to_file;
int fsdbg_flag_fs_filter;

char fsdbg_filename[64];

void fsdbg_rw_info_to_fifo(struct inode *inod)
{
	char line_buf[512];
	u64 clock;
	int fs_type;

	// get inode fs type
	if(inod->i_sb->s_magic == EXT4_SUPER_MAGIC)
	{
		fs_type = FSDBG_EXT4;
	}
	else if(inod->i_sb->s_magic == F2FS_SUPER_MAGIC)
	{
		fs_type = FSDBG_F2FS;
	}
	else
	{
		fs_type = 0;
	}

	if((fsdbg_flag_fs_filter & fs_type)==0)
		return;

	if((inod->i_write_times!=0)||(inod->i_read_times!=0))
	{
		if(inod->i_filename == UNINIT_FILE_NAME)
		{
			printk("ino=%lu, name=%s\n", inod->i_ino, "UNINIT_FILE_NAME");
		}
		else
		{
			clock = local_clock();
			clock /=1000;
			snprintf(line_buf, sizeof(line_buf), "[%5llu.%06llu] %s(%d): w_times=%llu, w_count=%llu, r_times=%llu, r_count=%llu, ino=%lu, name=%s\n",
				clock/1000000, clock%1000000, current->comm, current->pid, inod->i_write_times, inod->i_write_count,inod->i_read_times, inod->i_read_count, inod->i_ino, inod->i_filename);
			//pr_debug("%s", line_buf);
			kfifo_in(&fsdbg_fifo, line_buf, strlen(line_buf));
		}

		// clear count for next time use
		inod->i_write_count = 0;
		inod->i_read_count = 0;
		inod->i_write_times = 0;
		inod->i_read_times = 0;
		inod->i_filename = UNINIT_FILE_NAME;
	}
}

int fsdbg_write_to_file(void)
{
	int fifo_len;

	// disable dump to file
	if(fsdbg_flag_dump_to_file == 0)
		return 0;

	fifo_len = kfifo_len(&fsdbg_fifo);

	if((fifo_len > FSDBG_FIFO_SIZE/2)||(fsdbg_flag_last_data !=0 ))
	{
		schedule_delayed_work(&fsdbg_dw_file_write, 0);
	}

	// fifo len over 3/4 return flag
	if(fifo_len > 3*FSDBG_FIFO_SIZE/4)
		return 1;
	else
		return 0;
}
static void handler_inodes_dump(struct work_struct *work)
{
	// disable dump to file
	if(fsdbg_flag_dump_to_file == 0)
		return;

	fsdbg_active_inodes_dump();
}

static void handler_log_file_write(struct work_struct *work)
{
	u64 timestamp;
	mm_segment_t old_fs;
	int fd, fifo_len;
	char *write_buf;
	int write_size;

	// disable dump to file
	if(fsdbg_flag_dump_to_file == 0)
		return;

	if(fsdbg_filename[0]==0)
	{
		// create file rw log file
		timestamp = ktime_get().tv64;
		timestamp /= 1000;
		sprintf(fsdbg_filename, "/data/misc/logd/fslog_%llu_%06llu.log", timestamp/1000000, timestamp%1000000 );
		//printk("fsdbg_filename=%s\n", fsdbg_filename);

		old_fs = get_fs();
		set_fs(KERNEL_DS);
		fd = sys_open(fsdbg_filename, O_CREAT|O_WRONLY, 0666);
		if(fd>=0)
		{
			sys_close(fd);
		}
		set_fs(old_fs);
	}

	//write log into file
	fifo_len = kfifo_len(&fsdbg_fifo);
	if(fifo_len == 0)
		goto _exit;
	if((fsdbg_flag_last_data==0) && (fifo_len<FSDBG_WRITE_BUF_SIZE))
		goto _exit;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	fd = sys_open(fsdbg_filename, O_APPEND|O_WRONLY, 0666);
	if(fd < 0)
	{
		set_fs(old_fs);
		printk("open %s error, fd = %d\n", fsdbg_filename, fd);
		goto _exit;
	}
	write_buf = kmalloc(FSDBG_WRITE_BUF_SIZE, GFP_KERNEL);
	if(write_buf == NULL)
	{
		set_fs(old_fs);
		printk("write_buf kmalloc error\n");
		goto _exit;
	}
	do
	{
		if(fifo_len > FSDBG_WRITE_BUF_SIZE)
		{
			write_size = FSDBG_WRITE_BUF_SIZE;
		}
		else if(fsdbg_flag_last_data)
		{
			write_size = fifo_len;
			fsdbg_filename[0] = 0;
			fsdbg_flag_last_data = 0;
		}
		else
		{
			break;
		}

		write_size = kfifo_out(&fsdbg_fifo, write_buf, write_size);
		if(write_size < 0)
			break;

		sys_write(fd, write_buf, write_size);
		fifo_len = kfifo_len(&fsdbg_fifo);
	}while(fifo_len > 0);

	sys_close(fd);
	set_fs(old_fs);
	kfree(write_buf);

_exit:
	return;
}

#endif //CONFIG_FILESYSTEM_STATISTICS

#ifdef CONFIG_IO_MONITOR
#define DEFAULT_IOM_THRESHOLD (300*1000000)    // 300 ms
s64 iom_threshold;
unsigned int iom_mask;

struct kfifo iom_log_fifo_blk;
struct kfifo iom_log_fifo_fs;

spinlock_t iom_log_fifo_lock_blk;
struct mutex iom_log_fifo_lock_fs;
#define IOM_LOCK_SPINLOCK 	0
#define IOM_LOCK_MUTEX 	1

void iom_bio_end(struct bio *bio)
{
	ktime_t end, start;
	ktime_t duration_ktime;
	int duration;
	char filename_buf[512], *filename;
	uint32_t inode=0;
	char line_buf[512];
	int fifo_len, len, size;

	// get the bio process time
	start.tv64 = bio->bi_starttime;
	end = ktime_get();
	duration_ktime = ktime_sub(end, start);
	if(duration_ktime.tv64 < iom_threshold)
		return;

	// convert ns to ms
	duration = duration_ktime.tv64/1000000;
	// get full path filename
	filename = get_bio_related_filename(bio, filename_buf,sizeof(filename_buf),&inode);

	// Insert log to FIFO
	start.tv64 = start.tv64/1000;
	if(filename)
	{
		snprintf(line_buf, sizeof(line_buf), "[%5llu.%06llu] %s(%d): BLK, %s, pos=%lu, len=%u, err=%d, duration=%d, ino=%u, name=%s\n",
			start.tv64/1000000, start.tv64%1000000, bio->bi_taskname, bio->bi_pid, op_is_write(bio_op(bio)) ? "WRITE" : "READ",bio->bi_iter.bi_sector, bio_sectors(bio), bio->bi_error, duration, inode, filename);
	}
	else
	{
		snprintf(line_buf, sizeof(line_buf), "[%5llu.%06llu] %s(%d): BLK, %s, pos=%lu, len=%u, err=%d, duration=%d, ino=%u, name=%s\n",
			start.tv64/1000000, start.tv64%1000000, bio->bi_taskname, bio->bi_pid, op_is_write(bio_op(bio)) ? "WRITE" : "READ",bio->bi_iter.bi_sector, bio_sectors(bio), bio->bi_error, duration, inode, "NULL");
	}
	//pr_debug("%s", line_buf);
	spin_lock(&iom_log_fifo_lock_blk);
	kfifo_in(&iom_log_fifo_blk, line_buf, strlen(line_buf));
	spin_unlock(&iom_log_fifo_lock_blk);
	// If fifo full discard old log
	fifo_len = kfifo_len(&iom_log_fifo_blk);
	if(fifo_len > IOM_FIFO_SIZE - IOM_FIFO_RSV_SIZE)
	{
		len = IOM_FIFO_RSV_SIZE;
		while(len > 0)
		{
			spin_lock(&iom_log_fifo_lock_blk);
			size = kfifo_out(&iom_log_fifo_blk, line_buf, sizeof(line_buf));
			spin_unlock(&iom_log_fifo_lock_blk);
			if(size < 0)
			{
				break;
			}
			else
			{
				len -= sizeof(line_buf);
			}
		}
	}

}

void iom_bio_start(struct bio *bio)
{
	ktime_t ts;

	ts = ktime_get();
	bio->bi_starttime  = ts.tv64;
	bio->bi_pid = current->pid;
	memcpy(bio->bi_taskname, current->comm, sizeof(bio->bi_taskname));
}

static void __iom_log_file_write(char* filename, struct kfifo* logfifo,  void* fifo_lock, int lock_type)
{
	mm_segment_t old_fs;
	int fd, fifo_len;
	char *write_buf=NULL;
	int write_size;

	// open file
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	fd = sys_open(filename, O_CREAT|O_WRONLY|O_TRUNC, 0666);
	if(fd < 0)
	{
		printk("open iomonitor.log error, fd = %d\n", fd);
		goto _exit;
	}

	//get fifo len
	fifo_len = kfifo_len(logfifo);
	if(fifo_len == 0)
		goto _exit;

	write_buf = kmalloc(IOM_FIFO_SIZE, GFP_KERNEL);
	if(write_buf == NULL)
	{
		printk("write_buf kmalloc error\n");
		goto _exit;
	}

	// get data from FIFO
	if(lock_type == IOM_LOCK_SPINLOCK)
	{
		spin_lock_irq((spinlock_t*)fifo_lock);
	}
	else
	{
		mutex_lock((struct mutex*)fifo_lock);
	}
	write_size = kfifo_out(logfifo, write_buf, IOM_FIFO_SIZE);
	if(lock_type == IOM_LOCK_SPINLOCK)
	{
		spin_unlock_irq((spinlock_t*)fifo_lock);
	}
	else
	{
		mutex_unlock((struct mutex*)fifo_lock);
	}
	if(write_size < 0)
		goto _exit;

	// write to file
	sys_write(fd, write_buf, write_size);
	sys_close(fd);

_exit:
	set_fs(old_fs);
	if(write_buf)
		kfree(write_buf);
	return;
}

static void iom_log_file_write(void)
{
	__iom_log_file_write("/data/misc/logd/iomonitor_blk.log", &iom_log_fifo_blk, &iom_log_fifo_lock_blk, IOM_LOCK_SPINLOCK);
	__iom_log_file_write("/data/misc/logd/iomonitor_fs.log", &iom_log_fifo_fs, &iom_log_fifo_lock_fs, IOM_LOCK_MUTEX);
}

#endif //CONFIG_IO_MONITOR

static ssize_t command_read(struct file *filp, char __user *buffer,
				size_t count, loff_t *ppos)
{
	char buf[1024];

	snprintf(buf, sizeof(buf),
			"\nFile system debug kits V1.0 	 Author: lizhigang@smartisan.com\n\n"
			"Support commands: \n"
			"       test               Test command\n"
#ifdef CONFIG_FILESYSTEM_STATISTICS
			"       inodes_dump        Dump all inodes rw information into file\n"
			"       disable_dump       Disable dump function\n"
			"       enable_dump        Enable dump function\n"
			"       fs=f2fs            Only dump F2FS type, such as data partition\n"
			"       fs=ext4            Only dump EXT4 type, such as system partition\n"
			"       fs=f2fs_ext4       Dump F2FS and EXT4\n"
#endif

#ifdef CONFIG_IO_MONITOR
			"       iom_dump                Dump long IO log into file\n"
			"       iom_mask=XX             Set moniter mask, default is block layer\n"
			"       iom_threshold=XX        Set long IO time threshold, unit is ms\n"
#endif
			"\n"
			);

	return simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
}


static ssize_t command_write(struct file *file, const char __user *ubuf,
						size_t count, loff_t *ppos)
{
	char msg[32];
#ifdef CONFIG_IO_MONITOR
	int idx, ret;
	unsigned int value;
#endif

	if (copy_from_user(msg, ubuf, count)) {
		return -EFAULT;
	}

	msg[count-1]=0;

	if(!strcasecmp(msg, "test"))
	{
		int i;
		char line_buf[512];
		printk("%s,  test command get\n", __func__);
		sprintf(line_buf, "%s,  test command get\n", __func__);
		for(i=0;i<100;i++)
		{
			//schedule_delayed_work(&fsdbg_dw_inodes_dump, 0);
		}

	}
#ifdef CONFIG_FILESYSTEM_STATISTICS
	else if(!strcasecmp(msg, "inodes_dump"))
	{
		pr_debug("%s,  inode_dump command get\n", __func__);
		schedule_delayed_work(&fsdbg_dw_inodes_dump, 0);

	}
	else if(!strcasecmp(msg, "disable_dump"))
	{
		pr_debug("%s,  disable_dump command get\n", __func__);
		fsdbg_flag_dump_to_file = 0;
	}
	else if(!strcasecmp(msg, "enable_dump"))
	{
		pr_debug("%s,  enable_dump command get\n", __func__);
		fsdbg_flag_dump_to_file = 1;
	}
	else if(!strcasecmp(msg, "fs=f2fs"))
	{
		fsdbg_flag_fs_filter = FSDBG_F2FS;
	}
	else if(!strcasecmp(msg, "fs=ext4"))
	{
		fsdbg_flag_fs_filter = FSDBG_EXT4;
	}
	else if(!strcasecmp(msg, "fs=f2fs_ext4"))
	{
		fsdbg_flag_fs_filter = FSDBG_EXT4 | FSDBG_F2FS;
	}
	else if(!strcasecmp(msg, "fs=ext4_f2fs"))
	{
		fsdbg_flag_fs_filter = FSDBG_EXT4 | FSDBG_F2FS;
	}
#endif

#ifdef CONFIG_IO_MONITOR
	else if(!strcasecmp(msg, "iom_dump"))
	{
		iom_log_file_write();
	}
	else if(!strncasecmp(msg, "iom_mask=", strlen("iom_mask=")))
	{
		idx = strlen("iom_mask=");
		ret = kstrtouint(&msg[idx], 0, &value);
		if(ret == 0)
		{
			iom_mask = value;
		}
	}
	else if(!strncasecmp(msg, "iom_threshold=", strlen("iom_threshold=")))
	{
		idx = strlen("iom_threshold=");
		ret = kstrtouint(&msg[idx], 0, &value);
		if(ret == 0)
		{
			iom_threshold = value*1000000;
		}
	}
#endif
	else
	{
		printk("%s,  unsupport command\n", __func__);
	}

	return count;
}

static ssize_t status_read(struct file *filp, char __user *buffer,
				size_t count, loff_t *ppos)
{
	char buf[1024];
	int str_len;

	str_len = 0;
	snprintf(&buf[str_len], sizeof(buf)-str_len, "\nFile system debug kits V1.0 	 Author: lizhigang@smartisan.com\n\n");

#ifdef CONFIG_FILESYSTEM_STATISTICS
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "\n--------File system statistics status\n");
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "dump fs type:  ");
	if(fsdbg_flag_fs_filter & FSDBG_F2FS)
	{
		str_len = strlen(buf);
		snprintf(&buf[str_len], sizeof(buf)-str_len, "F2FS ");
	}
	if(fsdbg_flag_fs_filter & FSDBG_EXT4)
	{
		str_len = strlen(buf);
		snprintf(&buf[str_len], sizeof(buf)-str_len, "EXT4 ");
	}
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "\ndump_to_file flag: %d\n", fsdbg_flag_dump_to_file);
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "dumping file name: %s\n", fsdbg_filename);
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "FSDBG log size in FIFO (Max: %d): %d\n", FSDBG_FIFO_SIZE, kfifo_len(&fsdbg_fifo));
#endif

#ifdef CONFIG_IO_MONITOR
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "\n--------IO monitor status\n");
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "iom_mask: 0x%X\n", iom_mask);
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "iom_threshold: %lld\n", iom_threshold/1000000);
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "IOM log size in BLK FIFO (Max: %d): %d\n", IOM_FIFO_SIZE, kfifo_len(&iom_log_fifo_blk));
	str_len = strlen(buf);
	snprintf(&buf[str_len], sizeof(buf)-str_len, "IOM log size in FS FIFO (Max: %d): %d\n", IOM_FIFO_SIZE, kfifo_len(&iom_log_fifo_fs));
#endif

	return simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));
}

static const struct file_operations command_fops = {
	.open		= simple_open,
	.read		= command_read,
	.write		= command_write,
};

static const struct file_operations status_fops = {
	.open		= simple_open,
	.read		= status_read,
};


static void fsdbg_debugfs_init(void)
{
	struct dentry *f_ent;
	struct dentry *f_debugfs_dir;

	f_debugfs_dir = debugfs_create_dir("fs_debug", NULL);
	if (IS_ERR(f_debugfs_dir)) {
		pr_err("Failed to create fs_debug directory\n");
		return;
	}

	f_ent = debugfs_create_file("command", 0600, f_debugfs_dir,
					NULL, &command_fops);
	if (IS_ERR(f_ent)) {
		pr_err("Failed to create command file\n");
		return;
	}

	f_ent = debugfs_create_file("status", 0400, f_debugfs_dir,
					NULL, &status_fops);
	if (IS_ERR(f_ent)) {
		pr_err("Failed to create status file\n");
		return;
	}
}


static int __init fsdbg_init(void)
{
#if (defined CONFIG_FILESYSTEM_STATISTICS) || (defined CONFIG_IO_MONITOR)
	int ret;
#endif

	// create debugfs node
	fsdbg_debugfs_init();

#ifdef CONFIG_FILESYSTEM_STATISTICS
	// alloc fifo for file rw log
	ret = kfifo_alloc(&fsdbg_fifo, FSDBG_FIFO_SIZE, GFP_KERNEL);
	if (ret) {
		printk(KERN_ERR "fsdbg_fifo alloc error\n");
		return 1;
	}

	// init file write delay work
	INIT_DELAYED_WORK(&fsdbg_dw_inodes_dump, handler_inodes_dump);
	INIT_DELAYED_WORK(&fsdbg_dw_file_write, handler_log_file_write);
	fsdbg_filename[0] = 0;
	fsdbg_flag_last_data = 0;
	fsdbg_flag_dump_to_file = 0;
	fsdbg_flag_fs_filter = FSDBG_F2FS;
#endif

#ifdef CONFIG_IO_MONITOR
	// set long io threshold default value
	iom_threshold = DEFAULT_IOM_THRESHOLD;
	iom_mask = IOM_F2FS_RW|IOM_EXT4_RW;

	// alloc fifo for long IO log
	ret = kfifo_alloc(&iom_log_fifo_blk, IOM_FIFO_SIZE, GFP_KERNEL);
	if (ret) {
		printk(KERN_ERR "iom_log_fifo_blk alloc error\n");
		return 2;
	}
	spin_lock_init(&iom_log_fifo_lock_blk);

	ret = kfifo_alloc(&iom_log_fifo_fs, IOM_FIFO_SIZE, GFP_KERNEL);
	if (ret) {
		printk(KERN_ERR "iom_log_fifo_fs alloc error\n");
		return 2;
	}
	mutex_init(&iom_log_fifo_lock_fs);

#endif

	return 0;
}
subsys_initcall(fsdbg_init);

