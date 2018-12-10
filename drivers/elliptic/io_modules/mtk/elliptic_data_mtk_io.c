/**
 * Copyright Elliptic Labs
 *
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/wakelock.h>

#include <scp_ipi.h>
#include <elliptic/elliptic_data_io.h>
#include "elliptic_device.h"

typedef struct
{
    uint32_t elliptic_ipi_message_id; // uint instead of enum for fixed-width
    uint32_t data_size;
} elliptic_ipi_host_message_header_t;

#define ELLIPTIC_HOST_MESSAGE_HEADER_SIZE (sizeof(elliptic_ipi_host_message_header_t))
#define ELLIPTIC_HOST_MESSAGE_MAX_DATA_SIZE ( (SHARE_BUF_DATA_SIZE) - (ELLIPTIC_HOST_MESSAGE_HEADER_SIZE) )

typedef struct
{
    elliptic_ipi_host_message_header_t header;
    uint8_t data[ELLIPTIC_HOST_MESSAGE_MAX_DATA_SIZE];
} elliptic_ipi_host_message_t;


// Will be called from MTK SCP IPI driver when data arrives from DSP
void elliptic_data_io_ipi_handler(int id, void *data, unsigned int len)
{
	const size_t max_len = min( (size_t)len, (size_t)ELLIPTIC_MSG_BUF_SIZE );
    elliptic_data_push((const char *)data, max_len, ELLIPTIC_DATA_PUSH_FROM_KERNEL);
}

int elliptic_data_io_initialize(void)
{
    ipi_status ipi_registration_result;

    ipi_registration_result = scp_ipi_registration(IPI_USND,
    elliptic_data_io_ipi_handler, "usnd" );
    if(ipi_registration_result != 0){
        EL_PRINT_E("failed to register IPI callback");
        return -1;
    }

    return 0;
}

int32_t elliptic_data_io_write(uint32_t message_id, const char *data,
    size_t data_size)
{
    static elliptic_ipi_host_message_t host_message;
    ipi_status send_status;
    //mutex lock
    host_message.header.elliptic_ipi_message_id = message_id;

    host_message.header.data_size = min( data_size, (size_t)ELLIPTIC_HOST_MESSAGE_MAX_DATA_SIZE );
    memcpy(host_message.data, data, host_message.header.data_size);

    send_status = scp_ipi_send(IPI_USND, &host_message, sizeof(host_message) , 1);
    //mutex unlock
    if (DONE != send_status)
    {
        pr_err( "[ELUS]: elliptic_data_io_write failed to send\n" );
        return 0;
    }
    return (int32_t)data_size;

    return 0;
}


int elliptic_data_io_cleanup(void)
{
    EL_PRINT_I("Unimplemented");
    return 0;
}

