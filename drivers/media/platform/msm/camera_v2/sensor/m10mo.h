#ifndef M10MO_H
#define M10MO_H

#include "msm_cci.h"
#include "msm_sensor.h"
#include "msm_camera_io_util.h"

#include <linux/time.h>
#include <mach/socinfo.h>
#include <linux/spi/spi.h>
#include <linux/msm_ion.h>
#include <media/v4l2-event.h>

#define M10MO_DATA_MAX (31)
#define M10MO_RAM_ADDR_TOP (0x01100000)
#define M10MO_RAM_ADDR_FLASHCTL	(0x13000005)

#define M10MO_TEST_DATA	(0x55aa55aa)

#define FUJI_ERROR_BYTE	(0xFF)
#define MSLEEP_WAIT_NORM (25)
#define MSLEEP_WAIT_LONG (100)
#define MSLEEP_WAIT_LONGLONG (500)
#define FIRMWARE_SIZE (2 * 1024 * 1024)

#define BOOT_TIMEOUT (500)
#define LENS_TIMEOUT (1000)
#define MONITOR_TIMEOUT (1000)
#define CAPTURE_TIMEOUT (1000)
#define CAPTURE_STOP_TIMEOUT (1000)
#define MONITOR_MINIMUM_TIME (180)
#define _1SHOT_TIMEOUT (2000)
#define SAFE_I2C_DELAY (10)
#define AE_LOCK_DELAY (150)
#define AWB_LOCK_DELAY (100)

#define AF_STOP_TIMEOUT (2000)

#define MIN_ZOOM_LEVEL (1)
#define MAX_ZOOM_LEVEL (31)

#define MAX_EV_BIAS (3.0f)
#define MIN_EV_BIAS (-3.0f)
#define EV_STEP (0.3f)

#define ZSL_MONITOR_WIDTH (1440)
#define ZSL_MONITOR_HEIGHT (1080)

#define CATE_0X00 (0x00)

	#define CUSTOMER_CODE 0x00
	#define PROJECT_CODE 0x01
	#define VER_FIRMWARE 0x02
	#define VER_FIRMWARE_H 0x02
	#define VER_FIRMWARE_L 0x03
	#define MODULE_VENDOR 0x0A
		#define Foxconn 0x00
		#define Lite_ON 0x01
	#define M10MO_SYS_MODE 0x0B
		#define Parameter_setting_mode 0x01
		#define Monitor_mode 0x02
	#define INT_ENABLE 0x10

	#define INT_FACTOR 0x1C
		#define INT_EN_MODE (1 << 0)
		#define INT_EN_AF (1 << 1)
		#define INT_EN_CAPTURE (1 << 3)
		#define INT_EN_CAF (1 << 4)

		#define INT_STATUS_MODE (1 << 0)
		#define INT_STATUS_AF (1 << 1)
		#define INT_STATUS_CAPTURE (1 << 3)
		#define INT_STATUS_CAF_START (1 << 4)
		#define INT_STATUS_CAF_END (1 << 5)

	#define SEN_DEBUG_INFO1 0x46
	#define SEN_DEBUG_INFO2 0x47
	#define SEN_DEBUG_INFO3 0x48
	#define SEN_DEBUG_INFO4 0x49
	#define SEN_DEBUG_INFO5 0x4A
	#define SEN_DEBUG_INFO6 0x4B
	#define SEN_DEBUG_INFO7 0x4C
	#define SEN_DEBUG_INFO8 0x4D

#define CATE_0X01 (0x01)
	#define MON_SIZE (0x01)
		#define _1440x1080 (0x37)
		#define _1920x1080 (0x28)
		#define _2560x1920 (0x49)
	#define SENSOR_HDR_MODE (0x0c)
		#define ON (0x01)
		#define OFF (0x00)

	#define OTP_0X0A06 (0x2E)
	#define OTP_0X0A07 (0x2F)
	#define OTP_0X0A08 (0x30)
	#define OTP_0X0A09 (0x31)
	#define OTP_0X0A0A (0x32)
	#define OTP_0X0A0B (0x33)

#define CATE_0X02 (0x02)
	#define ZOOM (0x01)

	#define REVERSE (0x05)
		#define REVERSE_OFF (0x00)
		#define REVERSE_ON (0x01)

	#define MIRROR 0x06
		#define MIRROR_OFF (0x00)
		#define MIRROR_ON (0x01)

	#define SCENE_NUM (0x5C)
		#define SCENE_NUM_Auto (0x00)
		#define SCENE_NUM_Night (0x01)
		#define SCENE_NUM_Night_Portrait (0x02)
		#define SCENE_NUM_Backlit (0x03)
		#define SCENE_NUM_Backlit_Portrait (0x04)
		#define SCENE_NUM_Portrait (0x05)
		#define SCENE_NUM_Macro (0x06)

	#define ROI_UPDATE_TRIG (0xA0)
		#define Update (0x01)
		#define Face_Update (0x02)

	#define ROI_LEFT 0xA1
	#define ROI_LEFT_H 0xA1
	#define ROI_LEFT_L 0xA2

	#define ROI_TOP 0xA3
	#define ROI_TOP_H 0xA3
	#define ROI_TOP_L 0xA4

	#define ROI_RIGHT 0xA5
	#define ROI_RIGHT_H 0xA5
	#define ROI_RIGHT_L 0xA6

	#define ROI_BOTTOM 0xA7
	#define ROI_BOTTOM_H 0xA7
	#define ROI_BOTTOM_L 0xA8

#define CATE_0X03 0x03

	#define AE_LOCK 0x00
		#define AE_LOCK_OFF 0x00
		#define AE_LOCK_ON 0x01

	#define AE_MODE 0x01
		#define AE_OFF 0x00
		#define All_block_integral 0x01
		#define Center_weighted_average1 0x02
		#define ROI_Mode 0x10

	#define ISOSEL 0x05
		#define ISO_AUTO 0x00
		#define ISO_50 0x01
		#define ISO_100 0x02
		#define ISO_200 0x03
		#define ISO_400 0x04
		#define ISO_800 0x05
		#define ISO_1600 0x06
		#define ISO_3200 0x07

	#define EV_BIAS 0x09

	#define AE_PARAM_UPDATE 0x0D
		#define AE_PARAM_UPDATE_Update 1

	#define NOW_GAIN 0x0E
	#define NOW_GAIN_H 0x0E
	#define NOW_GAIN_L 0x0F

	#define NOW_EXPOSURE 0x10
	#define NOW_EXPOSURE_H 0x10
	#define NOW_EXPOSURE_L 0x11

	#define OB_RELATED1 0x12
		#define OB_RELATED_V1 0x00

	#define OB_RELATED2 0x13
		#define OB_RELATED_V2 0xfe

	#define STROBE_EN 0x3c
		#define STROBE_EN_Forced_OFF 0x00
		#define STROBE_EN_Auto  0x01
		#define STROBE_EN_Forced_ON 0x02
		#define STROBE_EN_Torch 0x03
		#define STROBE_EN_Torch_on_by_TX_pin 0x04

	#define ZSL_FAST_SPEED_CAPTURE 0x4F
		#define ZSL_FAST_SPEED_CAPTURE_Off 0
		#define ZSL_FAST_SPEED_CAPTURE_On 1

	#define DEGREE 0x68
		#define DEGREE_0 0x00
		#define DEGREE_90 0x01
		#define DEGREE_180 0x02
		#define DEGREE_270 0x03
#define CATE_0X05 0x05

#define CATE_0X06 0x06
	#define AWB_LOCK 0x00
		#define AWB_LOCK_OFF 0x00
		#define AWB_LOCK_ON 0x01

	#define AWB_MODE 0x02
		#define AWB_Auto 0x01
		#define Manual_WB 0x02

	#define AWB_MANUAL 0x03
		#define AWB_Invalid 0x00
		#define AWB_Incandescent_light 0x01
		#define AWB_Fluorescent_light1 0x02
		#define AWB_Fluorescent_light2 0x03
		#define AWB_Day_light 0x04
		#define AWB_Cloudy 0x05
		#define AWB_Shade 0x06
		#define AWB_Horizon 0x07
		#define AWB_User_setting 0x08

	#define AWB_PARAM_UPDATE 0x0C
		#define AWB_PARAM_UPDATE_Update 0x01

#define CATE_0X07 0x07
	#define INFO_EXPTIME7 0x00
	#define INFO_EXPTIME6 0x01
	#define INFO_EXPTIME5 0x02
	#define INFO_EXPTIME4 0x03
	#define INFO_EXPTIME3 0x04
	#define INFO_EXPTIME2 0x05
	#define INFO_EXPTIME1 0x06
	#define INFO_EXPTIME0 0x07

	#define INFO_ISO 0x28
	#define INFO_ISO1 0x28
	#define INFO_ISO0 0x29

#define CATE_0X0A 0x0a
	#define AF_MODE 0x00
		#define Invalid_AF 0x00
		#define Normal_AF 0x01
		#define Continuous_AF 0x06
		/* Fixed, Macro, Infinity status only, 
		 * not for operation*/
		#define Fixed_AF 0x07
		#define Macro_AF 0x08
		#define Infinity_AF 0x09
		#define Continuous_AF_applied 0x0A

	#define AF_RANGE 0x01
		#define INF_position 0x01
		#define Normal_position 0x02
		#define Bar_code_position 0x03
		#define Macro_position 0x04
		#define Initial_DAC_position 0x05
		#define Close_position 0x06

	#define AF_START 0x02
		#define AF_stop_by_force 0x00
		#define AF_start 0x01
		#define AF_done  0x02
		#define AF_pause 0x04
		#define AF_resume 0x05

	#define AF_RESULT 0x03
		#define AF_OFF 0x00
		#define Focus_operation_success 0x01
		#define Focus_operation_fail 0x02
		#define Focus_operation_stopped_at_edge 0x03
		#define AF_operating 0x10

	#define LED_ASSIST_EN 0x1C
		#define LED_ASSIST_EN_OFF 0x00
		#define LED_ASSIST_EN_Auto 0x01

	/* 0x22~0x23 */
	#define CURRENT_DAC 0x22

	#define MANUAL_LENS_DAC 0x24
		#define plus_1DAC 0x01
		#define plus_10DAC 0x0A
		#define plus_127DAC 0x7F
		#define minus_128DAC 0x80
		#define minus_10DAC 0xF6
		#define minus_1DAC 0xFF

	#define AF_AREA_MODE 0x30
		#define CENTER 0x00
		#define ROI 0x01

	#define AF_DISTANCE 0x50
	#define AF_DISTANCE_H 0x50
	#define AF_DISTANCE_L 0x51

	#define CAF_MOVIE_EN 0x52
		#define CAF_MOVIE_Disable 0x00
		#define CAF_MOVIE_Enable 0x01

	#define LENS_ANGLE_INFO 0x53

	#define GYRO_UPDATE 0x58
		#define GYRO_UPDATE_Update 0x01

	#define GYRO_SPEED_X 0x59
	#define GYRO_SPEED_Y 0x5A
	#define GYRO_SPEED_Z 0x5B
	#define GYRO_RADIAN_X 0x5C
	#define GYRO_RADIAN_Y 0x5D
	#define GYRO_RADIAN_Z 0x5E

#define CATE_0X0C 0x0c

	#define CAP_MODE 0x00
		#define Movie 0x00
		#define Panorama 0x0D
		#define Zsl_Capture_type2 0x0E

	#define START_CAP 0x05
		#define Start_burst_shot 0x04
		#define Stop_burst_shot 0x05
		#define Start_Raw_Main_Debug 0x06
		#define Start_burst_shot_debug_Output_1_frame 0x0C

#define CATE_0X0D 0x0d

	#define ADD_SHOW 0x06
		#define Log_string_address 0x00

	#define LOG_STR_ADD 0x08

	#define LOG_SEL 0x0c /*and 0x0d*/

	#define LOG_ACT 0x0e
		#define Enable_Log 0x01
		#define Disable_Log 0x02
		#define Output_Log_string 0x03
		#define Clear_Log 0x04

	#define LOG_MODE 0x0F
		#define Standard_log_mode_old_type 0x00
		#define Analyze_log_mode_header_info 0x01
		#define Analyze_log_mode_data_only 0x02
		#define Analyze_log_mode_data_and_string 0x03

	#define LOG_DATA_LEN 0x14

	#define LED_TEST 0xF0
		#define LED_Init 0x01
		#define Torch_On 0x02
		#define Torch_Off 0x03
		#define Flash 0x04

#define CATE_0X0F 0x0f
	#define FLASH_AD 0x00
		#define Flash_Erase_Start_Addr 0x00
		#define Flash_Write_Start_Addr 0x00

	#define FLASH_BYTE 0x04

	#define FLASH_ERASE 0x06
		#define BIT_CHIP_ERASE 1
		#define CHIP_ERASE 0x02

	#define FLASH_WR 0x07
		#define PROGRAM 1
		#define BIT_PROGRAM 0

	#define FLASH_CHK 0x09
		#define FLASH_CHK_16M 4

	#define FLASH_SUM 0x0A

	#define CAM_START 0x12
		#define ENABLE 0x01

	#define DATA_RAM_ADDR 0x14
		#define DATA_RAM_Addr 0x20000000

	#define DATA_TRANS_SIZE 0x18
		#define DATA_TRANS_Size 0x00200000

	#define PLL1DIV_VALUE 0x1C
		#define PLL_19_2MHz 0x001D0152

	#define SDRAM_SET 0x48
		#define SDRAM_SET_Value 0x0608
	#define RAM_START 0x4A
		#define RAM_Start 0x01
		#define SIO_Mode 0x02
	#define SIO_RECEIVE_MODE 0x4B
		#define ISP_latch_data_at_rising_edge 0x4C
		#define ISP_latch_data_at_falling_edge 0x44

enum camera_auto_exposure_mode_type {
	CAMERA_AEC_FRAME_AVERAGE,
	CAMERA_AEC_CENTER_WEIGHTED,
	CAMERA_AEC_SPOT_METERING,
	CAMERA_AEC_SMART_METERING,
	CAMERA_AEC_USER_METERING,
	CAMERA_AEC_SPOT_METERING_ADV,
	CAMERA_AEC_CENTER_WEIGHTED_ADV,
	CAMERA_AEC_MAX_MODES
};


enum cam_focus_mode_type {
	CAM_FOCUS_MODE_AUTO,
	CAM_FOCUS_MODE_INFINITY,
	CAM_FOCUS_MODE_MACRO,
	CAM_FOCUS_MODE_FIXED,
	CAM_FOCUS_MODE_EDOF,
	CAM_FOCUS_MODE_CONTINOUS_VIDEO,
	CAM_FOCUS_MODE_CONTINOUS_PICTURE,
	CAM_FOCUS_MODE_MAX
};

enum feature_bit {
	FEATURE_DEBUG = 1,
	FEATURE_CMD_DUMP = 2,
	FEATURE_OB_CHECK = 3,
	FEATURE_REAL_EXIF = 4,
	FEATURE_GYRO_UPDATE = 5,
	FEATURE_RAW_CAPTURE = 6,
	FEATURE_ISP_LOG_VIEW = 7,
	FEATURE_AF_PROFILING = 8,
	FEATURE_AF_DAC_TEST = 9,
};

struct cam_rect_t {
	int32_t left;
	int32_t top;
	int32_t width;
	int32_t height;
};

struct roi_info_t {
	uint32_t left;
	uint32_t right;
	uint32_t top;
	uint32_t bottom;
};

enum cam_stream_type_t {
	CAM_STREAM_TYPE_DEFAULT,       
	CAM_STREAM_TYPE_PREVIEW,      
	CAM_STREAM_TYPE_POSTVIEW,     
	CAM_STREAM_TYPE_SNAPSHOT,     
	CAM_STREAM_TYPE_VIDEO,         
	CAM_STREAM_TYPE_IMPL_DEFINED, 
	CAM_STREAM_TYPE_YUV,         
	CAM_STREAM_TYPE_METADATA,     
	CAM_STREAM_TYPE_RAW,           
	CAM_STREAM_TYPE_OFFLINE_PROC,
	CAM_STREAM_TYPE_MAX,
};


enum cam_iso_mode_type {
	CAM_ISO_MODE_AUTO,
	CAM_ISO_MODE_DEBLUR,
	CAM_ISO_MODE_50,
	CAM_ISO_MODE_100,
	CAM_ISO_MODE_200,
	CAM_ISO_MODE_400,
	CAM_ISO_MODE_800,
	CAM_ISO_MODE_1600,
	CAM_ISO_MODE_3200,
	CAM_ISO_MODE_MAX
};

enum cam_wb_mode_type {
	CAM_WB_MODE_AUTO,
	CAM_WB_MODE_CUSTOM,
	CAM_WB_MODE_INCANDESCENT,
	CAM_WB_MODE_FLUORESCENT,
	CAM_WB_MODE_WARM_FLUORESCENT,
	CAM_WB_MODE_DAYLIGHT,
	CAM_WB_MODE_CLOUDY_DAYLIGHT,
	CAM_WB_MODE_TWILIGHT,
	CAM_WB_MODE_SHADE,
	CAM_WB_MODE_OFF,
	CAM_WB_MODE_MAX
};

struct sensor_stream_start_info {
	int32_t num_burst;
	enum cam_stream_type_t stream_type;
};


enum AF_STATUS {
	LENS_DEINITED = 0,
	LENS_DEINITIALING,
	LENS_INITED,
	AF_RANGE_SETTING,
	AF_ONGOING,
	CAF_PAUSING,
	AF_STOPPING
};


enum STREAM_STATUS {
	MONITOR = 0,
	MONITOR_STOPPING,
	ZSL_CAPTURE,
	ZSL_CAPTURE_STARTING,
	ZSL_CAPTURE_STOPPING,
	MONITOR_VIRTUAL_OFF,
	STREAM_OFF,
	UNBOOTED,
	POWER_DOWNING,
	POWER_DOWN,
} STREAM_STATUS;



enum led_mode_t {
	LED_MODE_OFF,
	LED_MODE_AUTO,
	LED_MODE_ON,
	LED_MODE_TORCH,
	LED_MODE_MAX
};

enum {
	CAM_SCENE_MODE_OFF,
	CAM_SCENE_MODE_AUTO,
	CAM_SCENE_MODE_LANDSCAPE,
	CAM_SCENE_MODE_SNOW,
	CAM_SCENE_MODE_BEACH,
	CAM_SCENE_MODE_SUNSET,
	CAM_SCENE_MODE_NIGHT,
	CAM_SCENE_MODE_PORTRAIT,
	CAM_SCENE_MODE_BACKLIGHT,
	CAM_SCENE_MODE_SPORTS,
	CAM_SCENE_MODE_ANTISHAKE,
	CAM_SCENE_MODE_FLOWERS,
	CAM_SCENE_MODE_CANDLELIGHT,
	CAM_SCENE_MODE_FIREWORKS,
	CAM_SCENE_MODE_PARTY,
	CAM_SCENE_MODE_NIGHT_PORTRAIT,
	CAM_SCENE_MODE_THEATRE,
	CAM_SCENE_MODE_ACTION,
	CAM_SCENE_MODE_AR,
	CAM_SCENE_MODE_FACE_PRIORITY,
	CAM_SCENE_MODE_BARCODE,
	CAM_SCENE_MODE_HDR,
	CAM_SCENE_MODE_BACKLIGHT_PORTRAIT,
	CAM_SCENE_MODE_MACRO,
	CAM_SCENE_MODE_MAX
} scene_mode_type;

struct acc_info_t {
	int8_t x;
	int8_t y;
	int8_t z;
};

struct gyro_info_t {
	int8_t x;
	int8_t y;
	int8_t z;
};

enum {
	CPL_BOOT = 0,
	CPL_LINIT,
	CPL_LDEINIT,
	CPL_AF_RANGE,
	CPL_AF_FINISH,
	CPL_AF_STOP,
	CPL_CAF_PAUSE,
	CPL_MON_FINISH,
	CPL_MON_START,
	CPL_CAP_START,
	CPL_CAP_STOP,
	CPL_NUM,
};

enum {
	IRQ_PROCESSING = 0,
	IRQ_PROCESSED,
};

enum {
	MONITOR_WORK_COMPLETED = 0,
	MONITOR_WORK_ONGOING,
};

enum {
	MONITOR_STOP_WORK_COMPLETED = 0,
	MONITOR_STOP_WORK_ONGOING,
};

enum {
	CAPTURE_PENDING = 0,
	CAPTURE_COMPLETED,
};

struct m10mo_ctrl_t {
	int32_t irq_num;
	spinlock_t irq_work_lock;
	struct work_struct irq_work;
	struct mutex *m10mo_i2c_mutex;
	/* because of async work m10mo power down, it is possible
	   power down in the middle of functions_show, so mutex protection */
	struct mutex *power_down_mutex;
	struct workqueue_struct *irq_q;
	spinlock_t monitor_work_lock;
	struct work_struct power_work;
	struct work_struct monitor_work;

	struct work_struct gyro_set_work;
	struct work_struct degree_set_work;
	struct work_struct position_set_work;
	struct work_struct monitor_stop_work;

	struct workqueue_struct *power_q;
	struct workqueue_struct *monitor_q;
	struct msm_sensor_ctrl_t sensor_ctrl;
	wait_queue_head_t wait_q;
	struct completion cpl[CPL_NUM];	
	
	atomic_t af_mode;
	atomic_t af_mode_p;
	atomic_t af_status;
	atomic_t hdr_enable;
	atomic_t flash_mode;
	atomic_t stream_status;
	atomic_t irq_processed;
	atomic_t monitor_working;
	atomic_t monitor_stop_working;
	atomic_t capture_pending;
	atomic_t degree;
	atomic_t position;
	atomic_t manual_af;
	atomic_t m_af_trigger;
	struct roi_info_t af_roi;
	struct acc_info_t acc_info;
	struct gyro_info_t gyro_info;

	uint8_t ae_mode;
	uint8_t movie_caf;
	uint8_t af_area_mode;

	atomic_t cur_res;
	atomic_t new_res;

	struct ion_client *iclient;
	struct ion_handle *log_buf_h;
	uint8_t *log_p;
	uint8_t *fw_buf;

	unsigned long feature_mask;
	struct timespec taf_trigger_t;
	struct timespec caf_trigger_t;
	struct timespec taf_total_t;
	struct timespec caf_total_t;

	int32_t caf_counter;
	struct timespec monitor_f_t;
	struct timespec capture_s_t;

	long taf_time_last;
	int32_t taf_counter;
	struct mutex *taf_time_mutex;
};

struct fuji_i2c_seq {
	uint8_t		num;
	uint8_t		cmd;

	uint8_t		cat;
	uint8_t		byte;
	uint8_t		num8;
	uint16_t	num16;
	
	uint8_t		data[M10MO_DATA_MAX];
	uint32_t	addr;

	uint8_t		*pdata;
	uint16_t	data_size;
};

struct fuji_dev {
	unsigned short current_pointer;
	struct i2c_client *client;
	struct cdev cdev;
};

#endif
