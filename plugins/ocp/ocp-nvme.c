// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *   	    Venkat Ramesh <venkatraghavan@fb.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "linux/nvme_ioctl.h"

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"
#include "nvme-status.h"

#define CREATE_CMD
#include "ocp-nvme.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Smart Add Log

#define C0_SMART_CLOUD_ATTR_LEN             0x200
#define C0_SMART_CLOUD_ATTR_OPCODE          0xC0
#define C0_GUID_LENGTH                      16
#define C0_ACTIVE_BUCKET_TIMER_INCREMENT    5
#define C0_ACTIVE_THRESHOLD_INCREMENT       5
#define C0_MINIMUM_WINDOW_INCREMENT         100

static __u8 scao_guid[C0_GUID_LENGTH]    = { 0xC5, 0xAF, 0x10, 0x28, 0xEA, 0xBF,
		0xF2, 0xA4, 0x9C, 0x4F, 0x6F, 0x7C, 0xC9, 0x14, 0xD5, 0xAF };

typedef enum {
	SCAO_PMUW               =  0,	/* Physical media units written */
	SCAO_PMUR               = 16,	/* Physical media units read */
	SCAO_BUNBR              = 32,	/* Bad user nand blocks raw */
	SCAO_BUNBN              = 38,	/* Bad user nand blocks normalized */
	SCAO_BSNBR              = 40,	/* Bad system nand blocks raw */
	SCAO_BSNBN              = 46,	/* Bad system nand blocks normalized */
	SCAO_XRC                = 48,	/* XOR recovery count */
	SCAO_UREC               = 56,	/* Uncorrectable read error count */
	SCAO_SEEC               = 64,	/* Soft ecc error count */
	SCAO_EECE               = 72,	/* End to end corrected errors */
	SCAO_EEDC               = 76,	/* End to end detected errors */
	SCAO_SDPU               = 80,	/* System data percent used */
	SCAO_RFSC               = 81,	/* Refresh counts */
	SCAO_MXUDEC             = 88,	/* Max User data erase counts */
	SCAO_MNUDEC             = 92,	/* Min User data erase counts */
	SCAO_NTTE               = 96,	/* Number of Thermal throttling events */
	SCAO_CTS                = 97,	/* Current throttling status */
	SCAO_EVF                = 98,   /* Errata Version Field */
	SCAO_PVF                = 99,   /* Point Version Field */
	SCAO_MIVF               = 101,  /* Minor Version Field */
	SCAO_MAVF               = 103,  /* Major Version Field */
	SCAO_PCEC               = 104,	/* PCIe correctable error count */
	SCAO_ICS                = 112,	/* Incomplete shutdowns */
	SCAO_PFB                = 120,	/* Percent free blocks */
	SCAO_CPH                = 128,	/* Capacitor health */
	SCAO_NEV                = 130,  /* NVMe Errata Version */
	SCAO_UIO                = 136,	/* Unaligned I/O */
	SCAO_SVN                = 144,	/* Security Version Number */
	SCAO_NUSE               = 152,	/* NUSE - Namespace utilization */
	SCAO_PSC                = 160,	/* PLP start count */
	SCAO_EEST               = 176,	/* Endurance estimate */
	SCAO_PLRC               = 192,  /* PCIe Link Retraining Count */
	SCAO_LPV                = 494,	/* Log page version */
	SCAO_LPG                = 496,	/* Log page GUID */
} SMART_CLOUD_ATTRIBUTE_OFFSETS;

static long double int128_to_double(__u8 *data)
{
	int i;
	long double result = 0;

	for (i = 0; i < 16; i++) {
		result *= 256;
		result += data[15 - i];
	}
	return result;
}

static void ocp_print_C0_log_normal(void *data)
{
	__u8 *log_data = (__u8*)data;
	uint16_t smart_log_ver = 0;

	printf("SMART Cloud Attributes :- \n");

	printf("  Physical media units written -   	        %"PRIu64" %"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW+8] & 0xFFFFFFFFFFFFFFFF),
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW] & 0xFFFFFFFFFFFFFFFF));
	printf("  Physical media units read    - 	        %"PRIu64" %"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR+8] & 0xFFFFFFFFFFFFFFFF),
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR] & 0xFFFFFFFFFFFFFFFF));
	printf("  Bad user nand blocks - Raw			%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BUNBR] & 0x0000FFFFFFFFFFFF));
	printf("  Bad user nand blocks - Normalized		%d\n",
			(uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BUNBN]));
	printf("  Bad system nand blocks - Raw			%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BSNBR] & 0x0000FFFFFFFFFFFF));
	printf("  Bad system nand blocks - Normalized		%d\n",
			(uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BSNBN]));
	printf("  XOR recovery count				%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_XRC]));
	printf("  Uncorrectable read error count		%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UREC]));
	printf("  Soft ecc error count				%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SEEC]));
	printf("  End to end corrected errors			%"PRIu32"\n",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EECE]));
	printf("  End to end detected errors			%"PRIu32"\n",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EEDC]));
	printf("  System data percent used			%d\n",
			(__u8)log_data[SCAO_SDPU]);
	printf("  Refresh counts				%"PRIu64"\n",
			(uint64_t)(le64_to_cpu(*(uint64_t *)&log_data[SCAO_RFSC])& 0x00FFFFFFFFFFFFFF));
	printf("  Max User data erase counts			%"PRIu32"\n",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MXUDEC]));
	printf("  Min User data erase counts			%"PRIu32"\n",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MNUDEC]));
	printf("  Number of Thermal throttling events		%d\n",
			(__u8)log_data[SCAO_NTTE]);
	printf("  Current throttling status		  	0x%x\n",
			(__u8)log_data[SCAO_CTS]);
	printf("  PCIe correctable error count			%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PCEC]));
	printf("  Incomplete shutdowns				%"PRIu32"\n",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_ICS]));
	printf("  Percent free blocks				%d\n",
			(__u8)log_data[SCAO_PFB]);
	printf("  Capacitor health				%"PRIu16"\n",
			(uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_CPH]));
	printf("  Unaligned I/O					%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UIO]));
	printf("  Security Version Number			%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SVN]));
	printf("  NUSE - Namespace utilization			%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_NUSE]));
	printf("  PLP start count				%.0Lf\n",
			int128_to_double(&log_data[SCAO_PSC]));
	printf("  Endurance estimate				%.0Lf\n",
			int128_to_double(&log_data[SCAO_EEST]));
	smart_log_ver = (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_LPV]);
	printf("  Log page version				%"PRIu16"\n",smart_log_ver);
	printf("  Log page GUID					0x");
	printf("%"PRIx64"%"PRIx64"\n",(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG + 8]),
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG]));
	if(smart_log_ver > 2) {
		printf("  Errata Version Field                          %d\n",
				(__u8)log_data[SCAO_EVF]);
		printf("  Point Version Field                           %"PRIu16"\n",
				(uint16_t)log_data[SCAO_PVF]);
		printf("  Minor Version Field                           %"PRIu16"\n",
				(uint16_t)log_data[SCAO_MIVF]);
		printf("  Major Version Field                           %d\n",
				(__u8)log_data[SCAO_MAVF]);
		printf("  NVMe Errata Version				%d\n",
				(__u8)log_data[SCAO_NEV]);
		printf("  PCIe Link Retraining Count			%"PRIu64"\n",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PLRC]));
	}
	printf("\n");
}

static void ocp_print_C0_log_json(void *data)
{
	__u8 *log_data = (__u8*)data;
	struct json_object *root;
	struct json_object *pmuw;
	struct json_object *pmur;
	uint16_t smart_log_ver = 0;

	root = json_create_object();
	pmuw = json_create_object();
	pmur = json_create_object();

	json_object_add_value_uint(pmuw, "hi",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW+8] & 0xFFFFFFFFFFFFFFFF));
	json_object_add_value_uint(pmuw, "lo",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUW] & 0xFFFFFFFFFFFFFFFF));
	json_object_add_value_object(root, "Physical media units written", pmuw);
	json_object_add_value_uint(pmur, "hi",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR+8] & 0xFFFFFFFFFFFFFFFF));
	json_object_add_value_uint(pmur, "lo",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PMUR] & 0xFFFFFFFFFFFFFFFF));
	json_object_add_value_object(root, "Physical media units read", pmur);
	json_object_add_value_uint(root, "Bad user nand blocks - Raw",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BUNBR] & 0x0000FFFFFFFFFFFF));
	json_object_add_value_uint(root, "Bad user nand blocks - Normalized",
			(uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BUNBN]));
	json_object_add_value_uint(root, "Bad system nand blocks - Raw",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_BSNBR] & 0x0000FFFFFFFFFFFF));
	json_object_add_value_uint(root, "Bad system nand blocks - Normalized",
			(uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_BSNBN]));
	json_object_add_value_uint(root, "XOR recovery count",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_XRC]));
	json_object_add_value_uint(root, "Uncorrectable read error count",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UREC]));
	json_object_add_value_uint(root, "Soft ecc error count",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SEEC]));
	json_object_add_value_uint(root, "End to end corrected errors",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EECE]));
	json_object_add_value_uint(root, "End to end detected errors",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_EEDC]));
	json_object_add_value_uint(root, "System data percent used",
			(__u8)log_data[SCAO_SDPU]);
	json_object_add_value_uint(root, "Refresh counts",
			(uint64_t)(le64_to_cpu(*(uint64_t *)&log_data[SCAO_RFSC])& 0x00FFFFFFFFFFFFFF));
	json_object_add_value_uint(root, "Max User data erase counts",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MXUDEC]));
	json_object_add_value_uint(root, "Min User data erase counts",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_MNUDEC]));
	json_object_add_value_uint(root, "Number of Thermal throttling events",
			(__u8)log_data[SCAO_NTTE]);
	json_object_add_value_uint(root, "Current throttling status",
			(__u8)log_data[SCAO_CTS]);
	json_object_add_value_uint(root, "PCIe correctable error count",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PCEC]));
	json_object_add_value_uint(root, "Incomplete shutdowns",
			(uint32_t)le32_to_cpu(*(uint32_t *)&log_data[SCAO_ICS]));
	json_object_add_value_uint(root, "Percent free blocks",
			(__u8)log_data[SCAO_PFB]);
	json_object_add_value_uint(root, "Capacitor health",
			(uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_CPH]));
	json_object_add_value_uint(root, "Unaligned I/O",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_UIO]));
	json_object_add_value_uint(root, "Security Version Number",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_SVN]));
	json_object_add_value_uint(root, "NUSE - Namespace utilization",
			(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_NUSE]));
	json_object_add_value_uint(root, "PLP start count",
			int128_to_double(&log_data[SCAO_PSC]));
	json_object_add_value_uint(root, "Endurance estimate",
			int128_to_double(&log_data[SCAO_EEST]));
	smart_log_ver = (uint16_t)le16_to_cpu(*(uint16_t *)&log_data[SCAO_LPV]);
	json_object_add_value_uint(root, "Log page version", smart_log_ver);
	char guid[40];
	memset((void*)guid, 0, 40);
	sprintf((char*)guid, "0x%"PRIx64"%"PRIx64"",(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG + 8]),
		(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_LPG]));
	json_object_add_value_string(root, "Log page GUID", guid);
	if(smart_log_ver > 2){
		json_object_add_value_uint(root, "Errata Version Field",
				(__u8)log_data[SCAO_EVF]);
		json_object_add_value_uint(root, "Point Version Field",
				(uint16_t)log_data[SCAO_PVF]);
		json_object_add_value_uint(root, "Minor Version Field",
				(uint16_t)log_data[SCAO_MIVF]);
		json_object_add_value_uint(root, "Major Version Field",
				(__u8)log_data[SCAO_MAVF]);
		json_object_add_value_uint(root, "NVMe Errata Version",
				(__u8)log_data[SCAO_NEV]);
		json_object_add_value_uint(root, "PCIe Link Retraining Count",
				(uint64_t)le64_to_cpu(*(uint64_t *)&log_data[SCAO_PLRC]));
	}
	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static int get_c0_log_page(int fd, char *format)
{
	int ret = 0;
	int fmt = -1;
	__u8 *data;
	int i;

	fmt = validate_output_format(format);
	if (fmt < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return fmt;
	}

	if ((data = (__u8 *) malloc(sizeof(__u8) * C0_SMART_CLOUD_ATTR_LEN)) == NULL) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof (__u8) * C0_SMART_CLOUD_ATTR_LEN);

	ret = nvme_get_log14(fd, NVME_NSID_ALL, C0_SMART_CLOUD_ATTR_OPCODE,
			   NVME_NO_LOG_LSP, 0, 0, false, 0, C0_SMART_CLOUD_ATTR_LEN, data);

	if (strcmp(format, "json"))
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(ret), ret);

	if (ret == 0) {

		/* check log page guid */
		/* Verify GUID matches */
		for (i=0; i<16; i++) {
			if (scao_guid[i] != data[SCAO_LPG + i])	{
				fprintf(stderr, "ERROR : OCP : Unknown GUID in C0 Log Page data\n");
				int j;
				fprintf(stderr, "ERROR : OCP : Expected GUID:  0x");
				for (j = 0; j<16; j++) {
					fprintf(stderr, "%x", scao_guid[j]);
				}
				fprintf(stderr, "\nERROR : OCP : Actual GUID:    0x");
				for (j = 0; j<16; j++) {
					fprintf(stderr, "%x", data[SCAO_LPG + j]);
				}
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}

		/* print the data */
		switch (fmt) {
		case NORMAL:
			ocp_print_C0_log_normal(data);
			break;
		case JSON:
			ocp_print_C0_log_json(data);
			break;
		}
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C0 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_smart_add_log(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve latency monitor log data.";
	int fd;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json"),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	ret = get_c0_log_page(fd, cfg.output_format);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C0 Log Page, ret = %d\n",
			ret);
	close(fd);
	return ret;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Latency Monitor Log

#define C3_LATENCY_MON_LOG_BUF_LEN          0x200
#define C3_LATENCY_MON_OPCODE               0xC3
#define C3_LATENCY_MON_VERSION              0x0001
#define C3_GUID_LENGTH                      16
#define NVME_FEAT_OCP_LATENCY_MONITOR	    0xC5
static __u8 lat_mon_guid[C3_GUID_LENGTH] = { 0x92, 0x7a, 0xc0, 0x8c, 0xd0, 0x84,
		0x6c, 0x9c, 0x70, 0x43, 0xe6, 0xd4, 0x58, 0x5e, 0xd4, 0x85 };

#define READ            3
#define WRITE           2
#define TRIM            1
#define RESERVED        0

struct __attribute__((__packed__)) ssd_latency_monitor_log {
	__u8    feature_status;                         /* 0x00  */
	__u8    rsvd1;                                  /* 0x01  */
	__le16  active_bucket_timer;                    /* 0x02  */
	__le16  active_bucket_timer_threshold;          /* 0x04  */
	__u8    active_threshold_a;                     /* 0x06  */
	__u8    active_threshold_b;                     /* 0x07  */
	__u8    active_threshold_c;                     /* 0x08  */
	__u8    active_threshold_d;                     /* 0x09  */
	__le16  active_latency_config;                  /* 0x0A  */
	__u8    active_latency_min_window;              /* 0x0C  */
	__u8    rsvd2[0x13];                            /* 0x0D  */

	__le32  active_bucket_counter[4][4] ;           /* 0x20 - 0x5F   */
	__le64  active_latency_timestamp[4][3];         /* 0x60 - 0xBF   */
	__le16  active_measured_latency[4][3];          /* 0xC0 - 0xD7   */
	__le16  active_latency_stamp_units;             /* 0xD8  */
	__u8    rsvd3[0x16];                            /* 0xDA  */

	__le32  static_bucket_counter[4][4] ;           /* 0xF0  - 0x12F */
	__le64  static_latency_timestamp[4][3];         /* 0x130 - 0x18F */
	__le16  static_measured_latency[4][3];          /* 0x190 - 0x1A7 */
	__le16  static_latency_stamp_units;             /* 0x1A8 */
	__u8    rsvd4[0x16];                            /* 0x1AA */

	__le16  debug_log_trigger_enable;               /* 0x1C0 */
	__le16  debug_log_measured_latency;             /* 0x1C2 */
	__le64  debug_log_latency_stamp;                /* 0x1C4 */
	__le16  debug_log_ptr;                          /* 0x1CC */
	__le16  debug_log_counter_trigger;              /* 0x1CE */
	__u8    debug_log_stamp_units;                  /* 0x1D0 */
	__u8    rsvd5[0x1D];                            /* 0x1D1 */

	__le16  log_page_version;                       /* 0x1EE */
	__u8    log_page_guid[0x10];                    /* 0x1F0 */
};

struct __attribute__((__packed__)) feature_latency_monitor {
	__u16 active_bucket_timer_threshold;
	__u8  active_threshold_a;
	__u8  active_threshold_b;
	__u8  active_threshold_c;
	__u8  active_threshold_d;
	__u16 active_latency_config;
	__u8  active_latency_minimum_window;
	__u16 debug_log_trigger_enable;
	__u8  discard_debug_log;
	__u8  latency_monitor_feature_enable;
	__u8  reserved[4083];
};

static int convert_ts(time_t time, char *ts_buf)
{
	struct tm  gmTimeInfo;
	time_t     time_Human, time_ms;
	char       buf[80];

	time_Human = time/1000;
	time_ms = time % 1000;

	gmtime_r((const time_t *)&time_Human, &gmTimeInfo);

	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &gmTimeInfo);
	sprintf(ts_buf, "%s.%03ld GMT", buf, time_ms);

	return 0;
}

static int ocp_print_C3_log_normal(struct ssd_latency_monitor_log *log_data)
{
	printf("-Latency Monitor/C3 Log Page Data- \n");
	printf("  Controller   :  %s\n", devicename);
	int i, j;
	int pos = 0;
	char       ts_buf[128];

	printf("  Feature Status                     0x%x \n",
		 log_data->feature_status);
	printf("  Active Bucket Timer                %d min \n",
		 C0_ACTIVE_BUCKET_TIMER_INCREMENT *
		 le16_to_cpu(log_data->active_bucket_timer));
	printf("  Active Bucket Timer Threshold      %d min \n",
		 C0_ACTIVE_BUCKET_TIMER_INCREMENT *
		 le16_to_cpu(log_data->active_bucket_timer_threshold));
	printf("  Active Threshold A                 %d ms \n",
		 C0_ACTIVE_THRESHOLD_INCREMENT *
		 le16_to_cpu(log_data->active_threshold_a+1));
	printf("  Active Threshold B                 %d ms \n",
		 C0_ACTIVE_THRESHOLD_INCREMENT *
		 le16_to_cpu(log_data->active_threshold_b+1));
	printf("  Active Threshold C                 %d ms \n",
		 C0_ACTIVE_THRESHOLD_INCREMENT *
		 le16_to_cpu(log_data->active_threshold_c+1));
	printf("  Active Threshold D                 %d ms \n",
		 C0_ACTIVE_THRESHOLD_INCREMENT *
		 le16_to_cpu(log_data->active_threshold_d+1));
	printf("  Active Latency Minimum Window      %d ms \n",
		 C0_MINIMUM_WINDOW_INCREMENT *
		 le16_to_cpu(log_data->active_latency_min_window));
	printf("  Active Latency Stamp Units         %d \n",
		 le16_to_cpu(log_data->active_latency_stamp_units));
	printf("  Static Latency Stamp Units         %d \n",
		 le16_to_cpu(log_data->static_latency_stamp_units));
	printf("  Debug Log Trigger Enable           %d \n",
		 le16_to_cpu(log_data->debug_log_trigger_enable));
	printf("  Debug Log Measured Latency         %d \n",
		 le16_to_cpu(log_data->debug_log_measured_latency));
	if (le64_to_cpu(log_data->debug_log_latency_stamp) == -1)
		printf("  Debug Log Latency Time Stamp       N/A \n");
	else {
		convert_ts(le64_to_cpu(log_data->debug_log_latency_stamp), ts_buf);
		printf("  Debug Log Latency Time Stamp       %s \n", ts_buf);
	}
	printf("  Debug Log Pointer                  %d \n",
		 le16_to_cpu(log_data->debug_log_ptr));
	printf("  Debug Counter Trigger Source       %d \n",
		 le16_to_cpu(log_data->debug_log_counter_trigger));
	printf("  Debug Log Stamp Units              %d \n",
		 le16_to_cpu(log_data->debug_log_stamp_units));
	printf("  Log Page Version                   %d \n",
		 le16_to_cpu(log_data->log_page_version));

	char guid[(C3_GUID_LENGTH * 2) + 1];
	char *ptr = &guid[0];
	for (i = C3_GUID_LENGTH - 1; i >= 0; i--) {
		ptr += sprintf(ptr, "%02X", log_data->log_page_guid[i]);
	}
	printf("  Log Page GUID                      %s \n", guid);
	printf("\n");
	printf("                                                            Read                           Write                 Deallocate/Trim \n");
	for (i = 0; i <= 3; i++) {
		printf("  Active Latency Mode: Bucket %d      %27d     %27d     %27d \n",
			i,
			log_data->active_latency_config & (1 << pos),
			log_data->active_latency_config & (1 << pos),
			log_data->active_latency_config & (1 << pos));
	}
	for (i = 0; i <= 3; i++) {
		printf("  Active Bucket Counter: Bucket %d    %27d     %27d     %27d \n",
			i,
			le32_to_cpu(log_data->active_bucket_counter[i][READ]),
			le32_to_cpu(log_data->active_bucket_counter[i][WRITE]),
			le32_to_cpu(log_data->active_bucket_counter[i][TRIM]));
	}
	for (i = 0; i <= 3; i++) {
		printf("  Active Latency Time Stamp: Bucket %d    ", i);
		for (j = 2; j <= 0; j--) {
			if (le64_to_cpu(log_data->active_latency_timestamp[i][j]) == -1)
				printf("                    N/A         ");
			else {
				convert_ts(le64_to_cpu(log_data->active_latency_timestamp[i][j]), ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
	}
	for (i = 0; i <= 3; i++) {
		printf("  Active Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms \n",
			i,
			le16_to_cpu(log_data->active_measured_latency[i][READ-1]),
			le16_to_cpu(log_data->active_measured_latency[i][WRITE-1]),
			le16_to_cpu(log_data->active_measured_latency[i][TRIM-1]));
	}
	printf("\n");
	for (i = 0; i <= 3; i++) {
		printf("  Static Bucket Counter: Bucket %d    %27d     %27d     %27d \n",
			i,
			le32_to_cpu(log_data->static_bucket_counter[i][READ]),
			le32_to_cpu(log_data->static_bucket_counter[i][WRITE]),
			le32_to_cpu(log_data->static_bucket_counter[i][TRIM]));
	}
	for (i = 0; i <= 3; i++) {
		printf("  Static Latency Time Stamp: Bucket %d    ", i);
		for (j = 2; j <= 0; j--) {
			if (le64_to_cpu(log_data->static_latency_timestamp[i][j]) == -1)
				printf("                    N/A         ");
			else {
				convert_ts(le64_to_cpu(log_data->static_latency_timestamp[i][j]), ts_buf);
				printf("%s     ", ts_buf);
			}
		}
		printf("\n");
	}
	for (i = 0; i <= 3; i++) {
		printf("  Static Measured Latency: Bucket %d  %27d ms  %27d ms  %27d ms \n",
			i,
			le16_to_cpu(log_data->static_measured_latency[i][READ-1]),
			le16_to_cpu(log_data->static_measured_latency[i][WRITE-1]),
			le16_to_cpu(log_data->static_measured_latency[i][TRIM-1]));
	}
	return 0;
}

static void ocp_print_C3_log_json(struct ssd_latency_monitor_log *log_data)
{
	int i, j;
	int pos = 0;
	char	buf[128];
	char    ts_buf[128];
	char	*operation[3] = {"Trim", "Write", "Read"};
	struct json_object *root;
	root = json_create_object();

	json_object_add_value_uint(root, "Feature Status",
			log_data->feature_status);
	json_object_add_value_uint(root, "Active Bucket Timer",
			C0_ACTIVE_BUCKET_TIMER_INCREMENT *
			le16_to_cpu(log_data->active_bucket_timer));
	json_object_add_value_uint(root, "Active Bucket Timer Threshold",
			C0_ACTIVE_BUCKET_TIMER_INCREMENT *
			le16_to_cpu(log_data->active_bucket_timer_threshold));
	json_object_add_value_uint(root, "Active Threshold A",
			C0_ACTIVE_THRESHOLD_INCREMENT *
			le16_to_cpu(log_data->active_threshold_a+1));
	json_object_add_value_uint(root, "Active Threshold B",
			C0_ACTIVE_THRESHOLD_INCREMENT *
			le16_to_cpu(log_data->active_threshold_b+1));
	json_object_add_value_uint(root, "Active Threshold C",
			C0_ACTIVE_THRESHOLD_INCREMENT *
			le16_to_cpu(log_data->active_threshold_c+1));
	json_object_add_value_uint(root, "Active Threshold D",
			C0_ACTIVE_THRESHOLD_INCREMENT *
			le16_to_cpu(log_data->active_threshold_d+1));
	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;
		bucket = json_create_object();
		sprintf(buf, "Active Latency Mode: Bucket %d", i);
		for (j = 2; j <= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
					log_data->active_latency_config & (1 << pos));
		}
		json_object_add_value_object(root, buf, bucket);
	}
	json_object_add_value_uint(root, "Active Latency Minimum Window",
			C0_MINIMUM_WINDOW_INCREMENT *
			le16_to_cpu(log_data->active_latency_min_window));
	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;
		bucket = json_create_object();
		sprintf(buf, "Active Bucket Counter: Bucket %d", i);
		for (j = 2; j <= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
					le32_to_cpu(log_data->active_bucket_counter[i][j+1]));
		}
		json_object_add_value_object(root, buf, bucket);
	}
	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;
		bucket = json_create_object();
		sprintf(buf, "Active Latency Time Stamp: Bucket %d", i);
		for (j = 2; j <= 0; j--) {
			if (le64_to_cpu(log_data->active_latency_timestamp[i][j]) == -1)
				json_object_add_value_string(bucket, operation[j], "NA");
			else {
				convert_ts(le64_to_cpu(log_data->active_latency_timestamp[i][j]), ts_buf);
				json_object_add_value_string(bucket, operation[j], ts_buf);
			}
		}
		json_object_add_value_object(root, buf, bucket);
	}
	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;
		bucket = json_create_object();
		sprintf(buf, "Active Measured Latency: Bucket %d", i);
		for (j = 2; j <= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
					le16_to_cpu(log_data->active_measured_latency[i][j]));
		}
		json_object_add_value_object(root, buf, bucket);
	}
	json_object_add_value_uint(root, "Active Latency Stamp Units",
			le16_to_cpu(log_data->active_latency_stamp_units));
	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;
		bucket = json_create_object();
		sprintf(buf, "Static Bucket Counter: Bucket %d", i);
		for (j = 2; j <= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
					le32_to_cpu(log_data->static_bucket_counter[i][j+1]));
		}
		json_object_add_value_object(root, buf, bucket);
	}
	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;
		bucket = json_create_object();
		sprintf(buf, "Static Latency Time Stamp: Bucket %d", i);
		for (j = 2; j <= 0; j--) {
			if (le64_to_cpu(log_data->static_latency_timestamp[i][j]) == -1)
				json_object_add_value_string(bucket, operation[j], "NA");
			else {
				convert_ts(le64_to_cpu(log_data->static_latency_timestamp[i][j]), ts_buf);
				json_object_add_value_string(bucket, operation[j], ts_buf);
			}
		}
		json_object_add_value_object(root, buf, bucket);
	}
	for (i = 0; i <= 3; i++) {
		struct json_object *bucket;
		bucket = json_create_object();
		sprintf(buf, "Static Measured Latency: Bucket %d", i);
		for (j = 2; j <= 0; j--) {
			json_object_add_value_uint(bucket, operation[j],
					le16_to_cpu(log_data->static_measured_latency[i][j]));
		}
		json_object_add_value_object(root, buf, bucket);
	}
	json_object_add_value_uint(root, "Static Latency Stamp Units",
			le16_to_cpu(log_data->static_latency_stamp_units));
	json_object_add_value_uint(root, "Debug Log Trigger Enable",
			le16_to_cpu(log_data->debug_log_trigger_enable));
	json_object_add_value_uint(root, "Debug Log Measured Latency",
			le16_to_cpu(log_data->debug_log_measured_latency));
	if (le64_to_cpu(log_data->debug_log_latency_stamp) == -1)
		json_object_add_value_string(root, "Debug Log Latency Time Stamp", "NA");
	else {
		convert_ts(le64_to_cpu(log_data->debug_log_latency_stamp), ts_buf);
		json_object_add_value_string(root, "Debug Log Latency Time Stamp", ts_buf);
	}
	json_object_add_value_uint(root, "Debug Log Pointer",
			le16_to_cpu(log_data->debug_log_ptr));
	json_object_add_value_uint(root, "Debug Counter Trigger Source",
			le16_to_cpu(log_data->debug_log_counter_trigger));
	json_object_add_value_uint(root, "Debug Log Stamp Units",
			le16_to_cpu(log_data->debug_log_stamp_units));
	json_object_add_value_uint(root, "Log Page Version",
			le16_to_cpu(log_data->log_page_version));
	char guid[(C3_GUID_LENGTH * 2) + 1];
	char *ptr = &guid[0];
	for (i = C3_GUID_LENGTH - 1; i >= 0; i--) {
		ptr += sprintf(ptr, "%02X", log_data->log_page_guid[i]);
	}
	json_object_add_value_string(root, "Log Page GUID", guid);

	json_print_object(root, NULL);
	printf("\n");

	json_free_object(root);
}

static int get_c3_log_page(int fd, char *format)
{
	int ret = 0;
	int fmt = -1;
	__u8 *data;
	int i;
	struct ssd_latency_monitor_log *log_data;

	fmt = validate_output_format(format);
	if (fmt < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return fmt;
	}

	if ((data = (__u8 *) malloc(sizeof(__u8) * C3_LATENCY_MON_LOG_BUF_LEN)) == NULL) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof (__u8) * C3_LATENCY_MON_LOG_BUF_LEN);

	ret = nvme_get_log14(fd, NVME_NSID_ALL, C3_LATENCY_MON_OPCODE,
			   NVME_NO_LOG_LSP, 0, 0, false, 0, C3_LATENCY_MON_LOG_BUF_LEN, data);

	if (strcmp(format, "json"))
		fprintf(stderr,
			"NVMe Status:%s(%x)\n",
			nvme_status_to_string(ret),
			ret);

	if (ret == 0) {
		log_data = (struct ssd_latency_monitor_log*)data;

		/* check log page version */
		if (log_data->log_page_version != C3_LATENCY_MON_VERSION) {
			fprintf(stderr,
				"ERROR : OCP : invalid latency monitor version\n");
			ret = -1;
			goto out;
		}

		/* check log page guid */
		/* Verify GUID matches */
		for (i=0; i<16; i++) {
			if (lat_mon_guid[i] != log_data->log_page_guid[i]) {
				fprintf(stderr,"ERROR : OCP : Unknown GUID in C3 Log Page data\n");
				int j;
				fprintf(stderr, "ERROR : OCP : Expected GUID: 0x");
				for (j = 0; j<16; j++) {
					fprintf(stderr, "%x", lat_mon_guid[j]);
				}
				fprintf(stderr, "\nERROR : OCP : Actual GUID: 0x");
				for (j = 0; j<16; j++) {
					fprintf(stderr, "%x", log_data->log_page_guid[j]);
				}
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}

		switch (fmt) {
		case NORMAL:
			ocp_print_C3_log_normal(log_data);
			break;
		case JSON:
			ocp_print_C3_log_json(log_data);
			break;
		}
	} else {
		fprintf(stderr,
			"ERROR : OCP : Unable to read C3 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

static int ocp_latency_monitor_log(int argc, char **argv, struct command *command,
		struct plugin *plugin)
{
	const char *desc = "Retrieve latency monitor log data.";
	int fd;
	int ret = 0;

	struct config {
		char *output_format;
	};

	struct config cfg = {
		.output_format = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format,
			"output Format: normal|json"),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;

	ret = get_c3_log_page(fd, cfg.output_format);
	if (ret)
		fprintf(stderr,
			"ERROR : OCP : Failure reading the C3 Log Page, ret = %d\n",
			ret);
	close(fd);
	return ret;
}

int ocp_set_latency_monitor_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int fd;
	int err = -1;
	__u32 result;
	struct feature_latency_monitor buf = {0,};
	__u32  nsid = NVME_NSID_ALL;
	struct stat nvme_stat;
	struct nvme_id_ctrl ctrl;

	const char *desc = "Set Latency Monitor feature.";
	const char *active_bucket_timer_threshold = "This is the value that loads the Active Bucket Timer Threshold.";
	const char *active_threshold_a = "This is the value that loads into the Active Threshold A.";
	const char *active_threshold_b = "This is the value that loads into the Active Threshold B.";
	const char *active_threshold_c = "This is the value that loads into the Active Threshold C.";
	const char *active_threshold_d = "This is the value that loads into the Active Threshold D.";
	const char *active_latency_config = "This is the value that loads into the Active Latency Configuration.";
	const char *active_latency_minimum_window = "This is the value that loads into the Active Latency Minimum Window.";
	const char *debug_log_trigger_enable = "This is the value that loads into the Debug Log Trigger Enable.";
	const char *discard_debug_log = "Discard Debug Log.";
	const char *latency_monitor_feature_enable = "Latency Monitor Feature Enable.";

	struct config {
		__u16 active_bucket_timer_threshold;
		__u8 active_threshold_a;
		__u8 active_threshold_b;
		__u8 active_threshold_c;
		__u8 active_threshold_d;
		__u16 active_latency_config;
		__u8 active_latency_minimum_window;
		__u16 debug_log_trigger_enable;
		__u8 discard_debug_log;
		__u8 latency_monitor_feature_enable;
	};

	struct config cfg = {
		.active_bucket_timer_threshold = 0x7E0,
		.active_threshold_a = 0x5,
		.active_threshold_b = 0x13,
		.active_threshold_c = 0x1E,
		.active_threshold_d = 0x2E,
		.active_latency_config = 0xFFF,
		.active_latency_minimum_window = 0xA,
		.debug_log_trigger_enable = 0,
		.discard_debug_log = 0,
		.latency_monitor_feature_enable = 0x7,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"active_bucket_timer_threshold", 't', "NUM", CFG_POSITIVE, &cfg.active_bucket_timer_threshold, required_argument, active_bucket_timer_threshold},
		{"active_threshold_a", 'a', "NUM", CFG_POSITIVE, &cfg.active_threshold_a, required_argument, active_threshold_a},
		{"active_threshold_b", 'b', "NUM", CFG_POSITIVE, &cfg.active_threshold_b, required_argument, active_threshold_b},
		{"active_threshold_c", 'c', "NUM", CFG_POSITIVE, &cfg.active_threshold_c, required_argument, active_threshold_c},
		{"active_threshold_d", 'd', "NUM", CFG_POSITIVE, &cfg.active_threshold_d, required_argument, active_threshold_d},
		{"active_latency_config", 'f', "NUM", CFG_POSITIVE, &cfg.active_latency_config, required_argument, active_latency_config},
		{"active_latency_minimum_window", 'w', "NUM", CFG_POSITIVE, &cfg.active_latency_minimum_window, required_argument, active_latency_minimum_window},
		{"debug_log_trigger_enable", 'r', "NUM", CFG_POSITIVE, &cfg.debug_log_trigger_enable, required_argument, debug_log_trigger_enable},
		{"discard_debug_log", 'l', "NUM", CFG_POSITIVE, &cfg.discard_debug_log, required_argument, discard_debug_log},
		{"latency_monitor_feature_enable", 'e', "NUM", CFG_POSITIVE, &cfg.latency_monitor_feature_enable, required_argument, latency_monitor_feature_enable},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options);
	if (fd < 0)
		return fd;

	err = fstat(fd, &nvme_stat);
	if (err < 0)
		goto close_fd;

	if (S_ISBLK(nvme_stat.st_mode)) {
		err = nsid = nvme_get_nsid(fd);
		if (err < 0) {
			perror("invalid-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err != 0) {
		goto close_fd;
	}

	memset(&buf, 0, sizeof (struct feature_latency_monitor));

	buf.active_bucket_timer_threshold = cfg.active_bucket_timer_threshold;
	buf.active_threshold_a = cfg.active_threshold_a;
	buf.active_threshold_b = cfg.active_threshold_b;
	buf.active_threshold_c = cfg.active_threshold_c;
	buf.active_threshold_d = cfg.active_threshold_d;
	buf.active_latency_config = cfg.active_latency_config;
	buf.active_latency_minimum_window = cfg.active_latency_minimum_window;
	buf.debug_log_trigger_enable = cfg.debug_log_trigger_enable;
	buf.discard_debug_log = cfg.discard_debug_log;
	buf.latency_monitor_feature_enable = cfg.latency_monitor_feature_enable;

	err = nvme_set_feature(fd, 0, NVME_FEAT_OCP_LATENCY_MONITOR, 0, 0, 1, sizeof(struct feature_latency_monitor), (void*)&buf, &result);

	if (err < 0) {
		perror("set-feature");
	} else if (!err) {
		printf("NVME_FEAT_OCP_LATENCY_MONITOR: 0x%02x \n", NVME_FEAT_OCP_LATENCY_MONITOR);
		printf("active bucket timer threshold: 0x%x \n", buf.active_bucket_timer_threshold);
		printf("active threshold a: 0x%x \n", buf.active_threshold_a);
		printf("active threshold b: 0x%x \n", buf.active_threshold_b);
		printf("active threshold c: 0x%x \n", buf.active_threshold_c);
		printf("active threshold d: 0x%x \n", buf.active_threshold_d);
		printf("active latency config: 0x%x \n", buf.active_latency_config);
		printf("active latency minimum window: 0x%x \n", buf.active_latency_minimum_window);
		printf("debug log trigger enable: 0x%x \n", buf.debug_log_trigger_enable);
		printf("discard debug log: 0x%x \n", buf.discard_debug_log);
		printf("latency monitor feature enable: 0x%x \n", buf.latency_monitor_feature_enable);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(err), err);

close_fd:
	close(fd);
return err;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Telemetry Log

#define TELEMETRY_HEADER_SIZE 512
#define TELEMETRY_BYTE_PER_BLOCK 512
#define TELEMETRY_TRANSFER_SIZE 1024
#define FILE_NAME_SIZE 2048


enum TELEMETRY_TYPE {
	TELEMETRY_TYPE_NONE       = 0,
	TELEMETRY_TYPE_HOST       = 7,
	TELEMETRY_TYPE_CONTROLLER = 8,
	TELEMETRY_TYPE_HOST_0     = 9,
	TELEMETRY_TYPE_HOST_1     = 10,
};

struct telemetry_initiated_log {
	__u8  LogIdentifier;
	__u8  Reserved1[4];
	__u8  IEEE[3];
	__le16 DataArea1LastBlock;
	__le16 DataArea2LastBlock;
	__le16 DataArea3LastBlock;
	__u8  Reserved2[368];
	__u8  DataAvailable;
	__u8  DataGenerationNumber;
	__u8  ReasonIdentifier[128];
};

static void get_serial_number(int fd, struct nvme_id_ctrl *ctrl, char *sn)
{
	int i;
	// Remove trailing spaces from the name
	for (i = 0; i < sizeof(ctrl->sn); i++) {
		if (ctrl->sn[i] == ' ')
			break;
		sn[i] = ctrl->sn[i];
	}
}

static int ocp_nvme_submit_admin_passthru(int fd, struct nvme_passthru_cmd *cmd)
{
	return ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
}

static int get_telemetry_header(int fd, __u32 ns, __u8 tele_type,
		__u32 data_len, void *data, __u8 nLSP, __u8 nRAE)
{
	struct nvme_admin_cmd cmd =
	{
		.opcode		= nvme_admin_get_log_page,
		.nsid		= ns,
		.addr		= (__u64)(uintptr_t) data,
		.data_len	= data_len,
	};

	__u32 numd = (data_len >> 2) - 1;
	__u16 numdu = numd >> 16;
	__u16 numdl = numd & 0xffff;

	cmd.cdw10 = tele_type | ((nLSP & 0x0F) << 8) | ((nRAE & 0x01) << 15)
			    |  ((numdl & 0xFFFF) << 16);
	cmd.cdw11 = numdu;
	cmd.cdw12 = 0;
	cmd.cdw13 = 0;
	cmd.cdw14 = 0;

	return ocp_nvme_submit_admin_passthru(fd, &cmd);
}

static void print_telemetry_header(struct telemetry_initiated_log *logheader,
		int tele_type)
{
	if (logheader != NULL) {
		unsigned int i = 0, j = 0;

		if (tele_type == TELEMETRY_TYPE_HOST)
			printf("============ Telemetry Host Header ============\n");
		else
			printf("========= Telemetry Controller Header =========\n");

		printf("Log Identifier         : 0x%02X\n", logheader->LogIdentifier);
		printf("IEEE                   : 0x%02X%02X%02X\n",
				logheader->IEEE[0], logheader->IEEE[1], logheader->IEEE[2]);
		printf("Data Area 1 Last Block : 0x%04X\n",
				le16_to_cpu(logheader->DataArea1LastBlock));
		printf("Data Area 2 Last Block : 0x%04X\n",
				le16_to_cpu(logheader->DataArea2LastBlock));
		printf("Data Area 3 Last Block : 0x%04X\n",
				le16_to_cpu(logheader->DataArea3LastBlock));
		printf("Data Available         : 0x%02X\n",	logheader->DataAvailable);
		printf("Data Generation Number : 0x%02X\n",	logheader->DataGenerationNumber);
		printf("Reason Identifier      :\n");

		for (i = 0; i < 8; i++) {
			for (j = 0; j < 16; j++)
				printf("%02X ",	logheader->ReasonIdentifier[127 - ((i * 16) + j)]);
			printf("\n");
		}
		printf("===============================================\n\n");
	}
}

static int extract_dump_get_log(char *featurename, char *filename, char *sn,
		int dumpsize, int transfersize, int fd, __u32 nsid, __u8 log_id,
		__u8 lsp, __u64 offset, bool rae)
{
	int i = 0, err = 0;

	char *data = calloc(transfersize, sizeof(char));
	char filepath[FILE_NAME_SIZE] = {0,};
	int output = 0;
	int total_loop_cnt = dumpsize / transfersize;
	int last_xfer_size = dumpsize % transfersize;

	if (last_xfer_size != 0)
		total_loop_cnt++;
	else
		last_xfer_size = transfersize;

	snprintf(filepath, FILE_NAME_SIZE + 6, "/%s_%s.bin", featurename, sn);

	for (i = 0; i < total_loop_cnt; i++) {
		memset(data, 0, transfersize);
		err = nvme_get_log14(fd, nsid, log_id, lsp, offset, 0, rae,
				0, transfersize, (void *)data);
		if (err != 0) {
			if (i > 0)
				goto close_output;
			else
				goto end;
		}

		if (i != total_loop_cnt - 1) {
			if (i == 0) {
				output = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
				if (output < 0) {
					err = -13;
					goto end;
				}
			}
			if (write(output, data, transfersize) < 0) {
				err = -10;
				goto close_output;
			}
		} else { //last piece
			if (write(output, data, last_xfer_size) < 0) {
				err = -10;
				goto close_output;
			}
		}
		offset += transfersize;
		printf("%d%%\r", (i + 1) * 100 / total_loop_cnt);
	}
	printf("100%%\nThe log file was saved at \"%s\"\n", filepath);

close_output:
	close(output);

end:
	free(data);
	return err;
}

static int get_telemetry_dump(int fd, char *filename, char *sn,
		enum TELEMETRY_TYPE tele_type, int data_area, bool header_print)
{
	__u32 err = 0, nsid = 0x00000000;
	__u8 lsp = 0, rae = 0;

	char data[TELEMETRY_TRANSFER_SIZE] = {0,};
	char *featurename = 0;

	if (tele_type == TELEMETRY_TYPE_HOST_0) {
		featurename = "Host(0)";
		lsp = 0;
		rae = 0;
		tele_type = TELEMETRY_TYPE_HOST;
	} else if (tele_type == TELEMETRY_TYPE_HOST_1) {
		featurename = "Host(1)";
		lsp = 1;
		rae = 0;
		tele_type = TELEMETRY_TYPE_HOST;
	} else { // TELEMETRY_TYPE_CONTROLLER
		featurename = "Controller";
		lsp = 0;
		rae = 1;
	}

	// Get Header
	err = get_telemetry_header(fd, nsid, tele_type, TELEMETRY_HEADER_SIZE,
			(void *)data, lsp, rae);
	if (err) {
		printf("asdf");
		goto end;
	}

	struct telemetry_initiated_log *logheader =
			(struct telemetry_initiated_log *)data;

	if (header_print)
		print_telemetry_header(logheader, tele_type);

	__u64 offset = 0, size = 0;

	switch (data_area) {
	case 1:
		offset  = TELEMETRY_HEADER_SIZE;
		size    = le16_to_cpu(logheader->DataArea1LastBlock);
		break;

	case 2:
		offset  = TELEMETRY_HEADER_SIZE
				+ (le16_to_cpu(logheader->DataArea1LastBlock) * TELEMETRY_BYTE_PER_BLOCK);
		size    = le16_to_cpu(logheader->DataArea2LastBlock)
				- le16_to_cpu(logheader->DataArea1LastBlock);
		break;

	case 3:
		offset  = TELEMETRY_HEADER_SIZE
				+ (le16_to_cpu(logheader->DataArea2LastBlock) * TELEMETRY_BYTE_PER_BLOCK);
		size    = le16_to_cpu(logheader->DataArea3LastBlock)
				- le16_to_cpu(logheader->DataArea2LastBlock);
		break;

	default:
		break;
	}

	if (size == 0) {
		printf("Telemetry %s Area %d is empty.\n", featurename, data_area);
		goto end;
	}

	// Get Data Block
	char dumpname[FILE_NAME_SIZE] = {0,};

	snprintf(dumpname, FILE_NAME_SIZE,
					"Telemetry_%s_Area_%d", featurename, data_area);
	err = extract_dump_get_log(dumpname, filename, sn, size * TELEMETRY_BYTE_PER_BLOCK,
			TELEMETRY_TRANSFER_SIZE, fd, nsid, tele_type,
			0, offset, rae);
	if (err)
		goto end;

end:
	return err;
}

static int ocp_telemetry_log(int argc, char **argv, struct command *cmd,
			      struct plugin *plugin)
{
	int fd;
	int err = 0;
	const char *desc = "Retrieve and save telemetry log.";
	const char *type = "Telemetry Type; 'host[Create bit]' or 'controller'";
	const char *area = "Telemetry Data Area; 1 or 3";
	const char *sfr_i = "Enable SFR for Inband Dump. Default: disabled.";
	const char *sfr_o = "Enable SFR for Ondemand Dump. Default: disabled.";
	// TODO: DELETE
	const char *file = "asdf";

	__u32  nsid = NVME_NSID_ALL;
	struct stat nvme_stat;
	char sn[21] = {0,};
	struct nvme_id_ctrl ctrl;
	bool is_support_telemetry_controller;

	int tele_type = 0;
	int tele_area = 0;

	struct config {
		char *type;
		int area;
		int sfr_i;
		int sfr_o;
		char *file;
	};

	struct config cfg = {
		.type = NULL,
		.area = 0,
		.sfr_i = 0,
		.sfr_o = 0,
		.file = NULL,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"telemetry_type",      't', "TYPE", CFG_STRING, &cfg.type,  required_argument, type},
		{"telemetry_data_area", 'a', "NUM",  CFG_INT,    &cfg.area,  required_argument, area},
		{"sfr_inband",          'I', NULL,   CFG_NONE,   &cfg.sfr_i, no_argument,       sfr_i},
		{"sfr_ondemand",        'O', NULL,   CFG_NONE,   &cfg.sfr_o, no_argument,       sfr_o},
		{"output-file",         'o', "FILE", CFG_STRING, &cfg.file,  required_argument, file},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options);
	if (fd < 0)
		return fd;

	err = fstat(fd, &nvme_stat);
	if (err < 0)
		goto close_fd;

	if (S_ISBLK(nvme_stat.st_mode)) {
		err = nsid = nvme_get_nsid(fd);
		if (err < 0) {
			perror("invalid-namespace-id");
			goto close_fd;
		}
	}

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err != 0) {
		goto close_fd;
	}

	get_serial_number(fd, &ctrl, sn);

	is_support_telemetry_controller = ((ctrl.lpa & 0x8) >> 3);

	if (!cfg.type && !cfg.area) {
		tele_type = TELEMETRY_TYPE_NONE;
		tele_area = 0;
	} else if ((!cfg.type + !cfg.area) == 0) {
		if (!strcmp(cfg.type, "host0"))
			tele_type = TELEMETRY_TYPE_HOST_0;
		else if (!strcmp(cfg.type, "host1"))
			tele_type = TELEMETRY_TYPE_HOST_1;
		else if	(!strcmp(cfg.type, "controller"))
			tele_type = TELEMETRY_TYPE_CONTROLLER;

		tele_area = cfg.area;

		if (!((((tele_type == TELEMETRY_TYPE_HOST_0)
				|| (tele_type == TELEMETRY_TYPE_HOST_1))
				&& ((tele_area == 1) ||  (tele_area == 3)))
				|| (tele_type == TELEMETRY_TYPE_CONTROLLER && tele_area == 3))) {
			printf("\nUnsupported parameters entered.\n");
			printf("Possible combinations; {'host0',1}, {'host0',3}, "
					"{'host1',1}, {'host1',3}, {'controller',3}\n");
			goto close_fd;
		}
	} else {
		printf("\nShould provide these all; 'telemetry_type' "
				"and 'telemetry_data_area'\n");
		goto close_fd;
	}

	if (tele_type == TELEMETRY_TYPE_NONE) {
		printf("\n-------------------------------------------------------------\n");
		//Host 0 (lsp == 0) must be executed before Host 1 (lsp == 1).
		printf("\nExtracting Telemetry Host 0 Dump (Data Area 1)...\n");

		err = get_telemetry_dump(fd, cfg.file, sn,
				TELEMETRY_TYPE_HOST_0, 1, true);
		if (err != 0)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err), err);

		printf("\n-------------------------------------------------------------\n");

		printf("\nExtracting Telemetry Host 0 Dump (Data Area 3)...\n");

		err = get_telemetry_dump(fd, cfg.file, sn,
				TELEMETRY_TYPE_HOST_0, 3, false);
		if (err != 0)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err), err);

		printf("\n-------------------------------------------------------------\n");

		printf("\nExtracting Telemetry Host 1 Dump (Data Area 1)...\n");

		err = get_telemetry_dump(fd, cfg.file, sn,
				TELEMETRY_TYPE_HOST_1, 1, true);
		if (err != 0)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err), err);

		printf("\n-------------------------------------------------------------\n");

		printf("\nExtracting Telemetry Host 1 Dump (Data Area 3)...\n");

		err = get_telemetry_dump(fd, cfg.file, sn,
				TELEMETRY_TYPE_HOST_1, 3, false);
		if (err != 0)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err), err);

		printf("\n-------------------------------------------------------------\n");

		printf("\nExtracting Telemetry Controller Dump (Data Area 3)...\n");

		if (is_support_telemetry_controller == true) {
			err = get_telemetry_dump(fd, cfg.file, sn,
					TELEMETRY_TYPE_CONTROLLER, 3, true);
			if (err != 0)
				fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err), err);
		}

		printf("\n-------------------------------------------------------------\n");
	} else if (tele_type == TELEMETRY_TYPE_CONTROLLER) {
		printf("Extracting Telemetry Controller Dump (Data Area %d)...\n", tele_area);

		if (is_support_telemetry_controller == true) {
			err = get_telemetry_dump(fd, cfg.file, sn, tele_type, tele_area, true);
			if (err != 0)
				fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err), err);
		}
	} else {
		printf("Extracting Telemetry Host(%d) Dump (Data Area %d)...\n",
				(tele_type == TELEMETRY_TYPE_HOST_0) ? 0 : 1, tele_area);

		err = get_telemetry_dump(fd, cfg.file, sn, tele_type, tele_area, true);
		if (err != 0)
			fprintf(stderr, "NVMe Status: %s(%x)\n", nvme_status_to_string(err), err);
	}

	printf("telemetry-log done.\n");

close_fd:
	close(fd);
return err;
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// fw activation history

#define INPUT_FILE_SIZE 2048
#define UNIT_DATA_SIZE_5KB (5*1024)

typedef struct nvme_FWActivationHistoryData_item
{
	__u8 *Buf;
	__u32 BufSize;
} nvme_FWActivationHistoryData_item;

typedef struct nvme_security_data_item {
	__u8 SECP;
	__u16 SPSP;
	__u32 tl;
	void *payload;
} nvme_security_data_item;

static int SecurityCMDReset(int fd)
{
	int err = 0;
	__u32 result = 0;
	unsigned char SendBuffer[4] ={0,};
	nvme_security_data_item sec=
	{
		.SECP = 0xFC,
		.SPSP = 0x1003,
		.tl = 4,
		.payload = &SendBuffer,
	};

	err = nvme_sec_send(fd, 0, 0, sec.SPSP, sec.SECP, sec.tl, sec.tl, sec.payload, &result);

	if (err < 0) {
		perror("security-send");
		goto END;
	} else if (err > 0) {
		fprintf(stderr, "NVME Security Send Command Error:%d\n", err);
		goto END;
	}
END:
	return err;
}

static int get_fw_activation_history_data(int fd, nvme_FWActivationHistoryData_item data)
{
	int err = 0;
	__u32 result = 0;
	SecurityCMDReset(fd);

	{
		unsigned char SendBuffer[16] ={0,};
		nvme_security_data_item sec =
		{
			.SECP = 0xFC,
			.SPSP = 0x1012,
			.tl = 16,
			.payload = &SendBuffer
		};

		SendBuffer[4]  = 0xD;

		err = nvme_sec_send(fd, 0, 0, sec.SPSP, sec.SECP, sec.tl, sec.tl, sec.payload, &result);

		if (err < 0) {
			perror("security-send");
			goto END;
		} else if (err > 0) {
			fprintf(stderr, "NVME Security Send Command Error:%d\n", err);
			goto END;
		}
	}

	{
		nvme_security_data_item sec =
		{
			.SECP = 0xFC,
			.SPSP = 0x1012,
			.tl = data.BufSize,
			.payload = data.Buf
		};

		err = nvme_sec_recv(fd, 0, 0, sec.SPSP, sec.SECP, sec.tl, sec.tl, sec.payload, &result);

		if (err < 0) {
			perror("security-receive");
			goto END;
		} else if (err > 0) {
			fprintf(stderr, "NVME Security Receive Command Error:%d\n", err);
			goto END;
		}
	}

END:
	return err;
}

static int get_and_save_fw_activation_history_path(int fd, char *featureName, char *filename, char filePath[INPUT_FILE_SIZE])
{
	int err = 0;

	if (filename == 0) {
		struct nvme_id_ctrl ctrl;
		int i = sizeof(ctrl.sn) - 1;

		err = nvme_identify_ctrl(fd, &ctrl);
		if (err)
		{
			goto END;
		}

		// Remove trailing spaces from the name
		while (i && ctrl.sn[i] == ' ')
		{
			ctrl.sn[i] = '\0';
			i--;
		}

		snprintf(filePath, INPUT_FILE_SIZE, "%s_%-.*s_FWActivationHistory.json", featureName, (int)sizeof(ctrl.sn), ctrl.sn);
	}
	else {
		snprintf(filePath, INPUT_FILE_SIZE, "%s_s_FWActivationHistory.json", filename);
	}

END:
	return err;
}

static int get_and_save_fw_activation_history(int fd, char *featureName, char *fileName)
{
	int err = 0;
	char filePath[INPUT_FILE_SIZE] = { 0, };

	err = get_and_save_fw_activation_history_path(fd, featureName, fileName, filePath);
	if (err != 0)
		goto END;

	int output;
	if ((output = open(filePath, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
		err = -13;
		goto END;
	}

	unsigned char UnitDataBuffer[UNIT_DATA_SIZE_5KB] ={0,};

	nvme_FWActivationHistoryData_item data =
	{
		.BufSize = UNIT_DATA_SIZE_5KB,
		.Buf = UnitDataBuffer
	};
	err = get_fw_activation_history_data(fd, data);

	if (err != 0)
		goto END;

	int nBufSize = strlen((char *)(data.Buf));
	if (write(output, data.Buf, nBufSize) < 0) {
		err = -10;
		goto END;
	}

	close(output);
	printf("The log file was saved in the \"%s\"\n", filePath);


END:
	return err;
}

static int ocp_fw_activate_history(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0;
	char *desc = "Get FW activation log and save it.";
	char *file = "Output file; defaults to device serial number";

	struct config {
		char *file;
	};

	struct config cfg = {
		.file = NULL,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"output-file",  'o', "FILE", CFG_STRING,   &cfg.file,         required_argument, file},
		{NULL}
	};

	int fd = parse_and_open(argc, argv, desc, command_line_options);

	if (fd < 0)
		return fd;

	err = get_and_save_fw_activation_history(fd, argv[0], cfg.file);

	if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n", nvme_status_to_string(err), err);

	return err;
}
