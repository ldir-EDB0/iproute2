/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __UAPI_TC_CONNDSCP_H
#define __UAPI_TC_CONNDSCP_H

#include <linux/types.h>
#include <linux/pkt_cls.h>

#define TCA_ACT_CONNDSCP 99

struct tc_conndscp {
	tc_gen;
	__u32 mask;
	__u32 statemask;
	__u16 zone;
	__u8 mode;
};

enum {
	TCA_CONNDSCP_UNSPEC,
	TCA_CONNDSCP_PARMS,
	TCA_CONNDSCP_TM,
	TCA_CONNDSCP_PAD,
	__TCA_CONNDSCP_MAX
};
#define TCA_CONNDSCP_MAX (__TCA_CONNDSCP_MAX - 1)

enum {
	CONNDSCP_FLAG_SETDSCP	= BIT(0)
};

#endif
