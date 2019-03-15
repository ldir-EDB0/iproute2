/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __UAPI_TC_CTINFO_H
#define __UAPI_TC_CTINFO_H

#include <linux/types.h>
#include <linux/pkt_cls.h>

struct tc_ctinfo {
	tc_gen;
};

struct tc_ctinfo_dscp {
	__u32 mask;
	__u32 statemask;
};

enum {
	TCA_CTINFO_UNSPEC,
	TCA_CTINFO_ACT,
	TCA_CTINFO_ZONE,
	TCA_CTINFO_DSCP_PARMS,
	TCA_CTINFO_MODE_DSCP,
	TCA_CTINFO_TM,
	TCA_CTINFO_PAD,
	__TCA_CTINFO_MAX
};
#define TCA_CTINFO_MAX (__TCA_CTINFO_MAX - 1)

enum {
	CTINFO_MODE_SETDSCP	= BIT(0)
};

#endif
