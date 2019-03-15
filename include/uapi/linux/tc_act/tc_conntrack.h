/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __UAPI_TC_CONNTRACK_H
#define __UAPI_TC_CONNTRACK_H

#include <linux/types.h>
#include <linux/pkt_cls.h>

#define TCA_ACT_CONNTRACK 27

struct tc_conntrack {
	tc_gen;
	__u32 mask;
	__u32 statemask;
	__u16 zone;
	__u8 mode;
	__u8 maskshift;
};

enum {
	TCA_CONNTRACK_UNSPEC,
	TCA_CONNTRACK_PARMS,
	TCA_CONNTRACK_TM,
	TCA_CONNTRACK_PAD,
	__TCA_CONNTRACK_MAX
};
#define TCA_CONNTRACK_MAX (__TCA_CONNTRACK_MAX - 1)

enum {
	CONNTRACK_FLAG_SETDSCP	= BIT(0)
};

#endif
