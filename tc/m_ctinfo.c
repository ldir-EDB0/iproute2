/*
 * m_ctinfo.c		netfilter ctinfo dscp<->ctinfo mark action
 *
 * Copyright (c) 2019 Kevin Darbyshire-Bryant <ldir@darbyshire-bryant.me.uk>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "utils.h"
#include "tc_util.h"
#include <linux/tc_act/tc_ctinfo.h>

static void
explain(void)
{
	fprintf(stderr, "Usage: ... ctinfo [dscp mask[/statemask]] [zone ZONE] [CONTROL] [index <INDEX>]\n");
	fprintf(stderr, "where :\n"
		"\tMASK is the bitmask to store/restore DSCP\n"
		"\tSTATEMASK is the bitmask to determine conditional storing/restoring\n"
		"\tMODE dscp\n"
		"\tZONE is the ctinfo zone\n"
		"\tCONTROL := reclassify | pipe | drop | continue | ok |\n"
		"\t           goto chain <CHAIN_INDEX>\n");
}

static void
usage(void)
{
	explain();
	exit(-1);
}

static int
parse_ctinfo(struct action_util *a, int *argc_p, char ***argv_p, int tca_id,
	      struct nlmsghdr *n)
{
	struct tc_ctinfo sel = {};
	struct tc_ctinfo_dscp seldscp = {};
	char **argv = *argv_p;
	int argc = *argc_p;
	int ok = 0;
	struct rtattr *tail;
	__u16 zone;

	while (argc > 0) {
		if (matches(*argv, "ctinfo") == 0) {
			ok = 1;
			argc--;
			argv++;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			break;
		}

	}

	if (!ok) {
		explain();
		return -1;
	}

	if (argc) {
		if (matches(*argv, "dscp") == 0) {
			NEXT_ARG();
			char *slash;
			if ((slash = strchr(*argv, '/')))
				*slash = '\0';
			if (get_u32(&seldscp.mask, *argv, 0)) {
				fprintf(stderr, "ctinfo: Illegal dscp \"mask\"\n");
				return -1;
			}
			if (slash) {
				if (get_u32(&seldscp.statemask, slash + 1, 0)) {
					fprintf(stderr, "ctinfo: Illegal dscp \"statemask\"\n");
					return -1;
				}
			}
		}
	}

	if (argc) {
		if (matches(*argv, "zone") == 0) {
			NEXT_ARG();
			if (get_u16(&zone, *argv, 10)) {
				fprintf(stderr, "ctinfo: Illegal \"zone\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	parse_action_control_dflt(&argc, &argv, &sel.action, false, TC_ACT_PIPE);

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&sel.index, *argv, 10)) {
				fprintf(stderr, "ctinfo: Illegal \"index\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	tail = addattr_nest(n, MAX_MSG, tca_id);
	addattr_l(n, MAX_MSG, TCA_CTINFO_ACT, &sel, sizeof(sel));
	if (zone)
		addattr16(n, MAX_MSG, TCA_CTINFO_ZONE, zone);
	if (seldscp.mask) {
		addattr_l(n, MAX_MSG, TCA_CTINFO_DSCP_PARMS, &seldscp, sizeof(seldscp));
		addattr(n, MAX_MSG, TCA_CTINFO_MODE_DSCP);
	}
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int print_ctinfo(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[TCA_CTINFO_MAX + 1];
	struct tc_ctinfo *ci;
	struct tc_ctinfo_dscp *ci_dscp = NULL;
	__u16 zone = 0;

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, TCA_CTINFO_MAX, arg);
	if (!tb[TCA_CTINFO_ACT]) {
		print_string(PRINT_FP, NULL, "%s", "[NULL ctinfo parameters]");
		return -1;
	}

	ci = RTA_DATA(tb[TCA_CTINFO_ACT]);

	if (tb[TCA_CTINFO_MODE_DSCP]) {
		if (!tb[TCA_CTINFO_DSCP_PARMS]) {
			print_string(PRINT_FP, NULL, "%s", "[NULL dscp parameters]");
			return -1;
		} else {
			if (RTA_PAYLOAD(tb[TCA_CTINFO_DSCP_PARMS]) >= sizeof(ci_dscp)) {
				ci_dscp = RTA_DATA(tb[TCA_CTINFO_DSCP_PARMS]);
			} else {
				print_string(PRINT_FP, NULL, "%s", "[invalid dscp parameters]");
			}
		}
	}

	if (tb[TCA_CTINFO_ZONE] &&
	    RTA_PAYLOAD(tb[TCA_CTINFO_ZONE]) >= sizeof(__u16))
			zone = rta_getattr_u16(tb[TCA_CTINFO_ZONE]);

	print_string(PRINT_ANY, "kind", "%s ", "ctinfo");
	print_uint(PRINT_ANY, "zone", "zone %u", zone);
	print_action_control(f, " ", ci->action, "");

	print_string(PRINT_FP, NULL, "%s", _SL_);
	print_uint(PRINT_ANY, "index", "\t index %u", ci->index);
	print_int(PRINT_ANY, "ref", " ref %d", ci->refcnt);
	print_int(PRINT_ANY, "bind", " bind %d", ci->bindcnt);

	if (tb[TCA_CTINFO_MODE_DSCP]) {
		if (ci_dscp) {
			print_0xhex(PRINT_ANY, "dscpmask", " dscp %08x", ci_dscp->mask);
			print_0xhex(PRINT_ANY, "dscpstatemask", "/%08x ", ci_dscp->statemask);
		}
	}

	if (show_stats) {
		if (tb[TCA_CTINFO_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_CTINFO_TM]);

			print_tm(f, tm);
		}
	}
	print_string(PRINT_FP, NULL, "%s", _SL_);

	return 0;
}

struct action_util ctinfo_action_util = {
	.id = "ctinfo",
	.parse_aopt = parse_ctinfo,
	.print_aopt = print_ctinfo,
};
