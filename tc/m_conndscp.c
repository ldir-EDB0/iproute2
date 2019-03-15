/*
 * m_conndscp.c		netfilter conndscp dscp<->conntrack mark action
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
#include <linux/tc_act/tc_conndscp.h>

static const char * conndscp_modes[] = {
	"?invalid",
	"dscp",
};

static void
explain(void)
{
	fprintf(stderr, "Usage: ... conndscp mask MASK statemask STATEMASK mode dscp [zone ZONE] [CONTROL] [index <INDEX>]\n");
	fprintf(stderr, "where :\n"
		"\tMASK is the bitmask to store/restore DSCP\n"
		"\tSTATEMASK is the bitmask to determine conditional storing/restoring\n"
		"\tMODE dscp\n"
		"\tZONE is the conntrack zone\n"
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
parse_conndscp(struct action_util *a, int *argc_p, char ***argv_p, int tca_id,
	      struct nlmsghdr *n)
{
	struct tc_conndscp sel = {};
	char **argv = *argv_p;
	int argc = *argc_p;
	int ok = 0;
	struct rtattr *tail;

	while (argc > 0) {
		if (matches(*argv, "conndscp") == 0) {
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
		if (matches(*argv, "mask") == 0) {
			NEXT_ARG();
			if (get_u32(&sel.mask, *argv, 0)) {
				fprintf(stderr, "conndscp: Illegal \"mask\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	if (argc) {
		if (matches(*argv, "statemask") == 0) {
			NEXT_ARG();
			if (get_u32(&sel.statemask, *argv, 0)) {
				fprintf(stderr, "conndscp: Illegal \"statemask\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	if (argc) {
		if (matches(*argv, "mode") == 0) {
			NEXT_ARG();
			if (matches(*argv, "dscp") == 0)
				sel.mode |= CONNDSCP_FLAG_SETDSCP;
			else {
				fprintf(stderr, "conndscp: Illegal \"mode\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	if (argc) {
		if (matches(*argv, "zone") == 0) {
			NEXT_ARG();
			if (get_u16(&sel.zone, *argv, 10)) {
				fprintf(stderr, "conndscp: Illegal \"zone\"\n");
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
				fprintf(stderr, "conndscp: Illegal \"index\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	tail = addattr_nest(n, MAX_MSG, tca_id);
	addattr_l(n, MAX_MSG, TCA_CONNDSCP_PARMS, &sel, sizeof(sel));
	addattr_nest_end(n, tail);

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int print_conndscp(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[TCA_CONNDSCP_MAX + 1];
	struct tc_conndscp *ci;

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, TCA_CONNDSCP_MAX, arg);
	if (tb[TCA_CONNDSCP_PARMS] == NULL) {
		print_string(PRINT_FP, NULL, "%s", "[NULL conndscp parameters]");
		return -1;
	}

	ci = RTA_DATA(tb[TCA_CONNDSCP_PARMS]);

	print_string(PRINT_ANY, "kind", "%s ", "conndscp");
	print_uint(PRINT_ANY, "zone", "zone %u", ci->zone);
	print_action_control(f, " ", ci->action, "");

	print_string(PRINT_FP, NULL, "%s", _SL_);
	print_uint(PRINT_ANY, "index", "\t index %u", ci->index);
	print_int(PRINT_ANY, "ref", " ref %d", ci->refcnt);
	print_int(PRINT_ANY, "bind", " bind %d", ci->bindcnt);
	print_uint(PRINT_ANY, "mask", " mask 0x%08x", ci->mask);
	print_uint(PRINT_ANY, "statemask", " statemask 0x%08x", ci->statemask);
	print_string(PRINT_ANY, "mode", " mode %s", conndscp_modes[ci->mode & CONNDSCP_FLAG_SETDSCP]);

	if (show_stats) {
		if (tb[TCA_CONNDSCP_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_CONNDSCP_TM]);

			print_tm(f, tm);
		}
	}
	print_string(PRINT_FP, NULL, "%s", _SL_);

	return 0;
}

struct action_util conndscp_action_util = {
	.id = "conndscp",
	.parse_aopt = parse_conndscp,
	.print_aopt = print_conndscp,
};
