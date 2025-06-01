#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <uapi/linux/pkt_sch_theaterq.h>

#include "utils.h"
#include "tc_util.h"
#include "tc_common.h"

static void explain(void)
{
    fprintf(stderr, "Usage: ... theaterq mode [LOAD|RUN|CLEAR] cont [LOOP|HOLD|CLEAR]\n");
}

static int theaterq_parse_opt(const struct qdisc_util *qu, int argc, 
                              char **argv, struct nlmsghdr *n, const char *dev)
{
    __u32 mode = THEATERQ_STAGE_LOAD;
    __u32 cont = THEATERQ_CONT_HOLD;
    struct rtattr *tail;

    for ( ; argc > 0; --argc, ++argv) {
        if (matches(*argv, "mode") == 0) {
            NEXT_ARG();
            if (strcmp(*argv, "LOAD") == 0) {
                mode = THEATERQ_STAGE_LOAD;
            } else if (strcmp(*argv, "RUN") == 0) {
                mode = THEATERQ_STAGE_RUN;
            } else if (strcmp(*argv, "CLEAR") == 0) {
                mode = THEATERQ_STAGE_CLEAR;
            } else {
                fprintf(stderr, "Unsupported mode \"%s\".\n", *argv);
                explain();
                return -1;
            }
        } else if (matches(*argv, "cont") == 0) {
            NEXT_ARG();
            if (strcmp(*argv, "LOOP") == 0) {
                mode = THEATERQ_CONT_LOOP;
            } else if (strcmp(*argv, "HOLD") == 0) {
                mode = THEATERQ_CONT_HOLD;
            } else if (strcmp(*argv, "CLEAR") == 0) {
                mode = THEATERQ_CONT_CLEAR;
            } else {
                fprintf(stderr, "Unsupported continue mode \"%s\".\n", *argv);
                explain();
                return -1;
            }
        } else if (matches(*argv, "help") == 0) {
            explain();
            return -1;
        } else {
            fprintf(stderr, "What is \"%s\"?\n", *argv);
            explain();
            return -1;
        }
    }

    tail = addattr_nest(n, 1024, TCA_OPTIONS | NLA_F_NESTED);
    addattr_l(n, 1024, TCA_THEATERQ_MODE, &mode, sizeof(mode));
    addattr_l(n, 1024, TCA_THEATERQ_CONT_MODE, &cont, sizeof(cont));
    addattr_nest_end(n, tail);
    fprintf(stderr, "Please ingest Trace File using /dev/theaterq:eth1:10:0.\n");
    return 0;
}

static int theaterq_print_opt(const struct qdisc_util *qu, FILE *f, 
                              struct rtattr *opt)
{
    return 0;
}

static int theaterq_print_xstats(const struct qdisc_util *qu, FILE *f,
                                 struct rtattr *xstats)
{
    return 0;
}

struct qdisc_util theaterq_qdisc_util = {
    .id           = "theaterq",
    .parse_qopt   = theaterq_parse_opt,
    .print_qopt   = theaterq_print_opt,
    .print_xstats = theaterq_print_xstats,
};
