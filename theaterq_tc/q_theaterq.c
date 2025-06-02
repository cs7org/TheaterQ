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
    fprintf(stderr, "Usage: ... theaterq [stage {LOAD|RUN|CLEAR}]\n"
                    "                    [cont {LOOP|HOLD|CLEAR}]\n"
                    "                    [seed SEED]\n"
                    "                    [overhead PACKETOVERHEAD]\n");
}

static void explain1(const char *arg)
{
    fprintf(stderr, "Illegal \"%s\"\n", arg);
}

static int theaterq_parse_opt(const struct qdisc_util *qu, int argc, 
                              char **argv, struct nlmsghdr *n, const char *dev)
{
    __u32 stage = THEATERQ_STAGE_UNSPEC;
    __u32 cont = THEATERQ_CONT_UNSPEC;
    __s32 pkt_overhead = 0;
    __u64 seed = 0;
    bool has_seed = false;
    struct rtattr *tail;

    for ( ; argc > 0; --argc, ++argv) {
        if (matches(*argv, "stage") == 0) {
            NEXT_ARG();
            if (strcmp(*argv, "LOAD") == 0) {
                stage = THEATERQ_STAGE_LOAD;
            } else if (strcmp(*argv, "RUN") == 0) {
                stage = THEATERQ_STAGE_RUN;
            } else if (strcmp(*argv, "CLEAR") == 0) {
                stage = THEATERQ_STAGE_CLEAR;
            } else {
                fprintf(stderr, "Unsupported stage \"%s\".\n", *argv);
                explain();
                return -1;
            }
        } else if (matches(*argv, "cont") == 0) {
            NEXT_ARG();
            if (strcmp(*argv, "LOOP") == 0) {
                cont = THEATERQ_CONT_LOOP;
            } else if (strcmp(*argv, "HOLD") == 0) {
                cont = THEATERQ_CONT_HOLD;
            } else if (strcmp(*argv, "CLEAR") == 0) {
                cont = THEATERQ_CONT_CLEAR;
            } else {
                fprintf(stderr, "Unsupported continue mode \"%s\".\n", *argv);
                explain();
                return -1;
            }
        } else if (matches(*argv, "seed") == 0) {
            NEXT_ARG();
            has_seed = true;
            if (get_u64(&seed, *argv, 10)) {
                explain1("seed");
                return -1;
            }
        } else if (matches(*argv, "overhead") == 0) {
            NEXT_ARG();
            if (get_s32(&pkt_overhead, *argv, 0)) {
                explain1("overhead");
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
    if (stage && 
        addattr_l(n, 1024, TCA_THEATERQ_STAGE, &stage, sizeof(stage)) < 0)
            return -1;
    if (cont && 
        addattr_l(n, 1024, TCA_THEATERQ_CONT_MODE, &cont, sizeof(cont)) < 0)
            return -1;
    if (has_seed && 
        addattr_l(n, 1024, TCA_THEATERQ_PRNG_SEED, &seed, sizeof(seed)) < 0)
            return -1;
    if (pkt_overhead && 
        addattr_l(n, 1024, TCA_THEATERQ_PKT_OVERHEAD, &pkt_overhead, sizeof(pkt_overhead)) < 0)
            return -1;
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
