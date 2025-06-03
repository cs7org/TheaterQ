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

    return 0;
}

static int theaterq_print_opt(const struct qdisc_util *qu, FILE *f, 
                              struct rtattr *opt)
{
    __u32 stage = 0;
    __u64 seed = 0;
    __s32 pkt_overhead = 0;
    __u32 cont = 0;
    char *ingest_cdev = NULL;
    __u64 entry_count = 0;
    __u64 entry_pos = 0;
    struct rtattr *tb[TCA_THEATERQ_MAX + 1];
    char present[TCA_THEATERQ_MAX + 1] = {};

    if (opt == NULL)
        return 0;

    parse_rtattr(tb, TCA_THEATERQ_MAX, RTA_DATA(opt), RTA_PAYLOAD(opt));

    if (tb[TCA_THEATERQ_STAGE]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_STAGE]) < sizeof(stage))
            return -1;
        stage = rta_getattr_u32(tb[TCA_THEATERQ_STAGE]);
        present[TCA_THEATERQ_STAGE]++;
    }
    
    if (tb[TCA_THEATERQ_PRNG_SEED]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_PRNG_SEED]) < sizeof(seed))
            return -1;
        seed = rta_getattr_u64(tb[TCA_THEATERQ_PRNG_SEED]);
        present[TCA_THEATERQ_PRNG_SEED]++;
    }

    if (tb[TCA_THEATERQ_PKT_OVERHEAD]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_PKT_OVERHEAD]) < sizeof(pkt_overhead))
            return -1;
        pkt_overhead = rta_getattr_s32(tb[TCA_THEATERQ_PKT_OVERHEAD]);
        present[TCA_THEATERQ_PKT_OVERHEAD]++;
    }

    if (tb[TCA_THEATERQ_CONT_MODE]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_CONT_MODE]) < sizeof(cont))
            return -1;
        cont = rta_getattr_u32(tb[TCA_THEATERQ_CONT_MODE]);
        present[TCA_THEATERQ_CONT_MODE]++;
    }

    if (tb[TCA_THEATERQ_INGEST_CDEV]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_INGEST_CDEV]) < sizeof(*ingest_cdev))
            return -1;
        ingest_cdev = RTA_DATA(tb[TCA_THEATERQ_INGEST_CDEV]);
        present[TCA_THEATERQ_INGEST_CDEV]++;
    }

    if (tb[TCA_THEATERQ_ENTRY_LEN]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_ENTRY_LEN]) < sizeof(entry_count))
            return -1;
        entry_count = rta_getattr_u64(tb[TCA_THEATERQ_ENTRY_LEN]);
        present[TCA_THEATERQ_ENTRY_LEN]++;
    }

    if (tb[TCA_THEATERQ_ENTRY_POS]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_ENTRY_POS]) < sizeof(entry_pos))
            return -1;
        entry_pos = rta_getattr_u64(tb[TCA_THEATERQ_ENTRY_POS]);
        present[TCA_THEATERQ_ENTRY_POS]++;
    }

    if (present[TCA_THEATERQ_STAGE]) {
        char *stage_str = "INVALID";

        if (stage == THEATERQ_STAGE_LOAD)
            stage_str = "LOAD";
        else if (stage == THEATERQ_STAGE_RUN)
            stage_str = "RUN";
        else if (stage == THEATERQ_STAGE_FINISH)
            stage_str = "FINISH";

        print_string(PRINT_ANY, "stage", " stage %s", stage_str);
    }

    if (present[TCA_THEATERQ_PRNG_SEED]) 
        print_u64(PRINT_ANY, "seed", " seed %llu", seed);
    
    if (present[TCA_THEATERQ_PKT_OVERHEAD])
        print_s64(PRINT_ANY, "packet_overhead", 
                  " packet_overhead %d", entry_count);

    if (present[TCA_THEATERQ_CONT_MODE]) {
        char *cont_str = "INVALID";

        if (cont == THEATERQ_CONT_HOLD)
            cont_str = "HOLD";
        else if (cont == THEATERQ_CONT_LOOP)
            cont_str = "LOOP";
        else if (cont == THEATERQ_CONT_CLEAR)
            cont_str = "CLEAR";

        print_string(PRINT_ANY, "cont_mode", " cont_mode %s", cont_str);
    }

    if (present[TCA_THEATERQ_INGEST_CDEV])
        print_string(PRINT_ANY, "ingest", " ingest %s", ingest_cdev);

    if (present[TCA_THEATERQ_ENTRY_LEN])
        print_u64(PRINT_ANY, "entries", " entries %llu", entry_count);
    
    if (present[TCA_THEATERQ_ENTRY_POS])
        print_u64(PRINT_ANY, "position", " position %llu", entry_pos);

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
