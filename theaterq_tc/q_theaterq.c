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
    fprintf(stderr, "Usage: ... theaterq [stage {LOAD|RUN|ARM|CLEAR}]\n"
                    "                    [cont {LOOP|HOLD|CLEAR}]\n"
                    "                    [byteqlen]\n"
                    "                    [allow_gso]\n"
                    "                    [seed SEED]\n"
                    "                    [overhead PACKETOVERHEAD]\n"
                    "                    [syncgroup SYNCGROUP]\n");
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
    __s32 syncgroup = -1;
    __u8 use_byteq = 0; 
    __u8 allow_gso = 0;
    bool has_seed = false;
    bool has_syncgroup = false;
    struct rtattr *tail;

    for ( ; argc > 0; --argc, ++argv) {
        if (matches(*argv, "stage") == 0) {
            NEXT_ARG();
            if (strcmp(*argv, "LOAD") == 0) {
                stage = THEATERQ_STAGE_LOAD;
            } else if (strcmp(*argv, "RUN") == 0) {
                stage = THEATERQ_STAGE_RUN;
            } else if (strcmp(*argv, "ARM") == 0) {
                stage = THEATERQ_STAGE_ARM;
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
        } else if (matches(*argv, "byteqlen") == 0) {
            use_byteq = 1; 
        } else if (matches(*argv, "allow_gso") == 0) {
            allow_gso = 1;
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
        } else if (matches(*argv, "syncgroup") == 0) {
            NEXT_ARG();
            if (get_s32(&syncgroup, *argv, 0)) {
                explain1("syncgroup");
                return -1;
            }

            if (syncgroup < -1 || syncgroup > UINT8_MAX) {
                fprintf(stderr, "Invalid syncgroup \"%d\" (select from [-1,%d]).\n", 
                        syncgroup, UINT8_MAX);
                explain();
                return -1;
            }

            has_syncgroup = true;
        } else if (matches(*argv, "help") == 0) {
            explain();
            return -1;
        } else {
            fprintf(stderr, "What is \"%s\"?\n", *argv);
            explain();
            return -1;
        }
    }

    tail = addattr_nest(n, 2048, TCA_OPTIONS | NLA_F_NESTED);
    if (stage && 
        addattr_l(n, 2048, TCA_THEATERQ_STAGE, &stage, sizeof(__u64)) < 0)
            return -1;
    if (cont && 
        addattr_l(n, 2048, TCA_THEATERQ_CONT_MODE, &cont, sizeof(__u64)) < 0)
            return -1;
    if (has_seed && 
        addattr_l(n, 2048, TCA_THEATERQ_PRNG_SEED, &seed, sizeof(__u64)) < 0)
            return -1;
    if (pkt_overhead && 
        addattr_l(n, 2048, TCA_THEATERQ_PKT_OVERHEAD, &pkt_overhead, sizeof(__u64)) < 0)
            return -1;
    if (has_syncgroup && 
        addattr_l(n, 2048, TCA_THEATERQ_SYNCGRP, &syncgroup, sizeof(__u64)) < 0)
            return -1;
    if (use_byteq && 
        addattr_l(n, 2048, TCA_THEATERQ_USE_BYTEQ, &use_byteq, sizeof(__u64)) < 0)
            return -1;
    if (allow_gso &&
        addattr_l(n, 2048, TCA_THEATERQ_ALLOW_GSO, &allow_gso, sizeof(__u64)) < 0)
            return -1;

    addattr_nest_end(n, tail);
    return 0;
}

static int theaterq_print_opt(const struct qdisc_util *qu, FILE *f, 
                              struct rtattr *opt)
{
    __u32 stage = THEATERQ_STAGE_UNSPEC;
    __u64 seed = 0;
    __u32 pkt_overhead = 0;
    __u32 syncgroup = -1;
    __u32 cont = THEATERQ_CONT_UNSPEC;
    __u64 entry_count = 0;
    __u64 entry_pos = 0;
    struct theaterq_entry *entry_current = NULL;
    char *ingest_cdev = NULL;
    char cdev_buf[THEATERQ_CDEV_MAX_NAMELEN + sizeof(THEATERQ_CDEV_PREFIX)] = {};

    struct rtattr *tb[TCA_THEATERQ_MAX + 1];
    char present[TCA_THEATERQ_MAX + 1] = {};

    SPRINT_BUF(b1);

    if (opt == NULL)
        return 0;

    parse_rtattr_nested(tb, TCA_THEATERQ_MAX, opt);

    if (tb[TCA_THEATERQ_STAGE]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_STAGE]) < sizeof(stage))
            return -1;
        stage = (__s32) rta_getattr_u64(tb[TCA_THEATERQ_STAGE]);
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
        pkt_overhead = (__s32) rta_getattr_u64(tb[TCA_THEATERQ_PKT_OVERHEAD]);
        present[TCA_THEATERQ_PKT_OVERHEAD]++;
    }

    if (tb[TCA_THEATERQ_SYNCGRP]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_SYNCGRP]) < sizeof(syncgroup))
            return -1;

        syncgroup = (__s32) rta_getattr_u64(tb[TCA_THEATERQ_SYNCGRP]);
        present[TCA_THEATERQ_SYNCGRP]++;
    }

    if (tb[TCA_THEATERQ_CONT_MODE]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_CONT_MODE]) < sizeof(cont))
            return -1;
        cont = (__u32) rta_getattr_u64(tb[TCA_THEATERQ_CONT_MODE]);
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

    if (tb[TCA_THEATERQ_ENTRY_CURRENT]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_ENTRY_CURRENT]) < sizeof(*entry_current))
            return -1;
        entry_current = RTA_DATA(tb[TCA_THEATERQ_ENTRY_CURRENT]);
        present[TCA_THEATERQ_ENTRY_CURRENT]++;
    }

    if (present[TCA_THEATERQ_STAGE]) {
        char *stage_str = "INVALID";

        if (stage == THEATERQ_STAGE_LOAD)
            stage_str = "LOAD";
        else if (stage == THEATERQ_STAGE_RUN)
            stage_str = "RUN";
        else if (stage == THEATERQ_STAGE_ARM)
            stage_str = "ARM";
        else if (stage == THEATERQ_STAGE_FINISH)
            stage_str = "FINISH";

        print_string(PRINT_ANY, "stage", "stage %s", stage_str);
    }

    if (present[TCA_THEATERQ_PRNG_SEED]) 
        print_u64(PRINT_ANY, "seed", " seed %llu", seed);
    
    if (present[TCA_THEATERQ_PKT_OVERHEAD])
        print_s64(PRINT_ANY, "packet_overhead", 
                  " packet_overhead %d", pkt_overhead);

    if (present[TCA_THEATERQ_SYNCGRP] && syncgroup != -1)
        print_s64(PRINT_ANY, "syncgroup", 
                 " syncgroup %d", syncgroup);

    print_on_off(PRINT_ANY, "bytequeue", 
                 " bytequeue %s", tb[TCA_THEATERQ_USE_BYTEQ]);
    print_on_off(PRINT_ANY, "allow_gso", 
                 " allow_gso %s", tb[TCA_THEATERQ_ALLOW_GSO]);

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

    if (present[TCA_THEATERQ_INGEST_CDEV]) {
        snprintf(cdev_buf, sizeof(cdev_buf), "%s%s", 
                 THEATERQ_CDEV_PREFIX, ingest_cdev);

        print_string(PRINT_ANY, "ingest", " ingest %s", cdev_buf);
    }

    if (present[TCA_THEATERQ_ENTRY_LEN])
        print_u64(PRINT_ANY, "entries", " entries %llu", entry_count);
    
    if (present[TCA_THEATERQ_ENTRY_POS])
        print_u64(PRINT_ANY, "position", " position %llu", entry_pos);

    if (present[TCA_THEATERQ_ENTRY_CURRENT]) {
        open_json_object("current");

        if (is_json_context()) {
            print_float(PRINT_JSON, "delay", NULL, 
                        (double) entry_current->latency / 1000000000.0);
            print_float(PRINT_JSON, "jitter", NULL, 
                        (double) entry_current->jitter / 1000000000.0);
        } else {
            print_string(PRINT_FP, NULL, " delay %s", 
                         sprint_time64(entry_current->latency, b1));
            if (entry_current->jitter != 0)
                print_string(PRINT_FP, NULL, "  %s", 
                             sprint_time64(entry_current->jitter, b1));
        }

        if (entry_current->rate != 0 || is_json_context())
            tc_print_rate(PRINT_ANY, "rate", " rate %s", entry_current->rate);
        
        print_float(PRINT_JSON, "loss", NULL, 
                        (1. * entry_current->loss) / UINT32_MAX);
        if (entry_current->loss)
            print_float(PRINT_FP, NULL, " loss", 
                        (100. * entry_current->loss) / UINT32_MAX);

        print_u64(PRINT_ANY, "limit", " limit %llu", 
                  (__u64) entry_current->limit);

        close_json_object();
    }

    return 0;
}

static int theaterq_print_xstats(const struct qdisc_util *qu, FILE *f,
                                 struct rtattr *xstats)
{
    struct tc_theaterq_xstats _stats = {};
    struct tc_theaterq_xstats *stats;

    SPRINT_BUF(b1);

    if (xstats == NULL)
        return 0;

    stats = RTA_DATA(xstats);
    if (RTA_PAYLOAD(xstats) < sizeof(*stats)) {
        memcpy(&_stats, stats, RTA_PAYLOAD(xstats));
        stats = &_stats;
    }

    print_u64(PRINT_FP, NULL, " tfifo %llub", stats->tfifo_blen);
    print_u64(PRINT_FP, NULL, " %llup", stats->tfifo_plen);
    print_u64(PRINT_JSON, "tfifo_blen", NULL, stats->tfifo_blen);
    print_u64(PRINT_JSON, "tfifo_plen", NULL, stats->tfifo_plen);
    print_u64(PRINT_ANY, "looped", " looped %llu", stats->looped);
    print_string(PRINT_FP, NULL, " duration %s", 
                 sprint_time64(stats->total_time, b1));
    print_float(PRINT_JSON, "duration", NULL, 
                (double) stats->total_time / 1000000000.0);
    print_u64(PRINT_ANY, "entries", " entries %llu", stats->total_entries);

    return 0;
}

struct qdisc_util theaterq_qdisc_util = {
    .id           = "theaterq",
    .parse_qopt   = theaterq_parse_opt,
    .print_qopt   = theaterq_print_opt,
    .print_xstats = theaterq_print_xstats,
};
