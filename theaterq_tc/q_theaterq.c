#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <uapi/linux/pkt_sch_theaterq.h>

#include "utils.h"
#include "tc_util.h"
#include "tc_common.h"

#define Q_THEATERQ_FLAG_NOT_SET 2

static void explain(void)
{
    fprintf(stderr, "Usage: ... theaterq [stage {LOAD|RUN|ARM|CLEAR}]\n"
                    "                    [cont {LOOP|HOLD|CLEAR}]\n"
                    "                    [byteqlen|pktqlen]\n"
                    "                    [allow_gso|prevent_gso]\n"
                    "                    [ingest {SIMPLE|EXTENDED}]\n"
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
    __u32 ingest = THEATERQ_INGEST_MODE_UNSPEC;
    __s32 pkt_overhead = 0;
    __u64 seed = 0;
    __s32 syncgroup = -1;
    __u8 use_byteq = Q_THEATERQ_FLAG_NOT_SET; 
    __u8 allow_gso = Q_THEATERQ_FLAG_NOT_SET;
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
        } else if (matches(*argv, "ingest") == 0) {
            NEXT_ARG();
            if (strcmp(*argv, "SIMPLE") == 0) {
                ingest = THEATERQ_INGEST_MODE_SIMPLE;
            } else if (strcmp(*argv, "EXTENDED") == 0) {
                ingest = THEATERQ_INGEST_MODE_EXTENDED;
            } else {
                fprintf(stderr, "Unsupported ingest mode \"%s\".\n", *argv);
                explain();
                return -1;
            }
        } else if (matches(*argv, "byteqlen") == 0) {
            use_byteq = 1; 
        } else if (matches(*argv, "allow_gso") == 0) {
            allow_gso = 1;
        } else if (matches(*argv, "pktqlen") == 0) {
            use_byteq = 0;
        } else if (matches(*argv, "prevent_gso") == 0) {
            allow_gso = 0;
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

            if (syncgroup < THEATERQ_SYNCGROUP_LEAVE || syncgroup > UINT8_MAX) {
                fprintf(stderr, "Invalid syncgroup \"%d\" (select from [%d,%d]).\n", 
                        syncgroup, THEATERQ_SYNCGROUP_LEAVE, UINT8_MAX);
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
        addattr_l(n, 2048, TCA_THEATERQ_STAGE, &stage, sizeof(stage)) < 0)
            return -1;
    if (cont && 
        addattr_l(n, 2048, TCA_THEATERQ_CONT_MODE, &cont, sizeof(cont)) < 0)
            return -1;
    if (ingest && 
        addattr_l(n, 2048, TCA_THEATERQ_INGEST_MODE, &ingest, sizeof(ingest)) < 0)
            return -1;
    if (has_seed && 
        addattr_l(n, 2048, TCA_THEATERQ_PRNG_SEED, &seed, sizeof(seed)) < 0)
            return -1;
    if (pkt_overhead && 
        addattr_l(n, 2048, TCA_THEATERQ_PKT_OVERHEAD, &pkt_overhead, sizeof(pkt_overhead)) < 0)
            return -1;
    if (has_syncgroup && 
        addattr_l(n, 2048, TCA_THEATERQ_SYNCGRP, &syncgroup, sizeof(syncgroup)) < 0)
            return -1;
    if (use_byteq != Q_THEATERQ_FLAG_NOT_SET && 
        addattr_l(n, 2048, TCA_THEATERQ_USE_BYTEQ, &use_byteq, sizeof(use_byteq)) < 0)
            return -1;
    if (allow_gso != Q_THEATERQ_FLAG_NOT_SET &&
        addattr_l(n, 2048, TCA_THEATERQ_ALLOW_GSO, &allow_gso, sizeof(use_byteq)) < 0)
            return -1;

    addattr_nest_end(n, tail);
    return 0;
}

static int theaterq_print_opt(const struct qdisc_util *qu, FILE *f, 
                              struct rtattr *opt)
{
    __u32 stage = THEATERQ_STAGE_UNSPEC;
    __u32 cont = THEATERQ_CONT_UNSPEC;
    __u32 ingest = THEATERQ_INGEST_MODE_UNSPEC;
    __u64 seed = 0;
    __u32 pkt_overhead = 0;
    __u32 syncgroup = -1;
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

#define SET_GETATTR_VALUE(destination, attr, accessor) do { \
                    if (tb[attr]) { \
                        if (RTA_PAYLOAD(tb[attr]) < sizeof(destination)) \
                            return -1; \
                        destination = accessor(tb[attr]); \
                        present[attr]++; \
                    } \
                } while (0)
    
    SET_GETATTR_VALUE(stage, TCA_THEATERQ_STAGE, rta_getattr_s32);
    SET_GETATTR_VALUE(cont, TCA_THEATERQ_CONT_MODE, rta_getattr_u32);
    SET_GETATTR_VALUE(ingest, TCA_THEATERQ_INGEST_MODE, rta_getattr_u32);
    SET_GETATTR_VALUE(seed, TCA_THEATERQ_PRNG_SEED, rta_getattr_u64);
    SET_GETATTR_VALUE(pkt_overhead, TCA_THEATERQ_PKT_OVERHEAD, rta_getattr_s32);
    SET_GETATTR_VALUE(syncgroup, TCA_THEATERQ_SYNCGRP, rta_getattr_s32);
    SET_GETATTR_VALUE(entry_count, TCA_THEATERQ_ENTRY_LEN, rta_getattr_u64);
    SET_GETATTR_VALUE(entry_pos, TCA_THEATERQ_ENTRY_POS, rta_getattr_u64);

#undef SET_GETATTR_VALUE

    if (tb[TCA_THEATERQ_INGEST_CDEV]) {
        if (RTA_PAYLOAD(tb[TCA_THEATERQ_INGEST_CDEV]) < sizeof(*ingest_cdev))
            return -1;
        ingest_cdev = RTA_DATA(tb[TCA_THEATERQ_INGEST_CDEV]);
        present[TCA_THEATERQ_INGEST_CDEV]++;
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

    if (present[TCA_THEATERQ_SYNCGRP] && 
        syncgroup != THEATERQ_SYNCGROUP_LEAVE)
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

    if (present[TCA_THEATERQ_INGEST_MODE]) {
        char *ingest_str = "INVALID";

        if (ingest == THEATERQ_INGEST_MODE_SIMPLE)
            ingest_str = "SIMPLE";
        else if (ingest == THEATERQ_INGEST_MODE_EXTENDED)
            ingest_str = "EXTENDED";

        print_string(PRINT_ANY, "ingest_mode", " ingest_mode %s", ingest_str);
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

        if (entry_current->dup_prob != 0) {
            if (is_json_context()) {
                print_float(PRINT_JSON, "duplicate_probability", NULL,
                            (1. * entry_current->dup_prob) / UINT32_MAX);
                print_float(PRINT_JSON, "duplicate_delay", NULL,
                            (double) entry_current->dup_delay / 1000000000.0);
            } else {
                print_float(PRINT_FP, NULL, " duplicate_probability",
                            (100. * entry_current->dup_prob) / UINT32_MAX);
                print_string(PRINT_FP, NULL, " %s",
                            sprint_time64(entry_current->dup_delay, b1));
            }
        }

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
