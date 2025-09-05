#ifndef __LINUX_PKT_SCH_THEATERQ_H
#define __LINUX_PKT_SCH_THEATERQ_H

#include <uapi/linux/pkt_sched.h>

#define THEATERQ_CDEV_MAX_NAMELEN 64
#define THEATERQ_CDEV_PREFIX "/dev/"
#define THEATERQ_NO_SYNCGRP_SELECTED -2

enum {
    THEATERQ_STAGE_UNSPEC,
    THEATERQ_STAGE_LOAD,
    THEATERQ_STAGE_RUN,
    THEATERQ_STAGE_CLEAR,
    THEATERQ_STAGE_FINISH,
    THEATERQ_STAGE_ARM,
    __THEATERQ_STAGE_MAX,
};
#define THEATERQ_STAGE_MAX (__THEATERQ_STAGE_MAX - 1)

enum {
    THEATERQ_CONT_UNSPEC,
    THEATERQ_CONT_HOLD,
    THEATERQ_CONT_LOOP,
    THEATERQ_CONT_CLEAR,
    __THEATERQ_CONT_MAX,
};
#define THEATERQ_CONT_MAX (__THEATERQ_CONT_MAX - 1)

enum {
    TCA_THEATERQ_UNSPEC,
    TCA_THEATERQ_PAD,
    TCA_THEATERQ_STAGE,
    TCA_THEATERQ_PRNG_SEED,
    TCA_THEATERQ_PKT_OVERHEAD,
    TCA_THEATERQ_CONT_MODE,
    TCA_THEATERQ_SYNCGRP,
    TCA_THEATERQ_USE_BYTEQ,
    TCA_THEATERQ_ALLOW_GSO,
    TCA_THEATERQ_INGEST_CDEV,
    TCA_THEATERQ_ENTRY_LEN,
    TCA_THEATERQ_ENTRY_POS,
    TCA_THEATERQ_ENTRY_CURRENT,
    __TCA_THEATERQ_MAX,
};
#define TCA_THEATERQ_MAX (__TCA_THEATERQ_MAX - 1)

struct theaterq_entry {
    __u64 delay;
    __u64 latency;
    __u64 jitter;
    __u64 rate;
    __u32 loss;
    __u32 limit;
    struct theaterq_entry *next;
};

struct tc_theaterq_xstats {
    __u64 looped;
    __u64 total_time;
    __u64 total_entries;
    __u32 tfifo_plen;
    __u64 tfifo_blen;
};

#endif //__LINUX_PKT_SCH_THEATERQ_H
