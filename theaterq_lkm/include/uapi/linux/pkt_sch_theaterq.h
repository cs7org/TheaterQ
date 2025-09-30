/*
TheaterQ Dynamic Network Emulator Kernel Module
    Copyright (C) 2025 Martin Ottens

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __LINUX_PKT_SCH_THEATERQ_H
#define __LINUX_PKT_SCH_THEATERQ_H

#include <uapi/linux/pkt_sched.h>

#define THEATERQ_CDEV_MAX_NAMELEN 64
#define THEATERQ_CDEV_PREFIX "/dev/"
#define THEATERQ_SYNCGROUP_LEAVE -1

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
    THEATERQ_CONT_CLEAN,
    __THEATERQ_CONT_MAX,
};
#define THEATERQ_CONT_MAX (__THEATERQ_CONT_MAX - 1)

enum {
    THEATERQ_INGEST_MODE_UNSPEC,
    THEATERQ_INGEST_MODE_SIMPLE,
    THEATERQ_INGEST_MODE_EXTENDED,
    __THEATERQ_INGEST_MODE_MAX,
};
#define THEATERQ_INGEST_MODE_MAX (__THEATERQ_INGEST_MODE_MAX - 1)

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
    TCA_THEATERQ_ENABLE_ECN,
    TCA_THEATERQ_INGEST_MODE,
    TCA_THEATERQ_INGEST_CDEV,
    TCA_THEATERQ_ENTRY_LEN,
    TCA_THEATERQ_ENTRY_POS,
    TCA_THEATERQ_ENTRY_CURRENT,
    TCA_THEATERQ_TIME_LEN,
    TCA_THEATERQ_TIME_PROGRESS,
    __TCA_THEATERQ_MAX,
};
#define TCA_THEATERQ_MAX (__TCA_THEATERQ_MAX - 1)

struct theaterq_entry {
    __u64 keep;
    __u64 latency;
    __u64 jitter;
    __u64 rate;
    __u32 loss;
    __u32 limit;
    __u32 dup_prob;
    __u32 dup_delay;
    struct theaterq_entry *next;
};

struct tc_theaterq_xstats {
    __u64 looped;
    __u64 total_time;
    __u64 total_entries;
    __u32 edfq_plen;
    __u64 edfq_blen;
};

#endif //__LINUX_PKT_SCH_THEATERQ_H
