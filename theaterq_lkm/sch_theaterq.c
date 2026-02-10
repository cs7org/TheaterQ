/*
TheaterQ Dynamic Network Emulator Kernel Module
    Copyright (C) 2025-2026 Martin Ottens

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

#include <linux/module.h>
#include <net/pkt_sched.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/prandom.h>
#include <linux/rtnetlink.h>
#include <linux/reciprocal_div.h>
#include <linux/rbtree.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,10)
#include <net/gso.h>
#endif
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/sock.h>
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/moduleparam.h>
#include <net/inet_ecn.h>
#include <linux/ctype.h>

#include "include/uapi/linux/pkt_sch_theaterq.h"

// DATA + HELPER FUNCTIONS =====================================================

#define THEATERQ_INGEST_MAXLEN 256
#define THEATERQ_NO_SYNCGRP_SELECTED -2
#define THEATERQ_NS_PER_US 1000
#define THEATERQ_NO_EXPIRY U64_MAX
#define THEATERQ_ALLOW_IMPLICIT_REORDER 0

// Slab allocator for Trace File entries of all instances
static struct kmem_cache *theaterq_cache = NULL;

// Lock for accessing syncgroup data across multiple instances
static DEFINE_SPINLOCK(theaterq_tree_lock);
static u8 syncgrps = 8;
static u8 syncgrps_members = 8;
static u16 reorder_routes = 255;

static const struct theaterq_entry theaterq_default_entry = {
    .keep = THEATERQ_NO_EXPIRY,
    .latency = 0ULL,
    .jitter = 0ULL,
    .rate = 0ULL,
    .loss = 0UL,
    .limit = 1000UL,
    .dup_prob = 0UL,
    .dup_delay = 0ULL,
    .route_id = 0UL,
    .next = NULL,
};

enum {
    THEATERQ_CDEV_AVAILABLE,
    THEATERQ_CDEV_LOCKED,
};

enum {
    THEATERQ_REPLAY_UNCHANGED = 0,
    THEATERQ_REPLAY_STOP = 1,
    THEATERQ_REPLAY_START = 2,
    THEATERQ_REPLAY_CLEAR = 4,
};

// Forward declaration
struct theaterq_syncgrp;

struct theaterq_sched_data {
    // FIFO input Dequeue
    struct sk_buff *fifo_head;
    struct sk_buff *fifo_tail;

    // Earliest Deadline First skb Dequeue
    struct rb_root edfq_root;
    struct sk_buff *edfq_head;
    struct sk_buff *edfq_tail;

    u64 t_busy_time;
    u32 edfq_len; // TODO. Needed?
    u64 edfq_blen;

    u32 fifo_len;
    u64 fifo_blen;

    struct Qdisc *qdisc;
    struct qdisc_watchdog watchdog;

    struct prng {
        u64 seed;
        bool seed_set;
        struct rnd_state prng_state;
    } prng;

    bool isdup;

    s32 packet_overhead;
    u32 stage;
    u32 cont_mode;
    u32 ingest_mode;
    bool use_byte_queue;
    bool apply_before_q;
    bool allow_gso;
    bool enable_ecn;

    // Linked list with Trace File entries
    bool deletion_pending;
    // Lock to prevent list clear and chardev insertion at the same time
    spinlock_t e_lock;
    struct theaterq_entry *current_entry;
    struct theaterq_entry *e_head;
    struct theaterq_entry *e_tail;
    u64 e_entries;
    u64 e_current;
    u64 e_totaltime;
    u64 e_progresstime;

    struct ingest_cdev {
        char name[THEATERQ_CDEV_MAX_NAMELEN];
        bool en;
        struct class *cls;
        struct device *device;
        dev_t dev;
        struct cdev cdev;
        atomic_t opened;
    } ingest_cdev; 

    struct ingest_helper {
        char lbuf[THEATERQ_INGEST_MAXLEN];
        size_t lpos;
    } ingest_helper;

    u64 t_updated;

    // State for route handling to prevent unwanted implicit packet 
    // reordering within a route
    u64 *r_last_send_times;

    // Referencing back to the theaterq_syncgrps[] entry.
    // NULL = not a member of any snycgroup
    struct theaterq_syncgrp *syncgrp;
    struct tc_theaterq_xstats stats;
};

// Syncgroup data structures:
// theaterq_syncgrps[syncgrps]:
//       - [0] -> 0, members[syncgrps_members]
//       - [1] -> 1, members[syncgrps_members]
//       - ...
// 'members' is a short array with static size, every entry can be NULL
// - insert: find first NULL entry and write
// - find/remove: iterate over all member fields
// This data structures should only be accessed under theaterq_tree_lock
struct theaterq_syncgrp {
    u16 index;
    struct theaterq_sched_data **members;
};

static struct theaterq_syncgrp *theaterq_syncgrps = NULL;

struct theaterq_skb_cb {
    // Send time of a packet: arrive_time + delays, used for EDFQ sorting
    u64 earliest_send_time;
    // Transmit time is determined at the time the packet is enqueued
    u64 transmit_time;
};

// SYNC GROUPS =================================================================

// Forward declarations
static void entry_list_clear(struct theaterq_sched_data *);
static struct sk_buff *theaterq_peek_edfq(struct theaterq_sched_data *);
static void theaterq_stop_replay(struct theaterq_sched_data *q, bool);
static int theaterq_start_replay(struct theaterq_sched_data *q, u64);

static void theaterq_syncgroup_stopall(struct theaterq_sched_data *q,
                                       u32 own_newstage)
{
    spin_lock_bh(&theaterq_tree_lock);

    // If no syncgroup is set: Just stop own instance
    if (!q->syncgrp) {
        theaterq_stop_replay(q, true);
        q->stage = own_newstage;
        goto unlock;
    }

    u32 group = q->syncgrp->index;

    for (int i = 0; i < syncgrps_members; i++) {
        if (theaterq_syncgrps[group].members[i] == NULL)
                continue;
        
        // Stop all instances in correct stage
        struct theaterq_sched_data *instance = theaterq_syncgrps[group].members[i];
        if (instance->stage != THEATERQ_STAGE_ARM && 
            instance->stage != THEATERQ_STAGE_RUN && 
            instance->stage != THEATERQ_STAGE_FINISH)
                continue;

        theaterq_stop_replay(instance, true);

        if (instance != q)
            instance->stage = THEATERQ_STAGE_LOAD;
        else
            instance->stage = own_newstage;
    }

unlock:
    spin_unlock_bh(&theaterq_tree_lock);
}

static int theaterq_syncgroup_startall(struct theaterq_sched_data *q)
{
    int ret = 0;
    u64 now = ktime_get_ns();
    spin_lock_bh(&theaterq_tree_lock);

    // If no syncgroup is set: Just start own instance
    if (!q->syncgrp) {
        if (q->stage == THEATERQ_STAGE_LOAD ||
            q->stage == THEATERQ_STAGE_FINISH ||
            q->stage == THEATERQ_STAGE_ARM)
                ret = theaterq_start_replay(q, now);

        goto unlock;
    }

    u32 grp = q->syncgrp->index;

    for (int i = 0; i < syncgrps_members; i++) {
        if (theaterq_syncgrps[grp].members[i] == NULL)
                continue;
        
        // Start all instances that are in correct stage
        struct theaterq_sched_data *instance = theaterq_syncgrps[grp].members[i];
        if (instance->stage != THEATERQ_STAGE_LOAD && 
            instance->stage != THEATERQ_STAGE_FINISH &&
            instance->stage != THEATERQ_STAGE_ARM)
                continue;

        int errno = theaterq_start_replay(instance, now);
        if (errno) {
            printk(KERN_WARNING "theaterq: Unable to start member %i in "
                                "syncgroup %d: %d\n", i, grp, errno);
            ret = errno;
        }
    }

unlock:
    spin_unlock_bh(&theaterq_tree_lock);
    return ret;
}

static bool theaterq_syncgroup_join(struct theaterq_sched_data *q, s32 grp)
{
    if (grp == THEATERQ_SYNCGROUP_LEAVE)
        return true;

    if (grp < THEATERQ_SYNCGROUP_LEAVE) {
        printk(KERN_WARNING "theaterq: Invalid syncgroup: Must be %d or "
                            "positive.\n", THEATERQ_SYNCGROUP_LEAVE);
        return false;
    }

    if (grp >= syncgrps) {
        printk(KERN_WARNING "theaterq: Maximum syncgroup index is %d\n", 
               syncgrps - 1);
        return false;
    }

    spin_lock_bh(&theaterq_tree_lock);

    int free_index = -1;

    for (int i = 0; i < syncgrps_members; i++) {
        if (theaterq_syncgrps[grp].members[i] == NULL) {
            if (free_index == -1)
                free_index = i;
        } else {
            u32 otherstage = theaterq_syncgrps[grp].members[i]->stage;
            if (otherstage != THEATERQ_STAGE_LOAD && otherstage != THEATERQ_STAGE_FINISH) {
                printk(KERN_WARNING "theaterq: Cannot join a syncgroup with "
                                    "running/armed members\n");
                goto fail_unlock;
            }
        }
    }

    if (free_index == -1) {
        printk(KERN_WARNING "theaterq: Selected syncgroup is full.\n");
        goto fail_unlock;
    }

    theaterq_syncgrps[grp].members[free_index] = q;
    q->syncgrp = &theaterq_syncgrps[grp];
    spin_unlock_bh(&theaterq_tree_lock);
    return true;

fail_unlock:
    spin_unlock_bh(&theaterq_tree_lock);
    return false;
}

static void theaterq_syncgroup_leave(struct theaterq_sched_data *q)
{
    spin_lock_bh(&theaterq_tree_lock);

    if (!q->syncgrp)
        goto unlock;
    
    for (int i = 0; i < syncgrps_members; i++) {
        if (theaterq_syncgrps[q->syncgrp->index].members[i] == q) {
            theaterq_syncgrps[q->syncgrp->index].members[i] = NULL;
            break;
        }
    }

    q->syncgrp = NULL;

unlock:
    spin_unlock_bh(&theaterq_tree_lock);
}

static inline bool theaterq_syncgroup_change(struct theaterq_sched_data *q, 
                                             s32 grp)
{
    theaterq_syncgroup_leave(q);
    return theaterq_syncgroup_join(q, grp);
}

static inline struct theaterq_skb_cb *theaterq_skb_cb(struct sk_buff *skb)
{
    qdisc_cb_private_validate(skb, sizeof(struct theaterq_skb_cb));
    return (struct theaterq_skb_cb *) qdisc_skb_cb(skb)->data;
}

static inline bool loss_event(struct theaterq_sched_data *q)
{
    if (!READ_ONCE(q->current_entry)) return false;

    return q->current_entry->loss && 
           q->current_entry->loss >= prandom_u32_state(&q->prng.prng_state);
}

static inline bool dup_event(struct theaterq_sched_data *q)
{
    if (!READ_ONCE(q->current_entry)) return false;

    return q->current_entry->dup_prob &&
           q->current_entry->dup_prob >= prandom_u32_state(&q->prng.prng_state);
}

static inline s64 get_pkt_delay(s64 mu, s32 sigma, struct prng *prng)
{
    u32 rnd;

    if (sigma == 0)
        return mu;

    rnd = prandom_u32_state(&prng->prng_state);
    return ((rnd % (2 * (u32) sigma)) + mu) - sigma;
}

static inline u64 packet_time_ns(u64 len, const struct theaterq_sched_data *q)
{
    if (!q->current_entry || q->current_entry->rate == 0)
        return 0ULL;

    len += q->packet_overhead;
    return div64_u64(len * NSEC_PER_SEC, q->current_entry->rate);
}

static void edfq_enqueue(struct sk_buff *nskb, struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    u64 tnext = theaterq_skb_cb(nskb)->earliest_send_time;

    // From NetEm: Linked list, when jitter is low, otherwise a tree is
    // used for quick access
    if (!q->edfq_tail || tnext >= theaterq_skb_cb(q->edfq_tail)->earliest_send_time) {
        if (q->edfq_tail)
            q->edfq_tail->next = nskb;
        else
            q->edfq_head = nskb;
        
        q->edfq_tail = nskb;
    } else {
        struct rb_node **p = &q->edfq_root.rb_node;
        struct rb_node *parent = NULL;

        while (*p) {
            struct sk_buff *skb;

            parent = *p;
            skb = rb_to_skb(parent);
            if (tnext >= theaterq_skb_cb(skb)->earliest_send_time)
                p = &parent->rb_right;
            else
                p = &parent->rb_left;
        }

        rb_link_node(&nskb->rbnode, parent, p);
        rb_insert_color(&nskb->rbnode, &q->edfq_root);
    }

    q->edfq_len++;
    q->edfq_blen += qdisc_pkt_len(nskb);
    sch->q.qlen++; // TODO
}

static void fifo_enqueue(struct sk_buff *nskb, struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    if (q->fifo_tail)
        q->fifo_tail->next = nskb;
    else
        q->edfq_head = nskb;

    q->edfq_tail = nskb;
    q->fifo_len++;
    q->fifo_blen += qdisc_pkt_len(nskb);
}

static void edfq_reset(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct rb_node *p = rb_first(&q->edfq_root);

    while (p) {
        struct sk_buff *skb = rb_to_skb(p);

        p = rb_next(p);
        rb_erase(&skb->rbnode, &q->edfq_root);
        rtnl_kfree_skbs(skb, skb);
    }

    rtnl_kfree_skbs(q->edfq_head, q->edfq_tail);
    q->edfq_head = NULL;
    q->edfq_tail = NULL;
    q->edfq_len = 0;
    q->edfq_blen = 0;
}

static void fifo_reset(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    rtnl_kfree_skbs(q->fifo_head, q->fifo_tail);
    q->fifo_head = NULL;
    q->fifo_tail = NULL;
    q->fifo_len = 0;
    q->fifo_blen = 0;
}

// Always called under tree_lock, also acquires the instance lock to
// prevent chardev insertion during clearing the list
static void entry_list_clear(struct theaterq_sched_data *q)
{
    spin_lock_bh(&q->e_lock);
    struct theaterq_entry *e = q->e_head;
    struct theaterq_entry *next = NULL;

    while (e) {
        next = e->next;
        kmem_cache_free(theaterq_cache, e);
        e = next;
    }

    q->e_head = NULL;
    q->e_tail = NULL;
    q->current_entry = (struct theaterq_entry *) &theaterq_default_entry;
    q->e_current = 0;
    q->e_entries = 0;
    q->e_totaltime = 0;
    q->e_progresstime = 0;
    q->deletion_pending = false;
    spin_unlock_bh(&q->e_lock);
}

static void theaterq_stats_clear(struct tc_theaterq_xstats *stats)
{
    stats->looped = 0;
    stats->total_time = 0;
    stats->total_entries = 0;
}

// Always called under global lock, function should fully set the state
// to allow for Trace File replay
static int theaterq_start_replay(struct theaterq_sched_data *q, u64 now)
{
    if (!q->e_head) {
        q->stage = THEATERQ_STAGE_LOAD;
        q->t_updated = THEATERQ_NO_EXPIRY;
         WRITE_ONCE(q->current_entry, 
              (struct theaterq_entry *) &theaterq_default_entry);
        return -EINVAL;
    }

    if (atomic_cmpxchg(&q->ingest_cdev.opened, THEATERQ_CDEV_AVAILABLE, 
                       THEATERQ_CDEV_LOCKED))
        return -EBUSY;
    
    q->e_current = 0;
    q->e_progresstime = 0;
    q->t_busy_time = 0;
    q->stage = THEATERQ_STAGE_RUN;
    q->t_updated = now;
    memset(q->r_last_send_times, (reorder_routes + 1) * sizeof(u64), 0);
    WRITE_ONCE(q->current_entry, q->e_head);

    return 0;
}

// Stage transition not handled here, because its depends on the context
static void theaterq_stop_replay(struct theaterq_sched_data *q, bool clear)
{
    if (clear) {
        WRITE_ONCE(q->current_entry, 
                  (struct theaterq_entry *) &theaterq_default_entry);
        q->e_current = 0;
    }

    q->t_updated = THEATERQ_NO_EXPIRY;
    atomic_set(&q->ingest_cdev.opened, THEATERQ_CDEV_AVAILABLE);
}

// CHARDEV OPS =================================================================

static int ingest_cdev_open(struct inode *inode, struct file *filp)
{
    struct theaterq_sched_data *q;
    q = container_of(inode->i_cdev, struct theaterq_sched_data, 
                     ingest_cdev.cdev);
    filp->private_data = q;

    // Ensure that only one process has access to the chardev at a time
    if (atomic_cmpxchg(&q->ingest_cdev.opened, THEATERQ_CDEV_AVAILABLE, 
                       THEATERQ_CDEV_LOCKED))
        return -EBUSY;

    try_module_get(THIS_MODULE);
    return 0;
}

static int ingest_cdev_release(struct inode *inode, struct file *filp)
{
    struct theaterq_sched_data *q = filp->private_data;
    atomic_set(&q->ingest_cdev.opened, THEATERQ_CDEV_AVAILABLE);

    q->ingest_helper.lpos = 0;

    module_put(THIS_MODULE);
    return 0;
}

static ssize_t ingest_cdev_read(struct file *filp, char __user *buffer,
                                size_t length, loff_t *offset)
{
    // Do not allow any read requests from the chardev
    // Could be extended to print the internal Trace File list
    return -EINVAL;
}

static ssize_t ingest_cdev_write(struct file *filp, const char __user *buffer,
                             size_t len, loff_t *offset)
{
    struct theaterq_sched_data *q = filp->private_data;
    
    char kbuf[THEATERQ_INGEST_MAXLEN];
    size_t actual_read = 0;
    ssize_t ret = 0;
    struct theaterq_entry *entry;

    if (len == 0) {
        printk(KERN_WARNING
               "sch_theaterq: Unable to parse line: Zero bytes read!\n");
        return -EINVAL;
    }
    
    // Read as long as bytes are available in the userspace buffer
    while (len > 0) {

        // Try to copy a part of the data to a kernel buffer
        size_t to_copy = min(len, sizeof(kbuf));
        if (copy_from_user(kbuf, buffer, to_copy)) {
            printk(KERN_ERR "sch_theaterq: chardev: Unable to copy_from_user!\n");
            return -EFAULT;
        }

        for (int i = 0; i < to_copy; i++) {
            char c = kbuf[i];

            // Reading character by character, until hitting the first \n
            // If the buffer is full and no full entry could be found, the
            // line must be invalid
            if (q->ingest_helper.lpos >= THEATERQ_INGEST_MAXLEN - 1) {
                q->ingest_helper.lpos = 0;
                printk(KERN_WARNING 
                       "sch_theaterq: Unable to parse too long line at entry %llu!\n", 
                        q->e_entries + 1);
                return -EINVAL;
            }

            // Copy the full entry line to the parser buffer
            q->ingest_helper.lbuf[q->ingest_helper.lpos++] = c;

            if (c == '\n') {
                if (q->ingest_helper.lpos == 1) continue;

                // Valid lines must be start with a digit, ignore otherwise
                // (Could be comments or CSV headers)
                if (!isdigit(q->ingest_helper.lbuf[0])) {
                    q->ingest_helper.lpos = 0;
                    continue;
                }

                // Replace the \n before parsing to mark end of string
                q->ingest_helper.lbuf[q->ingest_helper.lpos - 1] = '\0';

                struct theaterq_entry *entry = kmem_cache_alloc(theaterq_cache, GFP_KERNEL);
                if (!entry) {
                    printk(KERN_ERR 
                           "sch_theaterq: Unable to alloc memory for entry\n");
                    return -ENOMEM;
                }

                /* Simple input format:
                 * KEEP,LATENCY,RATE,LOSS,LIMIT\n
                 *  µs     ns    bps    a)    b)
                 * 
                 * Extended input format:
                 * KEEP,LATENCY,JITTER,RATE,LOSS,LIMIT,DUP_PROP,DUP_DELAY,ROUTE_ID\n
                 *  µs     ns      ns   bps   a)    b)     a)       ns      b)
                 * 
                 * a) Scaled u32: 0 = 0%, U32_MAX = 100%, kernel does not 
                 *  support floating point numbers
                 * b) Just a number
                 */

                char *token;
                char *p = q->ingest_helper.lbuf;
                int i = 0;

#define PARSE_TOKEN(fun, dest) do { \
                    token = strsep(&p, ","); \
                    if (!token || fun(token, 10, dest)) { \
                        printk(KERN_WARNING \
                              "sch_theaterq: Parsing error at pos %u in entry %llu\n", \
                              i, q->e_entries + 1); \
                        q->ingest_helper.lpos = 0; \
                        ret = -EINVAL; \
                        goto cleanup_failed_entry; \
                    } \
                    i++; \
                } while (0)

#define PARSE_TOKEN_EXTENDED(fun, dest, default) do { \
                    if (q->ingest_mode == THEATERQ_INGEST_MODE_EXTENDED) \
                        PARSE_TOKEN(fun, dest); \
                    else \
                        *dest = default; \
                } while (0)
                
                // Parse all entries delimited by ',', some are only
                // required for the EXTENDED format
                PARSE_TOKEN(kstrtou64, &entry->keep);
                PARSE_TOKEN(kstrtou64, &entry->latency);
                PARSE_TOKEN_EXTENDED(kstrtou64, &entry->jitter, 0);
                PARSE_TOKEN(kstrtou64, &entry->rate);
                PARSE_TOKEN(kstrtou32, &entry->loss);
                PARSE_TOKEN(kstrtou32, &entry->limit);
                PARSE_TOKEN_EXTENDED(kstrtou32, &entry->dup_prob, 0);
                PARSE_TOKEN_EXTENDED(kstrtou64, &entry->dup_delay, 0);
                PARSE_TOKEN_EXTENDED(kstrtou32, &entry->route_id, 
                                     THEATERQ_ALLOW_IMPLICIT_REORDER);

#undef PARSE_TOKEN_EXTENDED
#undef PARSE_TOKEN
                
                // When parsing has not reached the end of the buffer:
                // More data is in the line, thus entry is invalid.
                if (p && *p != '\0') {
                    printk(KERN_WARNING 
                           "sch_theaterq: Unable to parse line: Unexpected "
                           "input at entry %llu!\n",
                           q->e_entries + 1);
                    ret = -EINVAL;
                    goto cleanup_failed_entry;
                }

                q->ingest_helper.lpos = 0;

                if (entry->keep == 0) {
                    printk(KERN_WARNING 
                           "sch_theaterq: Zero keep values are not allowed!\n");
                    ret = -EINVAL;
                    goto cleanup_failed_entry;
                }

                if (entry->keep >= THEATERQ_NO_EXPIRY / THEATERQ_NS_PER_US) {
                    printk(KERN_WARNING 
                           "sch_theaterq: Keep value too large, max is %lld!\n",
                            (THEATERQ_NO_EXPIRY / THEATERQ_NS_PER_US) - 1);
                    ret = -EINVAL;
                    goto cleanup_failed_entry;
                }

                if (entry->route_id > reorder_routes) {
                    printk(KERN_WARNING 
                           "sch_theaterq: Reorder route index is too large, max is %d!\n",
                            reorder_routes);
                    ret = -EINVAL;
                    goto cleanup_failed_entry;
                }

                entry->keep = entry->keep * THEATERQ_NS_PER_US; // µs -> ns 
                entry->rate = div64_u64(entry->rate, 8); // bits per second -> byte per second
                entry->next = NULL;

                // Access to the linked list only under lock, to prevent
                // concurrent access with a possible list clear
                spin_lock_bh(&q->e_lock);

                if (q->stage != THEATERQ_STAGE_LOAD || q->deletion_pending) {
                    printk(KERN_WARNING 
                           "sch_theaterq: Qdisc not in load stage, or deletion pending.\n");
                    ret = -EBUSY;
                    goto cleanup_failed_unlock;
                }

                if (q->e_head == NULL) {
                    q->e_head = entry;
                    q->e_tail = entry;
                } else {
                    q->e_tail->next = entry;
                    q->e_tail = entry;
                }

                q->e_entries++;
                q->e_totaltime += entry->keep;
                entry = NULL;

                spin_unlock_bh(&q->e_lock);
            }
        }

        buffer += to_copy;
        len -= to_copy;
        actual_read += to_copy;
    }
    
    return actual_read;

cleanup_failed_unlock:
    spin_unlock_bh(&q->e_lock);
cleanup_failed_entry:
    if (entry != NULL)
        kmem_cache_free(theaterq_cache, entry);
    return ret;
}

static struct file_operations theaterq_cdev_fops = {
    .write   = ingest_cdev_write,
    .read    = ingest_cdev_read,
    .open    = ingest_cdev_open,
    .release = ingest_cdev_release,
};

static int create_ingest_cdev(struct Qdisc *sch)
{
    int ret;
    struct theaterq_sched_data *q = qdisc_priv(sch);

    // Trace File ingest dev name: /dev/theaterq:<IF_NAME>:<MAJOR>:<MINOR>
    ret = snprintf(q->ingest_cdev.name, sizeof(q->ingest_cdev.name), 
            "theaterq:%s:%x:%x", 
            qdisc_dev(sch)->name, 
            TC_H_MAJ(sch->handle) >> 16, 
            TC_H_MIN(sch->handle));

    if (ret < 0) 
        return -ENOBUFS;

    ret = alloc_chrdev_region(&q->ingest_cdev.dev, 0, 1, q->ingest_cdev.name);
    if (ret < 0)
        return ret;

    cdev_init(&q->ingest_cdev.cdev, &theaterq_cdev_fops);
    q->ingest_cdev.cdev.owner = THIS_MODULE;

    ret = cdev_add(&q->ingest_cdev.cdev, q->ingest_cdev.dev, 1);
    if (ret < 0)
        goto err_unregister;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    q->ingest_cdev.cls = class_create(q->ingest_cdev.name);
#else
    q->ingest_cdev.cls = class_create(THIS_MODULE, q->ingest_cdev.name);
#endif

    if (IS_ERR(q->ingest_cdev.cls)) {
        ret = PTR_ERR(q->ingest_cdev.cls);
        goto err_cdev_delete;
    }

    q->ingest_cdev.device = device_create(q->ingest_cdev.cls, NULL, 
                                          q->ingest_cdev.dev, NULL, 
                                          q->ingest_cdev.name);

    if (IS_ERR(q->ingest_cdev.device)) {
        ret = PTR_ERR(q->ingest_cdev.device);
        goto err_cls_delete;
    }

    atomic_set(&q->ingest_cdev.opened, THEATERQ_CDEV_AVAILABLE);
    q->ingest_cdev.en = true;
    return 0;

err_cls_delete:
    class_destroy(q->ingest_cdev.cls);
err_cdev_delete:
    cdev_del(&q->ingest_cdev.cdev);
err_unregister:
    unregister_chrdev_region(q->ingest_cdev.dev, 1);
    return ret;
}

static int destroy_ingest_cdev(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    if (!q->ingest_cdev.en)
        return 0;

    device_destroy(q->ingest_cdev.cls, q->ingest_cdev.dev);
    class_destroy(q->ingest_cdev.cls);
    cdev_del(&q->ingest_cdev.cdev);
    unregister_chrdev_region(q->ingest_cdev.dev, 1);
    q->ingest_cdev.en = false;
    return 0;
}

// QDISC OPS ===================================================================

static struct theaterq_entry *theaterq_get_entry(struct theaterq_sched_data *q, 
                                                 s64 now)
{
    struct theaterq_entry *current_entry = READ_ONCE(q->current_entry);

    if (unlikely(!current_entry)) {
        WRITE_ONCE(q->current_entry, 
                   (struct theaterq_entry *) &theaterq_default_entry);
        return q->current_entry;
    }

    // Check if the current_entry is still valid or if the pointer needs
    // to be moved to a future entry
    if (likely(q->t_updated + current_entry->keep > now ||
               current_entry->keep == THEATERQ_NO_EXPIRY))
            return current_entry;

#define UPDATE_PRIV_LOCAL(new) do { \
                            WRITE_ONCE(q->current_entry, new); \
                            current_entry = new; \
                        } while (0)

    // Shortcut for loop cont mode: When the list walk would run over
    // the start of the list (multiple times), we just set our pointer 
    // to the beginning of the list before entering the list walk,
    // thus shortcutting whole list walks during low packet load and/or
    // high update rates
    u64 time_since_update = now - q->t_updated;
    if (q->cont_mode == THEATERQ_CONT_LOOP && 
        time_since_update >= (q->e_totaltime - q->e_progresstime)) {

        u64 full_loops = time_since_update / q->e_totaltime;
        u64 remainder = time_since_update % q->e_totaltime;
        
        // Shortcut all full loops over the list
        if (full_loops >= 1) {
            u64 loop_time = full_loops * q->e_totaltime;
            q->stats.looped += full_loops;
            q->stats.total_entries += full_loops * q->e_entries;
            q->stats.total_time += loop_time;
            q->t_updated += loop_time;
        }

        // Shortcut the last loop back the the start of the list
        if (remainder >= (q->e_totaltime - q->e_progresstime)) {
            u64 time_to_start = q->e_totaltime - q->e_progresstime;
            q->stats.looped++;
            q->stats.total_entries += q->e_entries - q->e_current;
            q->stats.total_time += time_to_start;
            q->t_updated += time_to_start;
        }

        q->e_current = 0;
        q->e_progresstime = 0;
        UPDATE_PRIV_LOCAL(q->e_head);
    }

    // Perform a list walk until the entry is selected that should
    // be active during this moment. Long listwalks here a critical,
    // since the functions is called under the fastpath lock, so no
    // other enqueue can be called concurrently for this instance
    while (now - q->t_updated >= current_entry->keep) {
        q->t_updated += current_entry->keep;
        q->e_progresstime += current_entry->keep;

        if (!current_entry->next) {
            // No more list entries are available. cont_mode will 
            // define how to continue.
            switch (q->cont_mode) {
                case THEATERQ_CONT_LOOP:
                    q->stats.total_time += current_entry->keep;
                    q->stats.total_entries++;
                    q->e_progresstime = 0;
                    q->e_current = 0;
                    q->stats.looped++;
                    UPDATE_PRIV_LOCAL(q->e_head);
                    break;
                case THEATERQ_CONT_CLEAN:
                    // THEATERQ_NO_EXPIRY: Static entry that will not
                    // change anymore, prevent future list walks with
                    // possible u64 overflows
                    theaterq_stop_replay(q, true);
                    q->e_progresstime = 0;
                    q->t_busy_time = 0;
                    q->stage = THEATERQ_STAGE_FINISH;
                    UPDATE_PRIV_LOCAL((struct theaterq_entry *) &theaterq_default_entry);
                    return current_entry;
                case THEATERQ_CONT_HOLD:
                    /* fall through */
                default:
                    q->stage = THEATERQ_STAGE_FINISH;
                    theaterq_stop_replay(q, false);
                    return current_entry;
            }
        } else {
            // Default case: Just select the next entry in list
            q->stats.total_time += current_entry->keep;
            q->stats.total_entries++;
            q->e_current++;
            UPDATE_PRIV_LOCAL(current_entry->next);
        }
    }

#undef UPDATE_PRIV_LOCAL

    return current_entry;
}

// Enqueue a segment: Packet. Main EDFQ insertion function.
static int theaterq_enqueue_seg(struct sk_buff *skb, struct Qdisc *sch,
                                struct sk_buff **to_free)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct theaterq_skb_cb *cb;
    struct sk_buff *dup_skb;

    // Packet arrived in ARM state = Try to start this instance or whole 
    // syncgroup, when available
    if (READ_ONCE(q->stage) == THEATERQ_STAGE_ARM) {
        (void) theaterq_syncgroup_startall(q);
    }

    s64 now = ktime_get_ns();
    struct theaterq_entry *current_entry = theaterq_get_entry(q, now);
    s64 delay = 0;
    u64 check_len;
    bool orphaned = false;

    // At this point: current_entry is the entry that should be active at
    // this point in time

    delay = get_pkt_delay(current_entry->latency, 
                          current_entry->jitter,
                          &q->prng);
    skb->prev = NULL;

    if (loss_event(q)) {
        // Drop the packet, but do not tell the network stack about it,
        // since instance feedback could falsify reaction of, e.g., TCP
        qdisc_qstats_drop(sch);
        __qdisc_drop(skb, to_free);
        return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
    }

    if (current_entry->rate || current_entry->latency || current_entry->jitter) {
            // Prevent feedback of delayed skbs to upper layer of the
            // network stack
            skb_orphan_partial(skb);
            orphaned = true;
    }

    bool delay_has_dup = false;
    if (!q->isdup && dup_event(q) && 
        (dup_skb = skb_clone(skb, GFP_ATOMIC)) != NULL) {
            struct Qdisc *rootq = qdisc_root_bh(sch);

            // Don't duplicate a packet again
            q->isdup = true;
            rootq->enqueue(dup_skb, rootq, to_free);
            q->isdup = false;

            delay += current_entry->dup_delay;
            delay_has_dup = true;
            if (!orphaned && current_entry->dup_delay)
                skb_orphan_partial(skb);
    }

    check_len = q->use_byte_queue ? // TODO
                    q->edfq_blen + qdisc_pkt_len(skb) : q->edfq_len;

    if (unlikely(current_entry->limit && check_len >= current_entry->limit)) {
        if (q->enable_ecn)
            INET_ECN_set_ce(skb);

        qdisc_drop_all(skb, sch, to_free);
        return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
    }

    qdisc_qstats_backlog_inc(sch, skb);
    cb = theaterq_skb_cb(skb);

    // Fill the codeblock with current valid data, when route handling
    // is enabled: prevent implicit packet reordering by keeping track of
    // the current route id and its last earliest send timestamp
    cb->earliest_send_time = now + delay;

    if (likely(!delay_has_dup)) {
        if (cb->earliest_send_time <= q->r_last_send_times[current_entry->route_id])
            cb->earliest_send_time = q->r_last_send_times[current_entry->route_id] + 1;

        if (current_entry->route_id != THEATERQ_ALLOW_IMPLICIT_REORDER)
            q->r_last_send_times[current_entry->route_id] = cb->earliest_send_time;
    }

    cb->transmit_time = packet_time_ns(qdisc_pkt_len(skb), q);
    edfq_enqueue(skb, sch);

    // The dequeue will be aware of some delayed skbs in the EDFQ, but
    // the enqueued packet could "overtake" already enqueued skbs:
    // Check, if the dequeue must be called earlier by setting the hrtimer
    struct sk_buff *first = theaterq_peek_edfq(q);
    u64 first_send_time;
    if (!first) {
        if (q->t_busy_time < cb->earliest_send_time)
            qdisc_watchdog_schedule_ns(&q->watchdog, cb->earliest_send_time);
    } else {
        first_send_time = theaterq_skb_cb(first)->earliest_send_time;
        if (first_send_time > cb->earliest_send_time && 
            q->t_busy_time < cb->earliest_send_time)
                qdisc_watchdog_schedule_ns(&q->watchdog, cb->earliest_send_time);
    }

    return NET_XMIT_SUCCESS;
}

static int theaterq_enqueue_gso(struct sk_buff *skb, struct Qdisc *sch,
                                struct sk_buff **to_free)
{
    struct sk_buff *nskb;
    u32 nb = 0, dropped = 0;
    int ret = NET_XMIT_SUCCESS;
    int flag = 0;

    // Segment a GSO packet to segments = Layer 2 Ethernet packets
    // Heavily inspired from sch_tbf's segmentation implementation
    netdev_features_t features = netif_skb_features(skb);
    struct sk_buff *segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

    if (IS_ERR_OR_NULL(segs))
        return qdisc_drop(skb, sch, to_free);
    
    skb_list_walk_safe(segs, segs, nskb) {
        skb_mark_not_on_list(segs);
        qdisc_skb_cb(segs)->pkt_len = segs->len;

        ret = theaterq_enqueue_seg(segs, sch, to_free); 
        if ((ret & ~__NET_XMIT_BYPASS) == NET_XMIT_SUCCESS) {
            if ((ret & __NET_XMIT_BYPASS) != 0) {
                flag = __NET_XMIT_BYPASS;
            }
            nb++;
        } else {
            dropped++;
        }
    }

    if (nb > 0) {
        consume_skb(skb);
        return dropped == 0 ? NET_XMIT_SUCCESS | flag : NET_XMIT_DROP;
    }

    kfree_skb(skb);
    return NET_XMIT_DROP;
}

// Will be called by the tc systems and determined if a GSO segmentation
// is needed.
static int theaterq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                            struct sk_buff **to_free)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    if (skb_is_gso(skb) && !q->allow_gso)
        return theaterq_enqueue_gso(skb, sch, to_free);
    else
        return theaterq_enqueue_seg(skb, sch, to_free);
}

static struct sk_buff *theaterq_peek_edfq(struct theaterq_sched_data *q)
{
    struct sk_buff *skb = skb_rb_first(&q->edfq_root);
    u64 t1, t2;

    if (!skb) return q->edfq_head;
    if (!q->edfq_head) return skb;

    t1 = theaterq_skb_cb(skb)->earliest_send_time;
    t2 = theaterq_skb_cb(q->edfq_head)->earliest_send_time;

    if (t1 < t2)
        return skb;
    else
        return q->edfq_head;
}

static inline struct sk_buff *theaterq_peek_fifo(struct theaterq_sched_data *q)
{
    return q->edfq_head;
}

static void theaterq_erase_head_edfq(struct theaterq_sched_data *q, 
                                struct sk_buff *skb)
{
    if (skb == q->edfq_head) {
        q->edfq_head = skb->next;
        if (!q->edfq_head) q->edfq_tail = NULL;
    } else {
        rb_erase(&skb->rbnode, &q->edfq_root);
    }
}

static inline void theaterq_erase_head_fifo(struct theaterq_sched_data *q,
                                struct sk_buff *skb)
{
    if (skb != q->fifo_head) 
        return;

    q->fifo_head = skb->next;
    if (!q->fifo_head) q->fifo_tail = NULL;
}

static struct sk_buff *theaterq_dequeue(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct sk_buff *skb;
    u64 now = ktime_get_ns();
    
edfq_dequeue:
    // Fastpath qdisc skbs will be dequeued always
    skb = __qdisc_dequeue_head(&sch->q);
    if (skb) {
deliver:
        qdisc_qstats_backlog_dec(sch, skb);
        qdisc_bstats_update(sch, skb);
        return skb;
    }

    skb = theaterq_peek_edfq(q);
    if (skb) {
        // Each enqueued skb has an earliest_send_time and a transmit_time values.
        // For bandwidth limitations, the link is "busy" (t_busy_time) for the
        // transmit_time after a skb was sent.
        // The next skb dequeued is always the skb with the lowest 
        // earliest_send_time, but it can only be sent when:
        // - earliest_send_time >= now and
        // - earliest_send_time >= t_busy_time
        // Otherwise: Delay the dequeue by setting the hrtimer

        u64 earliest_send_time = theaterq_skb_cb(skb)->earliest_send_time;

        if (now < q->t_busy_time) {
            u64 next_send = max_t(u64, q->t_busy_time, earliest_send_time);
            qdisc_watchdog_schedule_ns(&q->watchdog, next_send);
        } else {
            unsigned int pkt_len = qdisc_pkt_len(skb);

            if (earliest_send_time <= now) {
                theaterq_erase_head_edfq(q, skb);
                q->edfq_len--;
                q->edfq_blen -= pkt_len;
                skb->next = NULL;
                skb->prev = NULL;
                skb->dev = qdisc_dev(sch);
                q->t_busy_time = now + theaterq_skb_cb(skb)->transmit_time;

                // When a child qdisc is available: Enqueue there, don't send.
                // skbs are enqueued to the child qdisc AFTER delay, queue
                // limits and bandwidth limitations are applied, thus this will
                // not be useful for AQM. skbs can be dropped during theaterq's
                // enqueue function, not arriving here at all.
                if (q->qdisc) {
                    struct sk_buff *to_free = NULL;
                    int err;

                    err = qdisc_enqueue(skb, q->qdisc, &to_free);
                    kfree_skb_list(to_free);

                    if (err != NET_XMIT_SUCCESS) {
                        if (net_xmit_drop_count(err)) qdisc_qstats_drop(sch);
                        sch->qstats.backlog -= pkt_len;
                        sch->q.qlen--;
                        qdisc_tree_reduce_backlog(sch, 1, pkt_len);
                    }

                    goto edfq_dequeue;
                }

                sch->q.qlen--;
                goto deliver;
            }

            qdisc_watchdog_schedule_ns(&q->watchdog, earliest_send_time);
        }

        // Always send skbs dequeued from the child qdisc
        if (q->qdisc) {
            skb = q->qdisc->ops->dequeue(q->qdisc);
            if (skb) {
                sch->q.qlen--;
                goto deliver;
            }
        }
    }

    // Always send skbs dequeued from the child qdisc
    if (q->qdisc) {
        skb = q->qdisc->ops->dequeue(q->qdisc);
        if (skb) {
            sch->q.qlen--;
            goto deliver;
        }
    }

    return NULL;
}

static const struct nla_policy theaterq_policy[TCA_THEATERQ_MAX + 1] = {
    [TCA_THEATERQ_STAGE]        = { .type = NLA_U32 },
    [TCA_THEATERQ_PRNG_SEED]    = { .type = NLA_U64 },
    [TCA_THEATERQ_PKT_OVERHEAD] = { .type = NLA_S32 },
    [TCA_THEATERQ_CONT_MODE]    = { .type = NLA_U32 },
    [TCA_THEATERQ_INGEST_MODE]  = { .type = NLA_U32 },
    [TCA_THEATERQ_SYNCGRP]      = { .type = NLA_S32 },
    [TCA_THEATERQ_USE_BYTEQ]    = { .type = NLA_U8  },
    [TCA_THEATERQ_ALLOW_GSO]    = { .type = NLA_U8  },
    [TCA_THEATERQ_ENABLE_ECN]   = { .type = NLA_U8  },
};

static int theaterq_change(struct Qdisc *sch, struct nlattr *opt,
                           struct netlink_ext_ack *extack)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct nlattr *tb[TCA_THEATERQ_MAX + 1];
    int start_replay = THEATERQ_REPLAY_UNCHANGED;
    int ret;
    u32 new_stage = THEATERQ_STAGE_UNSPEC;
    s32 new_syncgrp = THEATERQ_NO_SYNCGRP_SELECTED;

    ret = nla_parse_nested(tb, TCA_THEATERQ_MAX, opt, 
                    theaterq_policy, extack);
    if (ret < 0) {
        return ret;
    }

    sch_tree_lock(sch);
    if (tb[TCA_THEATERQ_STAGE]) {
        new_stage = nla_get_u32(tb[TCA_THEATERQ_STAGE]);

        if (new_stage == THEATERQ_STAGE_FINISH)
            new_stage = THEATERQ_STAGE_LOAD;

        if (new_stage == THEATERQ_STAGE_CLEAR) {
            q->t_busy_time = 0;
            new_stage = THEATERQ_STAGE_LOAD;
            q->deletion_pending = true;
            start_replay = THEATERQ_REPLAY_STOP | THEATERQ_REPLAY_CLEAR;
        } else if (new_stage == THEATERQ_STAGE_LOAD && 
                   q->stage != new_stage) {
            start_replay = THEATERQ_REPLAY_STOP;
        } else if (new_stage == THEATERQ_STAGE_ARM) {
            q->stage = new_stage;
        } else if (new_stage == THEATERQ_STAGE_RUN) {
            if (!q->e_entries) {
                ret = -ENODATA;
                printk(KERN_WARNING 
                       "theaterq: Unable to run without entries!\n");
                goto err_out;
            }

            start_replay = THEATERQ_REPLAY_START;
        }
    }

    if (tb[TCA_THEATERQ_CONT_MODE])
        q->cont_mode = nla_get_u32(tb[TCA_THEATERQ_CONT_MODE]);

    if (tb[TCA_THEATERQ_INGEST_MODE])
        q->ingest_mode = nla_get_u32(tb[TCA_THEATERQ_INGEST_MODE]);

    if (tb[TCA_THEATERQ_PKT_OVERHEAD])
        q->packet_overhead = nla_get_s32(tb[TCA_THEATERQ_PKT_OVERHEAD]);

    if (tb[TCA_THEATERQ_SYNCGRP])
        new_syncgrp =  nla_get_s32(tb[TCA_THEATERQ_SYNCGRP]);

    if (tb[TCA_THEATERQ_PRNG_SEED]) {
        q->prng.seed = nla_get_u64(tb[TCA_THEATERQ_PRNG_SEED]);
        q->prng.seed_set = true;
    } else {
        q->prng.seed = get_random_u64();
        q->prng.seed_set = false;
    }
    prandom_seed_state(&q->prng.prng_state, q->prng.seed);

    if (tb[TCA_THEATERQ_USE_BYTEQ])
        q->use_byte_queue = nla_get_u8(tb[TCA_THEATERQ_USE_BYTEQ]) != 0;

    if (tb[TCA_THEATERQ_ALLOW_GSO])
        q->allow_gso = nla_get_u8(tb[TCA_THEATERQ_ALLOW_GSO]) != 0;

    if (tb[TCA_THEATERQ_APPLY_BEFORE_Q])
        q->apply_before_q = nla_get_u8(tb[TCA_THEATERQ_APPLY_BEFORE_Q]) != 0;

    if (tb[TCA_THEATERQ_ENABLE_ECN])
        q->enable_ecn = nla_get_u8(tb[TCA_THEATERQ_ENABLE_ECN]) != 0;

    sch_tree_unlock(sch);

    if (new_syncgrp != THEATERQ_NO_SYNCGRP_SELECTED 
        && !theaterq_syncgroup_change(q, new_syncgrp))
            return -EBADE;
    
    // Important: Do not try to lock the global lock while also holding
    // the sch_tree_lock, a deadlock could occur.
    if (new_stage) {
        if (start_replay & THEATERQ_REPLAY_START) {
            theaterq_syncgroup_startall(q);
        } else if (start_replay & THEATERQ_REPLAY_STOP) {
            theaterq_syncgroup_stopall(q, new_stage);
        }

        // Delete the list under the sch_tree_lock again. The function
        // will also acquire the list lock of this instance
        if (start_replay & THEATERQ_REPLAY_CLEAR) {
            sch_tree_lock(sch);
            entry_list_clear(q);
            sch_tree_unlock(sch);

        }
    }

    return ret;

err_out:
    sch_tree_unlock(sch);
    return ret;
}

static int theaterq_init(struct Qdisc *sch, struct nlattr *opt,
                         struct netlink_ext_ack *extack)
{
    int ret;
    struct theaterq_sched_data *q = qdisc_priv(sch);

    q->r_last_send_times = kmalloc((reorder_routes + 1) * sizeof(u64), 
                                   GFP_KERNEL);

    if (!q->r_last_send_times) {
        printk(KERN_ERR "theaterq: Unable to allocate memory for reorder route cache.\n");
        return -ENOMEM;
    }

    // We will manage our queue sizes ourselves
    sch->limit = __UINT32_MAX__;

    // Set up the initial state
    q->stage = THEATERQ_STAGE_LOAD;
    q->cont_mode = THEATERQ_CONT_HOLD;
    q->ingest_mode = THEATERQ_INGEST_MODE_SIMPLE;
    q->allow_gso = false;
    q->apply_before_q = true;
    q->syncgrp = NULL;
    q->isdup = false;
    q->t_busy_time = 0ULL;
    q->t_updated = THEATERQ_NO_EXPIRY;
    q->deletion_pending = false;

    spin_lock_init(&q->e_lock);
    qdisc_watchdog_init(&q->watchdog, sch);

    if (!opt) return -EINVAL;

    q->ingest_cdev.en = false;
    ret = create_ingest_cdev(sch);
    if (ret < 0) return ret;

    entry_list_clear(q);

    ret = theaterq_change(sch, opt, extack);
    if (ret)
        destroy_ingest_cdev(sch);

    return ret;
}

static void theaterq_reset(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    qdisc_reset_queue(sch);
    edfq_reset(sch);
    // Leave the syncgroup but do not stop the other members
    theaterq_syncgroup_leave(q);
    theaterq_stop_replay(q, true);
    q->stage = THEATERQ_STAGE_LOAD;
    theaterq_stats_clear(&q->stats);
    q->t_busy_time = 0;
    if (q->qdisc) qdisc_reset(q->qdisc);
    qdisc_watchdog_cancel(&q->watchdog);
}

static void theaterq_destroy(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    qdisc_watchdog_cancel(&q->watchdog);
    theaterq_syncgroup_leave(q);
    kfree(q->r_last_send_times);
    destroy_ingest_cdev(sch);
    // enqueue will not be called again here
    entry_list_clear(q);
    if (q->qdisc) qdisc_put(q->qdisc);
}

static int theaterq_dump_qdisc(struct Qdisc *sch, struct sk_buff *skb)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    // Update the current entry when required. When no packets arrive, the
    // currently active entry would not be updates, so dump would show an
    // outdated entry.
    // This could alter the qdisc's data structure alongside the enqueue
    // function, so exclusive access is required.
    sch_tree_lock(sch);
    struct theaterq_entry *current_entry = theaterq_get_entry(q, ktime_get_ns());
    sch_tree_unlock(sch);

    struct nlattr *opts = nla_nest_start(skb, TCA_OPTIONS);
    struct theaterq_entry current_entry_nla;

    if (!opts)
        return -EMSGSIZE;

    if (nla_put_u32(skb, TCA_THEATERQ_STAGE, q->stage))
        goto nla_put_failure;

    if (q->prng.seed_set && nla_put_u64_64bit(skb, TCA_THEATERQ_PRNG_SEED, 
                                              q->prng.seed, TCA_THEATERQ_PAD))
        goto nla_put_failure;

    if (nla_put_s32(skb, TCA_THEATERQ_PKT_OVERHEAD, q->packet_overhead))
        goto nla_put_failure;
    
    s32 syncgroup = q->syncgrp == NULL ? THEATERQ_SYNCGROUP_LEAVE : q->syncgrp->index;
    if (nla_put_s32(skb, TCA_THEATERQ_SYNCGRP, syncgroup))
        goto nla_put_failure;
    
    if (nla_put_u32(skb, TCA_THEATERQ_CONT_MODE, q->cont_mode))
        goto nla_put_failure;

    if (nla_put_u32(skb, TCA_THEATERQ_INGEST_MODE, q->ingest_mode))
        goto nla_put_failure;
    
    if (nla_put(skb, TCA_THEATERQ_INGEST_CDEV, 
                sizeof(q->ingest_cdev.name), q->ingest_cdev.name))
        goto nla_put_failure;
    
    if (nla_put_u64_64bit(skb, TCA_THEATERQ_ENTRY_LEN, 
                          q->e_entries, TCA_THEATERQ_PAD))
        goto nla_put_failure;

    if (nla_put_u64_64bit(skb, TCA_THEATERQ_TIME_LEN,
                          q->e_totaltime, TCA_THEATERQ_PAD))
        goto nla_put_failure;
    
    if (nla_put_u64_64bit(skb, TCA_THEATERQ_ENTRY_POS, 
                          q->e_current, TCA_THEATERQ_PAD))
        goto nla_put_failure;
    
    if (nla_put_u64_64bit(skb, TCA_THEATERQ_TIME_PROGRESS,
                          q->e_progresstime, TCA_THEATERQ_PAD))
        goto nla_put_failure;

    if (current_entry) {
        memcpy(&current_entry_nla, current_entry, sizeof(current_entry_nla));
        current_entry_nla.next = NULL;

        if (nla_put(skb, TCA_THEATERQ_ENTRY_CURRENT, 
                    sizeof(current_entry_nla), &current_entry_nla))
            goto nla_put_failure;
    }

    if (q->use_byte_queue && nla_put_u8(skb, TCA_THEATERQ_USE_BYTEQ,
                                        q->use_byte_queue))
        goto nla_put_failure;

    if (q->allow_gso && nla_put_u8(skb, TCA_THEATERQ_ALLOW_GSO,
                                   q->allow_gso))
        goto nla_put_failure;

    if (q->apply_before_q && nla_put_u8(skb, TCA_THEATERQ_APPLY_BEFORE_Q,
                                        q->apply_before_q))
        goto nla_put_failure;

    if (q->enable_ecn && nla_put_u8(skb, TCA_THEATERQ_ENABLE_ECN,
                                    q->enable_ecn))
        goto nla_put_failure;

    return nla_nest_end(skb, opts);

nla_put_failure:
    nla_nest_cancel(skb, opts);
    return -EMSGSIZE;
}

static int theaterq_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    struct tc_theaterq_xstats stats = {};
    memcpy(&stats, &q->stats, sizeof(stats));

    stats.edfq_plen = q->edfq_len;
    stats.edfq_blen = q->edfq_blen;
    stats.fifo_plen = q->fifo_len;
    stats.fifo_blen = q->fifo_blen;

    return gnet_stats_copy_app(d, &stats, sizeof(stats));
}

// CLASS OPS ===================================================================

static int theaterq_graft(struct Qdisc *sch, unsigned long arg, 
                          struct Qdisc *new, struct Qdisc **old,
                          struct netlink_ext_ack *extack)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    *old = qdisc_replace(sch, new, &q->qdisc);
    return 0;
}

static struct Qdisc *theaterq_leaf(struct Qdisc *sch, unsigned long arg)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    return q->qdisc;
}

static unsigned long theaterq_find(struct Qdisc *sch, u32 classid)
{
    return 1;
}

static void theaterq_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
    if (!walker->stop) {
        if (!tc_qdisc_stats_dump(sch, 1, walker)) return;
    }
}

static int theaterq_dump_class(struct Qdisc *sch, unsigned long cl,
                               struct sk_buff *skb, struct tcmsg *tcm)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    if (cl != 1 || !q->qdisc) {
        return -ENOENT;
    }

    tcm->tcm_handle |= TC_H_MIN(1);
    tcm->tcm_info = q->qdisc->handle;

    return 0;
}

// MODULE BOOTSTRAP ============================================================

static const struct Qdisc_class_ops theaterq_class_ops = {
    .graft = theaterq_graft,
    .leaf  = theaterq_leaf,
    .find  = theaterq_find,
    .walk  = theaterq_walk,
    .dump  = theaterq_dump_class,
};

static struct Qdisc_ops theaterq_qdisc_ops __read_mostly = {
    .id         = "theaterq",
    .cl_ops     = &theaterq_class_ops,
    .priv_size  = sizeof(struct theaterq_sched_data),
    .enqueue    = theaterq_enqueue,
    .dequeue    = theaterq_dequeue,
    .peek       = qdisc_peek_dequeued,
    .init       = theaterq_init,
    .reset      = theaterq_reset,
    .destroy    = theaterq_destroy,
    .change     = theaterq_change,
    .dump       = theaterq_dump_qdisc,
    .dump_stats = theaterq_dump_stats,
    .owner      = THIS_MODULE,
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martin Ottens <martin.ottens@fau.de>");
MODULE_DESCRIPTION("Trace File based Link Emulator");
MODULE_VERSION("1.0");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
MODULE_ALIAS_NET_SCH("theaterq");
#endif

module_param(syncgrps, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(syncgrps, 
                 "Maximum synchronization groups (u8, default=8)");

module_param(syncgrps_members, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(syncgrps_members, 
                 "Maximum members per synchronization group (u8, default=8)");

module_param(reorder_routes, short, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(reorder_routes, 
                 "Number of different reorder routes to keep track of (u16, default=255)");

static int __init sch_theaterq_init(void)
{
    theaterq_cache = kmem_cache_create("theaterq_cache",
                                       sizeof(struct theaterq_entry),
                                       0, SLAB_HWCACHE_ALIGN, NULL);
    
    if (!theaterq_cache) {
        printk(KERN_ERR "theaterq: Unable to create slab allocator\n");
        return -ENOMEM;
    }

    theaterq_syncgrps = kmalloc_array(((u32) syncgrps), 
                                     sizeof(struct theaterq_syncgrp), 
                                     GFP_KERNEL);

    if (!theaterq_syncgrps) {
        printk(KERN_ERR "theaterq: Unable kmalloc for syncgroups\n");
        kmem_cache_destroy(theaterq_cache);
        theaterq_cache = NULL;
        return -ENOMEM;
    }
    s32 i;
    for (i = 0; i < syncgrps; i++) {
        theaterq_syncgrps[i].index = i;
        theaterq_syncgrps[i].members = kcalloc(syncgrps_members, 
                                             sizeof(struct theaterq_sched_data *), 
                                             GFP_KERNEL);
        if (theaterq_syncgrps[i].members == NULL) {
            goto init_failed;
        }
    }

    return register_qdisc(&theaterq_qdisc_ops);

init_failed:
    while (--i >= 0) {
        kfree(theaterq_syncgrps[i].members);
    }

    kfree(theaterq_syncgrps);
    theaterq_syncgrps = NULL;
    kmem_cache_destroy(theaterq_cache);
    theaterq_cache = NULL;
    return -ENOMEM;
}

static void __exit sch_theaterq_exit(void)
{
    if (theaterq_cache) {
        kmem_cache_destroy(theaterq_cache);
        theaterq_cache = NULL;
    }

    if (theaterq_syncgrps) {
        for (s32 i = 0; i < syncgrps; i++) {
            kfree(theaterq_syncgrps[i].members);
        }

        kfree(theaterq_syncgrps);
        theaterq_syncgrps = NULL;
    }

    unregister_qdisc(&theaterq_qdisc_ops);
}

module_init(sch_theaterq_init);
module_exit(sch_theaterq_exit);
