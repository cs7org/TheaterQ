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

#include "include/uapi/linux/pkt_sch_theaterq.h"

// TODO
// - Lock for chardev (check)
// - Synccheck in hrtimer
// - Duplication

// DATA + HELPER FUNCTIONS =====================================================

#define THEATERQ_INGEST_MAXLEN 256

static struct kmem_cache *theaterq_cache = NULL;
static DEFINE_SPINLOCK(theaterq_tree_lock);
static u8 syngrps = 8;
static u8 syngrps_members = 8;

static const struct theaterq_entry theaterq_default_entry = {
    .latency = 0ULL,
    .jitter = 0ULL,
    .rate = 0ULL,
    .loss = 0UL,
    .limit = 1000UL,
    .next = NULL,
};

enum {
    THEATERQ_CDEV_AVAILABLE,
    THEATERQ_CDEV_OPENED,
};

enum {
    THEATERQ_HRTIMER_STOPPED,
    THEATERQ_HRTIMER_RUNNING,
};

// Forward declaration
struct theaterq_syngrp;

struct theaterq_sched_data {
    struct rb_root t_root;
    struct sk_buff *t_head;
    struct sk_buff *t_tail;

    u32 t_len;
    u64 t_blen;

    struct Qdisc *qdisc;
    struct qdisc_watchdog watchdog;

    struct prng {
        u64 seed;
        bool seed_set;
        struct rnd_state prng_state;
    } prng;

    s32 packet_overhead;
    u32 stage;
    u32 cont_mode;
    bool use_byte_queue;
    bool allow_gso;
    struct theaterq_entry *current_entry;
    struct theaterq_entry *e_head;
    struct theaterq_entry *e_tail;
    u64 e_entries;
    u64 e_current;

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
    
    atomic_t t_running;
    u64 t_started;
    struct hrtimer timer;

    struct theaterq_syngrp *syngrp;

    struct tc_theaterq_xstats stats;
};

struct theaterq_syngrp {
    u16 index;
    struct theaterq_sched_data **members;
};

static struct theaterq_syngrp *theaterq_syngrps = NULL;

struct theaterq_skb_cb {
    u64 time_to_send;
};

// SYNC GROUPS =================================================================

// Forward delcarations
static void theaterq_stop_hrtimer(struct theaterq_sched_data *, bool, bool);
static int theaterq_run_hrtimer(struct theaterq_sched_data *, bool);
static void entry_list_clear(struct theaterq_sched_data *);

static void theaterq_syncgroup_stopall(struct theaterq_sched_data *q, 
                                       bool clear_others)
{
    spin_lock_bh(&theaterq_tree_lock);

    if (!q->syngrp)
        goto unlock;

    u32 group = q->syngrp->index;

    for (int i = 0; i < syngrps_members; i++) {
        if (theaterq_syngrps[group].members[i] == NULL ||
            theaterq_syngrps[group].members[i] == q)
                continue;
        
        struct theaterq_sched_data *other = theaterq_syngrps[group].members[i];
        if (other->stage != THEATERQ_STAGE_ARM && 
            other->stage != THEATERQ_STAGE_RUN && 
            other->stage != THEATERQ_STAGE_FINISH)
                continue;
        
        theaterq_stop_hrtimer(other, false, false);
        if (clear_others)
            entry_list_clear(q);

        other->stage = THEATERQ_STAGE_LOAD;

    }

unlock:
    spin_unlock_bh(&theaterq_tree_lock);
}

static void theaterq_syncgroup_startall(struct theaterq_sched_data *q)
{
    spin_lock_bh(&theaterq_tree_lock);

    if (!q->syngrp) {
        spin_unlock_bh(&theaterq_tree_lock);
        return;
    }

    u32 grp = q->syngrp->index;

    for (int i = 0; i < syngrps_members; i++) {
        if (theaterq_syngrps[grp].members[i] == NULL ||
            theaterq_syngrps[grp].members[i] == q)
                continue;
        
        struct theaterq_sched_data *other = theaterq_syngrps[grp].members[i];
        if (other->stage != THEATERQ_STAGE_LOAD && 
            other->stage != THEATERQ_STAGE_FINISH &&
            other->stage != THEATERQ_STAGE_ARM)
                continue;
        
        int errno = theaterq_run_hrtimer(other, false);
        if (errno)
            printk(KERN_WARNING "theaterq: Unable to start member %i in "
                                "syngroup %d: %d\n", i, grp, errno);
    }

    q->stage = THEATERQ_STAGE_LOAD;

    spin_unlock_bh(&theaterq_tree_lock);
}

static bool theaterq_syncgroup_join(struct theaterq_sched_data *q, s32 grp)
{
    if (grp == -1)
        return true;

    if (grp < -1) {
        printk(KERN_WARNING "theaterq: Invalid syncgroup: Must be -1 or "
                            "positive.\n");
        return false;
    }

    if (grp >= syngrps) {
        printk(KERN_WARNING "theaterq: Maximum syncgroup index is %d\n", 
               syngrps - 1);
        return false;
    }

    spin_lock_bh(&theaterq_tree_lock);

    int free_index = -1;

    for (int i = 0; i < syngrps_members; i++) {
        if (theaterq_syngrps[grp].members[i] == NULL) {
            if (free_index == -1)
                free_index = i;
        } else {
            u32 otherstage = theaterq_syngrps[grp].members[i]->stage;
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

    theaterq_syngrps[grp].members[free_index] = q;
    q->syngrp = &theaterq_syngrps[grp];
    spin_unlock_bh(&theaterq_tree_lock);
    return true;

fail_unlock:
    spin_unlock_bh(&theaterq_tree_lock);
    return false;
}

static void theaterq_syncgroup_leave(struct theaterq_sched_data *q)
{
    spin_lock_bh(&theaterq_tree_lock);

    if (!q->syngrp)
        goto unlock;
    
    for (int i = 0; i < syngrps_members; i++) {
        if (theaterq_syngrps[q->syngrp->index].members[i] == q) {
            theaterq_syngrps[q->syngrp->index].members[i] = NULL;
            break;
        }
    }

    q->syngrp = NULL;

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

static s64 get_pkt_delay(s64 mu, s32 sigma, struct prng *prng)
{
    u32 rnd;

    if (sigma == 0)
        return mu;

    rnd = prandom_u32_state(&prng->prng_state);
    return ((rnd % (2 * (u32) sigma)) + mu) - sigma;
}

static u64 packet_time_ns(u64 len, const struct theaterq_sched_data *q)
{
    if (!q->current_entry)
        return 0ul;

    len += q->packet_overhead;
    return div64_u64(len * NSEC_PER_SEC, q->current_entry->rate);
}

static void tfifo_enqueue(struct sk_buff *nskb, struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    u64 tnext = theaterq_skb_cb(nskb)->time_to_send;

    if (!q->t_tail || tnext >= theaterq_skb_cb(q->t_tail)->time_to_send) {
        if (q->t_tail)
            q->t_tail->next = nskb;
        else
            q->t_head = nskb;
        
        q->t_tail = nskb;
    } else {
        struct rb_node **p = &q->t_root.rb_node;
        struct rb_node *parent = NULL;

        while (*p) {
            struct sk_buff *skb;

            parent = *p;
            skb = rb_to_skb(parent);
            if (tnext >= theaterq_skb_cb(skb)->time_to_send)
                p = &parent->rb_right;
            else
                p = &parent->rb_left;
        }

        rb_link_node(&nskb->rbnode, parent, p);
        rb_insert_color(&nskb->rbnode, &q->t_root);
    }

    q->t_len++;
    q->t_blen += qdisc_pkt_len(nskb);
    sch->q.qlen++;
}

static void tfifo_reset(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct rb_node *p = rb_first(&q->t_root);

    while (p) {
        struct sk_buff *skb = rb_to_skb(p);

        p = rb_next(p);
        rb_erase(&skb->rbnode, &q->t_root);
        rtnl_kfree_skbs(skb, skb);
    }

    rtnl_kfree_skbs(q->t_head, q->t_tail);
    q->t_head = NULL;
    q->t_tail = NULL;
    q->t_len = 0;
    q->t_blen = 0;
}

static void entry_list_clear(struct theaterq_sched_data *q)
{
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
    q->e_entries = 0;
}

static void theaterq_stats_clear(struct tc_theaterq_xstats *stats)
{
    stats->looped = 0;
    stats->total_time = 0;
    stats->total_entries = 0;
}

static int theaterq_run_hrtimer(struct theaterq_sched_data *q, 
                                bool group_members)
{
    int ret = 0;

    if (group_members)
        theaterq_syncgroup_startall(q);

    if (atomic_cmpxchg(&q->t_running, THEATERQ_HRTIMER_STOPPED, 
                       THEATERQ_HRTIMER_RUNNING))
        return ret;
    
    if (!group_members) {
        q->stage = THEATERQ_STAGE_RUN;
    } else {
        spin_lock_bh(&theaterq_tree_lock);
        q->stage = THEATERQ_STAGE_RUN;
        spin_unlock_bh(&theaterq_tree_lock);
    }
    q->t_started = ktime_get_ns();

    if (!q->e_head) {
        ret = -EINVAL;
        goto fail_reset;
    }

    WRITE_ONCE(q->current_entry, q->e_head);
    q->current_entry = q->e_head;
    q->e_current = 0;

    if (!q->current_entry->next) {
        ret = -EINVAL;
        goto fail_reset;
    }

    q->stats.total_time = q->current_entry->next->delay;
    q->stats.total_entries++;
    ktime_t delay = ktime_set(0, q->stats.total_time);

    hrtimer_start(&q->timer, delay, HRTIMER_MODE_ABS);
    return ret;

fail_reset:
    atomic_set(&q->t_running, THEATERQ_HRTIMER_STOPPED);
    q->stage = THEATERQ_STAGE_LOAD;
    q->current_entry = (struct theaterq_entry *) &theaterq_default_entry;
    return ret;
}

static void theaterq_stop_hrtimer(struct theaterq_sched_data *q, 
                                  bool group_members, bool clear_members)
{
    if (group_members)
        theaterq_syncgroup_stopall(q, clear_members);

    if (atomic_cmpxchg(&q->t_running, THEATERQ_HRTIMER_RUNNING, 
                       THEATERQ_HRTIMER_STOPPED))
        return;

    hrtimer_cancel(&q->timer);

    WRITE_ONCE(q->current_entry, 
              (struct theaterq_entry *) &theaterq_default_entry);
}

// CHARDEV OPS =================================================================

static int ingest_cdev_open(struct inode *inode, struct file *filp)
{
    struct theaterq_sched_data *q;
    q = container_of(inode->i_cdev, struct theaterq_sched_data, 
                     ingest_cdev.cdev);
    filp->private_data = q;

    if (atomic_cmpxchg(&q->ingest_cdev.opened, THEATERQ_CDEV_AVAILABLE, 
                       THEATERQ_CDEV_OPENED))
        return -EBUSY;

    try_module_get(THIS_MODULE);
    return 0;
}

static int ingest_cdev_release(struct inode *inode, struct file *filp)
{
    struct theaterq_sched_data *q = filp->private_data;
    atomic_set(&q->ingest_cdev.opened, THEATERQ_CDEV_AVAILABLE);

    module_put(THIS_MODULE);
    return 0;
}

static ssize_t ingest_cdev_read(struct file *filp, char __user *buffer,
                                size_t length, loff_t *offset)
{
    return -EINVAL;
}

static ssize_t ingest_cdev_write(struct file *filp, const char __user *buffer,
                             size_t len, loff_t *offset)
{
    struct theaterq_sched_data *q = filp->private_data;
    
    char kbuf[THEATERQ_INGEST_MAXLEN];
    size_t actual_read = 0;

    if (len == 0) {
        printk(KERN_WARNING
               "sch_theaterq: Unable to parse line: Zero bytes read!\n");
        return -EINVAL;
    }
    
    while (len > 0) {
        size_t to_copy = min(len, sizeof(kbuf));
        if (copy_from_user(kbuf, buffer, to_copy)) {
            printk(KERN_ERR "sch_theaterq: chardev: Unable to copy_from_user!\n");
            return -EFAULT;
        }

        for (int i = 0; i < to_copy; i++) {
            char c = kbuf[i];

            if (q->ingest_helper.lpos >= THEATERQ_INGEST_MAXLEN - 1) {
                q->ingest_helper.lpos = 0;
                printk(KERN_WARNING 
                       "sch_theaterq: Unable to parse too long line at entry %llu!\n", 
                        q->e_entries + 1);
                return -EINVAL;
            }

            q->ingest_helper.lbuf[q->ingest_helper.lpos++] = c;

            if (c == '\n') {
                if (q->ingest_helper.lpos == 1) continue;

                q->ingest_helper.lbuf[q->ingest_helper.lpos - 1] = '\0';

                u64 delay;
                u64 latency;
                u64 jitter;
                u64 rate;
                u32 loss;
                u32 limit;
                struct theaterq_entry *entry;

                /* Input format:
                 * DELAY,LATENCY,JITTER,RATE,LOSS,LIMIT\n
                 *  ns     ns      ns   bps   a)    b)
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
                            return -EINVAL; \
                        } \
                        i++; \
                    } while (0)

                PARSE_TOKEN(kstrtou64, &delay);
                PARSE_TOKEN(kstrtou64, &latency);
                PARSE_TOKEN(kstrtou64, &jitter);
                PARSE_TOKEN(kstrtou64, &rate);
                PARSE_TOKEN(kstrtou32, &loss);
                PARSE_TOKEN(kstrtou32, &limit);

#undef PARSE_TOKEN

                if (p && *p != '\0') {
                    printk(KERN_WARNING 
                           "sch_theaterq: Unable to parse line: Unexpected "
                           "input at entry %llu!\n",
                           q->e_entries + 1);
                    return -EINVAL;
                }

                q->ingest_helper.lpos = 0;

                if (q->e_head == NULL && delay != 0) {
                    printk(KERN_WARNING 
                           "sch_theaterq: First loaded entry needs a delay of 0\n");
                    return -EINVAL;
                }

                if (q->stage != THEATERQ_STAGE_LOAD) {
                    printk(KERN_WARNING 
                           "sch_theaterq: Qdisc not in load stage\n");
                    return -EBUSY;
                }

                entry = kmem_cache_alloc(theaterq_cache, GFP_KERNEL);
                if (!entry) {
                    printk(KERN_ERR 
                           "sch_theaterq: Unable to alloc memory for entry\n");
                    return -ENOMEM;
                }

                entry->delay = delay; 
                entry->latency = latency;
                entry->jitter = jitter;
                entry->rate = rate / 8; // bits per second -> byte per second
                entry->loss = loss;
                entry->limit = limit;
                entry->next = NULL;

                if (q->e_head == NULL) {
                    q->e_head = entry;
                    q->e_tail = entry;
                } else {
                    q->e_tail->next = entry;
                    q->e_tail = entry;
                }

                q->e_entries++;
            }
        }

        buffer += to_copy;
        len -= to_copy;
        actual_read += to_copy;
    }
    
    return actual_read;
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

static enum hrtimer_restart theaterq_timer_cb(struct hrtimer *timer)
{
    struct theaterq_sched_data *q = container_of(timer, 
                                        struct theaterq_sched_data, timer);
    u64 next_delay;

    if (atomic_read(&q->t_running) != THEATERQ_HRTIMER_RUNNING)
        return HRTIMER_NORESTART;

    if (!q->current_entry->next) {
        switch (q->cont_mode) {
            case THEATERQ_CONT_LOOP:
                q->e_current = 0;
                q->stats.looped++;
                WRITE_ONCE(q->current_entry, q->e_head);
                break;

            case THEATERQ_CONT_CLEAR:
                WRITE_ONCE(q->current_entry, 
                           (struct theaterq_entry *) &theaterq_default_entry);

                // No fallthrough, gcc does not allow it after WRITE_ONCE
                WRITE_ONCE(q->stage, THEATERQ_STAGE_FINISH);
                atomic_set(&q->t_running, THEATERQ_HRTIMER_STOPPED);
                q->e_current = 0;
                return HRTIMER_NORESTART;

            case THEATERQ_CONT_HOLD:
                /* fallthrough */
            default:
                WRITE_ONCE(q->stage, THEATERQ_STAGE_FINISH);
                q->e_current = 0;
                return HRTIMER_NORESTART;
        }
    } else {
        WRITE_ONCE(q->current_entry, q->current_entry->next);
        q->e_current++;
    }

    if (q->current_entry->next)
        next_delay = q->current_entry->next->delay;
    else
        next_delay = q->current_entry->delay;

    q->stats.total_time += next_delay;
    q->stats.total_entries++;

    hrtimer_forward(timer, ktime_set(0, q->t_started + q->stats.total_time), next_delay);
    return HRTIMER_RESTART;
}

static int theaterq_enqueue_seg(struct sk_buff *skb, struct Qdisc *sch,
                                struct sk_buff **to_free)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct theaterq_skb_cb *cb;

    if (READ_ONCE(q->stage) == THEATERQ_STAGE_ARM) {
        (void) theaterq_run_hrtimer(q, true);
    }

    struct theaterq_entry *current_entry = READ_ONCE(q->current_entry);
    s64 now = ktime_get_ns();
    s64 delay = 0;
    u64 check_len;

    if (current_entry) {
        delay = get_pkt_delay(current_entry->latency, 
                              current_entry->jitter,
                              &q->prng);
    }
    skb->prev = NULL;

    if (loss_event(q)) {
        qdisc_qstats_drop(sch);
        __qdisc_drop(skb, to_free);
        return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
    }

    if (current_entry  && 
        (current_entry->latency ||
         current_entry->jitter ||
         current_entry->rate)) {
            skb_orphan_partial(skb);
    }

    check_len = q->use_byte_queue ? 
                    q->t_blen + qdisc_pkt_len(skb) : q->t_len;

    if (unlikely(current_entry && check_len >= current_entry->limit)) {
        qdisc_drop_all(skb, sch, to_free);
        return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
    }

    qdisc_qstats_backlog_inc(sch, skb);
    cb = theaterq_skb_cb(skb);

    if (current_entry && current_entry->rate) {
        struct theaterq_skb_cb *last = NULL;

        if (sch->q.tail) {
            last = theaterq_skb_cb(sch->q.tail);
        }

        if (q->t_root.rb_node) {
            struct sk_buff *t_skb = skb_rb_last(&q->t_root);
            struct theaterq_skb_cb *t_last = theaterq_skb_cb(t_skb);

            if (!last || t_last->time_to_send > last->time_to_send)
                last = t_last;
        }

        if (q->t_tail) {
            struct theaterq_skb_cb *t_last = theaterq_skb_cb(q->t_tail);

            if (!last || t_last->time_to_send > last->time_to_send)
                last = t_last;
        }

        if (last) {
            delay -= last->time_to_send - now;
            delay = max_t(s64, 0, delay);
            now = last->time_to_send;
        }

        delay += packet_time_ns(qdisc_pkt_len(skb), q);
    }

    cb->time_to_send = now + delay;
    tfifo_enqueue(skb, sch);
    return NET_XMIT_SUCCESS;
}

static int theaterq_enqueue_gso(struct sk_buff *skb, struct Qdisc *sch,
                                struct sk_buff **to_free)
{
    struct sk_buff *nskb;
    u32 nb = 0, dropped = 0;
    int ret = NET_XMIT_SUCCESS;
    int flag = 0;

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

static int theaterq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                            struct sk_buff **to_free)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    if (skb_is_gso(skb) && !q->allow_gso)
        return theaterq_enqueue_gso(skb, sch, to_free);
    else
        return theaterq_enqueue_seg(skb, sch, to_free);
}

static struct sk_buff *theaterq_peek(struct theaterq_sched_data *q)
{
    struct sk_buff *skb = skb_rb_first(&q->t_root);
    u64 t1, t2;

    if (!skb) return q->t_head;
    if (!q->t_head) return skb;

    t1 = theaterq_skb_cb(skb)->time_to_send;
    t2 = theaterq_skb_cb(q->t_head)->time_to_send;

    if (t1 < t2)
        return skb;
    else
        return q->t_head;
}

static void theaterq_erase_head(struct theaterq_sched_data *q, 
                                struct sk_buff *skb)
{
    if (skb == q->t_head) {
        q->t_head = skb->next;
        if (!q->t_head) q->t_tail = NULL;
    } else {
        rb_erase(&skb->rbnode, &q->t_root);
    }
}

static struct sk_buff *theaterq_dequeue(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct sk_buff *skb;

tfifo_dequeue:
    skb = __qdisc_dequeue_head(&sch->q);
    if (skb) {
deliver:
        qdisc_qstats_backlog_dec(sch, skb);
        qdisc_bstats_update(sch, skb);
        return skb;
    }

    skb = theaterq_peek(q);
    if (skb) {
        u64 time_to_send = theaterq_skb_cb(skb)->time_to_send;
        u64 now = ktime_get_ns();
        unsigned int pkt_len = qdisc_pkt_len(skb);

        if (time_to_send <= now) {
            theaterq_erase_head(q, skb);
            q->t_len--;
            q->t_blen -= pkt_len;
            skb->next = NULL;
            skb->prev = NULL;
            skb->dev = qdisc_dev(sch);

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

                goto tfifo_dequeue;
            }

            sch->q.qlen--;
            goto deliver;
        }

        if (q->qdisc) {
            skb = q->qdisc->ops->dequeue(q->qdisc);
            if (skb) {
                sch->q.qlen--;
                goto deliver;
            }
        }

        qdisc_watchdog_schedule_ns(&q->watchdog, time_to_send);
    }

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
    [TCA_THEATERQ_STAGE] = { .type = NLA_U32 },
    [TCA_THEATERQ_PRNG_SEED] = { .type = NLA_U64 },
    [TCA_THEATERQ_PKT_OVERHEAD] = { .type = NLA_S32 },
    [TCA_THEATERQ_CONT_MODE] = { .type = NLA_U32 },
    [TCA_THEATERQ_SYNCGRP] = { .type = NLA_S32 },
    [TCA_THEATERQ_USE_BYTEQ] = { .type = NLA_U8 },
    [TCA_THEATERQ_ALLOW_GSO] = { .type = NLA_U8 },
};

static int theaterq_change(struct Qdisc *sch, struct nlattr *opt,
                           struct netlink_ext_ack *extack)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct nlattr *tb[TCA_THEATERQ_MAX + 1];
    int run_hrtimer = 0;
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
            theaterq_stop_hrtimer(q, true, true);
            entry_list_clear(q);
            new_stage = THEATERQ_STAGE_LOAD;
        } else if (new_stage == THEATERQ_STAGE_LOAD && 
                   q->stage != new_stage) {
            theaterq_stop_hrtimer(q, true, false);
        } else if (new_stage == THEATERQ_STAGE_RUN) {
            if (!q->e_entries) {
                ret = -ENODATA;
                printk(KERN_WARNING 
                       "theaterq: Unable to run without entries!\n");
                goto err_out;
            }

            run_hrtimer = 1;
        }
    }

    if (tb[TCA_THEATERQ_CONT_MODE])
        q->cont_mode = nla_get_u32(tb[TCA_THEATERQ_CONT_MODE]);

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

    sch_tree_unlock(sch);

    if (new_stage != THEATERQ_STAGE_UNSPEC) {
        spin_lock_bh(&theaterq_tree_lock);
        q->stage = new_stage;
        spin_unlock_bh(&theaterq_tree_lock);
    }

    if (new_syncgrp != THEATERQ_NO_SYNCGRP_SELECTED 
        && !theaterq_syncgroup_change(q, new_syncgrp))
            return -EBADE;

    if (run_hrtimer)
        ret = theaterq_run_hrtimer(q, true);
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

    sch->limit = __UINT32_MAX__;

    q->stage = THEATERQ_STAGE_LOAD;
    q->cont_mode = THEATERQ_CONT_HOLD;
    q->allow_gso = false;
    q->syngrp = NULL;

    qdisc_watchdog_init(&q->watchdog, sch);

    if (!opt) return -EINVAL;

    q->ingest_cdev.en = false;
    ret = create_ingest_cdev(sch);
    if (ret < 0) return ret;

    entry_list_clear(q);

    hrtimer_init(&q->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
    q->timer.function = theaterq_timer_cb;
    atomic_set(&q->t_running, THEATERQ_HRTIMER_STOPPED);

    ret = theaterq_change(sch, opt, extack);
    if (ret)
        destroy_ingest_cdev(sch);

    return ret;
}

static void theaterq_reset(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    qdisc_reset_queue(sch);
    tfifo_reset(sch);
    theaterq_stop_hrtimer(q, false, false);
    theaterq_syncgroup_leave(q);
    theaterq_stats_clear(&q->stats);
    if (q->qdisc) qdisc_reset(q->qdisc);
    qdisc_watchdog_cancel(&q->watchdog);
}

static void theaterq_destroy(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    theaterq_stop_hrtimer(q, false, false);
    qdisc_watchdog_cancel(&q->watchdog);
    theaterq_syncgroup_leave(q);
    destroy_ingest_cdev(sch);
    entry_list_clear(q);
    if (q->qdisc) qdisc_put(q->qdisc);
}

static int theaterq_dump_qdisc(struct Qdisc *sch, struct sk_buff *skb)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct nlattr *opts = nla_nest_start(skb, TCA_OPTIONS);

    struct theaterq_entry current_entry;

    if (!opts)
        return -EMSGSIZE;

    if (nla_put_u32(skb, TCA_THEATERQ_STAGE, q->stage))
        goto nla_put_failure;

    if (q->prng.seed_set && nla_put_u64_64bit(skb, TCA_THEATERQ_PRNG_SEED, 
                                              q->prng.seed, TCA_THEATERQ_PAD))
        goto nla_put_failure;

    if (nla_put_s32(skb, TCA_THEATERQ_PKT_OVERHEAD, q->packet_overhead))
        goto nla_put_failure;
    
    s32 syncgroup = q->syngrp == NULL ? -1 : q->syngrp->index;
    if (nla_put_s32(skb, TCA_THEATERQ_SYNCGRP, syncgroup))
        goto nla_put_failure;
    
    if (nla_put_u32(skb, TCA_THEATERQ_CONT_MODE, q->cont_mode))
        goto nla_put_failure;
    
    if (nla_put(skb, TCA_THEATERQ_INGEST_CDEV, 
                sizeof(q->ingest_cdev.name), q->ingest_cdev.name))
        goto nla_put_failure;
    
    if (nla_put_u64_64bit(skb, TCA_THEATERQ_ENTRY_LEN, 
                          q->e_entries, TCA_THEATERQ_PAD))
        goto nla_put_failure;
    
    if (nla_put_u64_64bit(skb, TCA_THEATERQ_ENTRY_POS, 
                          q->e_current, TCA_THEATERQ_PAD))
        goto nla_put_failure;

     if (q->use_byte_queue && nla_put_u8(skb, TCA_THEATERQ_USE_BYTEQ,
                                         q->use_byte_queue))
        goto nla_put_failure;

    if (q->current_entry) {
        memcpy(&current_entry, q->current_entry, sizeof(current_entry));
        current_entry.next = NULL;

        if (nla_put(skb, TCA_THEATERQ_ENTRY_CURRENT, 
                    sizeof(current_entry), &current_entry))
            goto nla_put_failure;
    }

    if (q->allow_gso && nla_put_u8(skb, TCA_THEATERQ_ALLOW_GSO,
                                   q->allow_gso))
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

    stats.tfifo_plen = q->t_len;
    stats.tfifo_blen = q->t_blen;

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
MODULE_VERSION("0.1");

module_param(syngrps, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(syngrps, 
                 "Maximum synchronization groups (u8, default=8)");

module_param(syngrps_members, byte, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(syngrps_members, 
                 "Maximum members per synchronization group (u8, default=8)");

static int __init sch_theaterq_init(void)
{
    theaterq_cache = kmem_cache_create("theaterq_cache",
                                       sizeof(struct theaterq_entry),
                                       0, SLAB_HWCACHE_ALIGN, NULL);
    
    if (!theaterq_cache) {
        printk(KERN_ERR "theaterq: Unable to create slab allocator\n");
        return -ENOMEM;
    }

    theaterq_syngrps = kmalloc_array(((u32) syngrps), 
                                     sizeof(struct theaterq_syngrp), 
                                     GFP_KERNEL);

    if (!theaterq_syngrps) {
        printk(KERN_ERR "theaterq: Unable kmalloc for syncgroups\n");
        kmem_cache_destroy(theaterq_cache);
        theaterq_cache = NULL;
        return -ENOMEM;
    }
    s32 i;
    for (i = 0; i < syngrps; i++) {
        theaterq_syngrps[i].index = i;
        theaterq_syngrps[i].members = kcalloc(syngrps_members, 
                                             sizeof(struct theaterq_sched_data *), 
                                             GFP_KERNEL);
        if (theaterq_syngrps[i].members == NULL) {
            goto init_failed;
        }
    }

    return register_qdisc(&theaterq_qdisc_ops);

init_failed:
    while (--i >= 0) {
        kfree(theaterq_syngrps[i].members);
    }

    kfree(theaterq_syngrps);
    theaterq_syngrps = NULL;
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

    if (theaterq_syngrps) {
        for (s32 i = 0; i < syngrps; i++) {
            kfree(theaterq_syngrps[i].members);
        }

        kfree(theaterq_syngrps);
        theaterq_syngrps = NULL;
    }

    unregister_qdisc(&theaterq_qdisc_ops);
}

module_init(sch_theaterq_init);
module_exit(sch_theaterq_exit);
