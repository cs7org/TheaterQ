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
#include <net/gso.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/sock.h>

#include "include/uapi/linux/pkt_sch_theaterq.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Martin Ottens <martin.ottens@fau.de>");
MODULE_DESCRIPTION("Trace File based Link Emulator");
MODULE_VERSION("0.1");

// DATA + HELPER FUNCTIONS ================================================

struct theaterq_entry {
    s64 latency;
    s64 jitter;
    u64 rate;
    u32 loss;
    u32 limit;
};

struct theaterq_sched_data {
    struct rb_root t_root;
    struct sk_buff *t_head;
    struct sk_buff *t_tail;

    u32 t_len;

    struct Qdisc *qdisc;
    struct qdisc_watchdog watchdog;

    struct prng {
        u64 seed;
        struct rnd_state prng_state;
    } prng;

    struct tc_netem_slot slot_config;
    struct slotstate {
        u64 slot_next;
        s32 packets_left;
        s32 bytes_left;
    } slot;

    s32 packet_overhead;
    u32 stage;
    struct theaterq_entry *current_entry;
};

struct theaterq_skb_cb {
    u64 time_to_send;
};

static inline struct theaterq_skb_cb *theaterq_skb_cb(struct sk_buff *skb)
{
    qdisc_cb_private_validate(skb, sizeof(struct theaterq_skb_cb));
    return (struct theaterq_skb_cb *) qdisc_skb_cb(skb)->data;
}

static inline bool loss_event(struct theaterq_sched_data *q)
{
    return q->current_entry->loss && 
           q->current_entry->loss >= prandom_u32_state(&q->prng.prng_state);
}

static s64 get_pkt_delay(s64 mu, s32 sigma, struct prng *prng) {
    u32 rnd;

    if (sigma == 0) return mu;

    rnd = prandom_u32_state(&prng->prng_state);
    return ((rnd % (2 * (u32) sigma)) + mu) - sigma;
}

static u64 packet_time_ns(u64 len, const struct theaterq_sched_data *q)
{
    len += q->packet_overhead;
    return div64_u64(len * NSEC_PER_SEC, q->current_entry->rate);
}

static void tfifo_enqueue(struct sk_buff *nskb, struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    u64 tnext = theaterq_skb_cb(nskb)->time_to_send;

    if (!q->t_tail || tnext >= theaterq_skb_cb(q->t_tail)->time_to_send) {
        if (q->t_tail) {
            q->t_tail->next = nskb;
        } else {
            q->t_head = nskb;
        }
        
        q->t_tail = nskb;
    } else {
        struct rb_node **p = &q->t_root.rb_node;
        struct rb_node *parent = NULL;

        while (*p) {
            struct sk_buff *skb;

            parent = *p;
            skb = rb_to_skb(parent);
            if (tnext >= theaterq_skb_cb(skb)->time_to_send) {
                p = &parent->rb_right;
            } else {
                p = &parent->rb_left;
            }
        }

        rb_link_node(&nskb->rbnode, parent, p);
        rb_insert_color(&nskb->rbnode, &q->t_root);
    }

    q->t_len++;
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
}

static struct sk_buff *theaterq_segment(struct sk_buff *skb, struct Qdisc *sch,
                                        struct sk_buff **to_free)
{
    struct sk_buff *segs;
    netdev_features_t features = netif_skb_features(skb);
    segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

    if (IS_ERR_OR_NULL(segs)) {
        qdisc_drop(skb, sch, to_free);
        return NULL;
    }

    consume_skb(skb);
    return segs;
}

// QDISC OPS ==============================================================

static int theaterq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                            struct sk_buff **to_free)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct theaterq_skb_cb *cb;
    s64 now = ktime_get_ns();
    s64 delay = get_pkt_delay(q->current_entry->latency, 
                              q->current_entry->jitter,
                              &q->prng);
    skb->prev = NULL;

    if (loss_event(q)) {
        qdisc_qstats_drop(sch);
        __qdisc_drop(skb, to_free);
        return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
    }

    if (q->current_entry->latency ||
        q->current_entry->jitter ||
        q->current_entry->rate) {
            skb_orphan_partial(skb);
    }

    if (unlikely(q->t_len >= q->current_entry->limit)) {
        qdisc_drop_all(skb, sch, to_free);
        return NET_XMIT_DROP;
    }

    qdisc_qstats_backlog_inc(sch, skb);
    cb = theaterq_skb_cb(skb);

    if (q->current_entry->rate) {
        struct theaterq_skb_cb *last = NULL;

        if (sch->q.tail) {
            last = theaterq_skb_cb(sch->q.tail);
        }

        if (q->t_root.rb_node) {
            struct sk_buff *t_skb = skb_rb_last(&q->t_root);
            struct theaterq_skb_cb *t_last = theaterq_skb_cb(t_skb);

            if (!last || t_last->time_to_send < last->time_to_send) {
                last = t_last;
            }
        }

        if (q->t_tail) {
            struct theaterq_skb_cb *t_last = theaterq_skb_cb(q->t_tail);

            if (!last || t_last->time_to_send > last->time_to_send) {
                last = t_last;
            }
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

static struct sk_buff *theaterq_peek(struct theaterq_sched_data *q)
{
    struct sk_buff *skb = skb_rb_first(&q->t_root);
    u64 t1, t2;

    if (!skb) return q->t_head;
    if (!q->t_head) return skb;

    t1 = theaterq_skb_cb(skb)->time_to_send;
    t2 = theaterq_skb_cb(q->t_head)->time_to_send;

    if (t1 < t2) {
        return skb;
    } else {
        return q->t_head;
    }
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

        if (time_to_send <= now) {
            theaterq_erase_head(q, skb);
            q->t_len--;
            skb->next = NULL;
            skb->prev = NULL;
            skb->dev = qdisc_dev(sch);

            if (q->qdisc) {
                unsigned int pkt_len = qdisc_pkt_len(skb);
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
    [TCA_THEATERQ_MODE] = { .type = NLA_U32 },
};

static int theaterq_change(struct Qdisc *sch, struct nlattr *opt,
                           struct netlink_ext_ack *extack)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);
    struct nlattr *tb[TCA_THEATERQ_MAX + 1];
    int err;

    err = nla_parse_nested(tb, TCA_THEATERQ_MAX, opt, theaterq_policy, extack);
    if (err < 0) return err;

    sch_tree_lock(sch);

    if (tb[TCA_THEATERQ_MODE]) {
        q->stage = nla_get_u32(tb[TCA_THEATERQ_MODE]);
    }

    sch_tree_unlock(sch);
    printk(KERN_ERR "Theaterq is now: %d\n", q->stage);
    return 0;
}

static int theaterq_init(struct Qdisc *sch, struct nlattr *opt,
                         struct netlink_ext_ack *extack)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    q->stage = THEATERQ_STAGE_LOAD;
    qdisc_watchdog_init(&q->watchdog, sch);

    if (!opt) return -EINVAL;
    
    return theaterq_change(sch, opt, extack);
}

static void theaterq_reset(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    qdisc_reset_queue(sch);
    tfifo_reset(sch);
    if (q->qdisc) qdisc_reset(q->qdisc);
    qdisc_watchdog_cancel(&q->watchdog);
}

static void theaterq_destroy(struct Qdisc *sch)
{
    struct theaterq_sched_data *q = qdisc_priv(sch);

    qdisc_watchdog_cancel(&q->watchdog);
    if (q->qdisc) qdisc_put(q->qdisc);
}

static int theaterq_dump_qdisc(struct Qdisc *sch, struct sk_buff *skb)
{
    return 0;
}


// CLASS OPS ==============================================================

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

// MODULE BOOTSTRAP =======================================================

static const struct Qdisc_class_ops theaterq_class_ops = {
    .graft = theaterq_graft,
    .leaf  = theaterq_leaf,
    .find  = theaterq_find,
    .walk  = theaterq_walk,
    .dump  = theaterq_dump_class,
};

static struct Qdisc_ops theaterq_qdisc_ops __read_mostly = {
    .id        = "theaterq",
    .cl_ops    = &theaterq_class_ops,
    .priv_size = sizeof(struct theaterq_sched_data),
    .enqueue   = theaterq_enqueue,
    .dequeue   = theaterq_dequeue,
    .peek      = qdisc_peek_dequeued,
    .init      = theaterq_init,
    .reset     = theaterq_reset,
    .destroy   = theaterq_destroy,
    .change    = theaterq_change,
    .dump      = theaterq_dump_qdisc,
    .owner     = THIS_MODULE,
};

static int __init sch_theaterq_init(void)
{
    return register_qdisc(&theaterq_qdisc_ops);
}

static void __exit sch_theaterq_exit(void)
{
    unregister_qdisc(&theaterq_qdisc_ops);
}

module_init(sch_theaterq_init);
module_exit(sch_theaterq_exit);
