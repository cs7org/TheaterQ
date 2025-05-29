#include <uapi/linux/pkt_sch_theaterq.h>
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

MODULE_LICENSE("Proprietary");
MODULE_AUTHOR("Martin Ottens <martin.ottens@fau.de>");
MODULE_DESCRIPTION("Trace File based Link Emulator");
MODULE_VERSION("0.1");

// DATA ===================================================================

struct theaterq_sched_data {};

// QDISC OPS ==============================================================

static int theaterq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                            struct sk_buff **to_free)
{
    return 0;
}

static struct sk_buff *theaterq_dequeue(struct Qdisc *sch)
{
    return NULL;
}

static int theaterq_init(struct Qdisc *sch, struct nlattr *opt,
                         struct netlink_ext_ack *extack)
{
    return 1;
}

static void theaterq_reset(struct Qdisc *sch)
{

}

static void theaterq_destroy(struct Qdisc *sch)
{

}

static int theaterq_change(struct Qdisc *sch, struct nlattr *opt,
                           struct netlink_ext_ack *extack)
{
    return 1;
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
    return 0;
}

static struct Qdisc *theaterq_leaf(struct Qdisc *sch, unsigned long arg)
{
    return NULL;
}

static unsigned long theaterq_find(struct Qdisc *sch, u32 classid)
{
    return 1;
}

static void theaterq_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{

}

static int theaterq_dump_class(struct Qdisc *sch, unsigned long cl,
                               struct sk_buff *skb, struct tcmsg *tcm)
{
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
