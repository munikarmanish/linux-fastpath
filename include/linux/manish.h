#ifndef MANISH_H
#define MANISH_H

#include <linux/hashtable.h>
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

#define MANISH_SK_MAP_SIZE (256)

struct manish_sk_entry {
	u32		   key;
	struct sock	  *sk;
	struct net_device *dev;
	struct hlist_node  node;
};

struct manish_sk_map {
	struct hlist_head hash[MANISH_SK_MAP_SIZE];
};

struct manish_pkt {
	struct ethhdr *eth;
	struct iphdr  *ip;
	union {
		struct udphdr *udp;
		struct tcphdr *tcp;
	};
};

extern int MANISH_DEBUG;
extern int MANISH_FASTPATH;

inline bool manish_filter_parse_skb(const struct sk_buff *skb,
				    struct manish_pkt *pkt, bool deep);
extern bool manish_filter_skb(const struct sk_buff *skb, bool deep);
extern void manish_print_skb(const struct sk_buff *skb, const char *fname);
inline void manish_sk_map_init(int cpu);
extern struct manish_sk_entry *manish_sk_lookup(const struct sk_buff *skb);
inline bool manish_skb_is_from_mlx(const struct sk_buff *skb);
extern void manish_sk_insert(struct sk_buff *skb, struct sock *sk);
void	    manish_print_sk_map(struct seq_file *f);
extern bool manish_receive_skb(struct sk_buff *skb);
extern bool manish_deliver_skb(struct sk_buff *skb);
extern void manish_sk_remove(const struct sock *sk);
extern void manish_sk_remove_all(void);

#endif // MANISH_H
