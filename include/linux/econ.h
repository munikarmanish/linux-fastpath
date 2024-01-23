#ifndef ECON_H
#define ECON_H

#include <linux/hashtable.h>
#include <linux/skbuff.h>
#include <net/vxlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

#define ECON_MAP_SIZE (1<<10)

struct econ_flow {
	__u8   smac[6];
	__u8   dmac[6];
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8   proto;
};

struct econ_rx_entry {
	u32		   key;
	struct sock	  *sk;
	struct net_device *dev;
	struct econ_flow   flow;
	struct hlist_node  node;
};

struct econ_rx_map {
	u64 timestamp;
	struct hlist_head hash[ECON_MAP_SIZE];
};

struct econ_pkt {
	struct ethhdr *eth;
	struct iphdr  *ip;
	union {
		struct udphdr *udp;
		struct tcphdr *tcp;
	};
};

struct econ_tx_map {
	u64 timestamp;
	struct hlist_head hash[ECON_MAP_SIZE];
};

struct econ_outer_header {
	struct ethhdr eth;
	struct iphdr ip;
	struct udphdr udp;
	struct vxlanhdr vxlan;
};

struct econ_tx_entry {
	/* required */
	struct hlist_node node;
	u32 key;
	/* inner */
	struct sock *sk;
	/* outer */
	struct net_device *dev;
	struct econ_outer_header outer;
};

extern int ECON_DEBUG;
extern int ECON_ENABLED;

inline bool econ_filter_parse_skb(const struct sk_buff *skb, struct econ_pkt *pkt, bool deep);
extern bool econ_filter_skb(const struct sk_buff *skb, bool deep);
extern void econ_print_skb(const struct sk_buff *skb, const char *fname);
inline void econ_rx_map_init(int cpu);
extern struct econ_rx_entry *econ_rx_lookup(const struct sk_buff *skb);
inline bool econ_skb_is_from_mlx(const struct sk_buff *skb);
extern void econ_rx_insert(struct sk_buff *skb, struct sock *sk);
void	    econ_print_rx_map(struct seq_file *f);
extern bool econ_rx(struct sk_buff *skb);
extern bool econ_rx_deliver(struct sk_buff *skb);
extern void econ_rx_remove(const struct sock *sk);
extern void econ_rx_remove_all(void);
extern int  econ_tx_insert(struct sk_buff *skb);
extern int  econ_xmit(struct sk_buff *skb);

#endif // ECON_H
