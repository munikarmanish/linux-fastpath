#ifndef ECON_H
#define ECON_H

#include <linux/hashtable.h>
#include <linux/skbuff.h>
#include <net/vxlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

#define ECON_MAP_SIZE (1<<10)

struct econ_flow {	// 25 bytes (32 bytes)
	__u8   smac[6];		// 6 bytes
	__u8   dmac[6];		// 6 bytes
	__be32 saddr;		// 4 bytes
	__be32 daddr;		// 4 bytes
	__be16 sport;		// 2 bytes
	__be16 dport;		// 2 bytes
	__u8   proto;		// 1 byte
};

struct econ_rx_entry {	// 61B
	u32		   key;		// 4B
	struct sock	  *sk;		// 8B
	struct net_device *dev;		// 8B
	struct econ_flow   flow;	// 32B
	struct hlist_node  node;	// 16B
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
	struct ethhdr eth;	// 14 bytes
	struct iphdr ip;	// 20 bytes
	struct udphdr udp;	// 8 bytes
	struct vxlanhdr vxlan;	// 8 bytes
};

struct econ_tx_entry { // 86 bytes
	/* required */
	struct hlist_node node;		// 16 bytes
	u32 key;			// 4 bytes
	/* inner */
	struct sock *sk;		// 8 bytes
	/* outer */
	struct net_device *dev;		// 8 bytes
	struct econ_outer_header outer;	// 50 bytes
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
