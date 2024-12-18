#include <linux/econ.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/timekeeping.h>
#include <net/busy_poll.h>
#include <net/flow_dissector.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/vxlan.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

DEFINE_PER_CPU(struct econ_rx_map, econ_rx_map);
EXPORT_PER_CPU_SYMBOL(econ_rx_map);
DEFINE_PER_CPU(struct econ_tx_map, econ_tx_map);
EXPORT_PER_CPU_SYMBOL(econ_tx_map);

int ECON_ENABLED = 0;	// ECON disabled by default
EXPORT_SYMBOL(ECON_ENABLED);

int ECON_DEBUG = 0;	// debugging disabled by default
EXPORT_SYMBOL(ECON_DEBUG);

u32 PNIC_NET = 0xc0a800; // 192.168.0
// u32 VNIC_NET = 0x010000; // 1.0.0
u32 VNIC_NET = 0x0ae9; // 10.233

inline bool econ_filter_parse_skb(const struct sk_buff *skb, struct econ_pkt *pkt, bool deep)
{
	u8	      *cur;
	struct ethhdr *eth;
	struct iphdr  *ip;
	struct udphdr *udp;

	// initialize the cursor to the MAC header
	cur = skb->head;
	cur += skb->mac_header;

restart_from_eth:
	// parse Ethernet header
	eth = (struct ethhdr *)cur;
	if (pkt)
		pkt->eth = eth;
	if (ntohs(eth->h_proto) != ETH_P_IP)
		return false;

	// parse IP header
	cur += ETH_HLEN;
	ip = (struct iphdr *)cur;
	if (pkt)
		pkt->ip = ip;
	if (ip->version != 4)
		return false;
	// IP addresses must match
	if (((ntohl(ip->daddr) >> 8) != PNIC_NET) &&
	    ((ntohl(ip->daddr) >> 16) != VNIC_NET))
		return false;

	// if non-first fragment, return
	if (ip_is_fragment(ip) && (ntohs(ip->frag_off) & IP_OFFSET) > 0)
		return false;

	// only accept UDP and/or TCP
	if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP)
		return false;

	// parse UDP header
	cur += (ip->ihl * 4);
	udp = (struct udphdr *)cur;
	if (pkt)
		pkt->udp = udp;

	if (!deep && !pkt)
		return false;

	// is it vxlan?
	if (deep && ip->protocol == IPPROTO_UDP &&
	    ntohs(udp->dest) == IANA_VXLAN_UDP_PORT) {
		cur += 8 + 8; // udp + vxlan
		goto restart_from_eth;
	}

	return true;
}

bool econ_filter_skb(const struct sk_buff *skb, bool deep)
{
	return econ_filter_parse_skb(skb, NULL, deep);
}
EXPORT_SYMBOL(econ_filter_skb);

void econ_print_skb(const struct sk_buff *skb, const char *fname)
{
	struct econ_pkt pkt;
	u16 flags, offset;

	if (!ECON_DEBUG)
		return;

	// only print shallow headers
	if (!econ_filter_parse_skb(skb, &pkt, false))
		return;

	flags = ntohs(pkt.ip->frag_off) >> 13;
	offset = ntohs(pkt.ip->frag_off) << 3;

	if (pkt.udp && pkt.ip->protocol == IPPROTO_UDP) {
		pr_info("%s: skb=%px dev=%s iif=%d\n"
			" data=%ld tail=%u end=%u len=%u dlen=%u L2=%u L3=%u L4=%u\n"
			" hash=(%x sw=%u l4=%u) csum=(%x summed=%u sw=%u valid=%u)\n"
			" ip: %pI4 > %pI4 len=%u prot=%x flag=%x off=%u id=%x\n"
			" udp: %u > %u ulen=%u check=%x\n",
			fname, skb, skb->dev ? skb->dev->name : "NULL",
			skb->skb_iif, skb->data - skb->head, skb->tail,
			skb->end, skb->len, skb->data_len, skb->mac_header,
			skb->network_header, skb->transport_header, skb->hash,
			skb->sw_hash, skb->l4_hash, skb->csum, skb->ip_summed,
			skb->csum_complete_sw, skb->csum_valid, &pkt.ip->saddr,
			&pkt.ip->daddr, ntohs(pkt.ip->tot_len),
			pkt.ip->protocol, flags, offset, ntohs(pkt.ip->id),
			ntohs(pkt.udp->source), ntohs(pkt.udp->dest),
			ntohs(pkt.udp->len), ntohs(pkt.udp->check));
	} else if (pkt.tcp && pkt.ip->protocol == IPPROTO_TCP) {
		pr_info("%s: skb=%px dev=%s iif=%d\n"
			" data=%ld tail=%u end=%u len=%u dlen=%u L2=%u L3=%u L4=%u\n"
			" hash=(%x sw=%u l4=%u) csum=(%x summed=%u sw=%u valid=%u)\n"
			" ip: %pI4 > %pI4 len=%u prot=%x flag=%x off=%u id=%x\n"
			" tcp: %u > %u seq=%x flags=[%c%c%c%c]\n",
			fname, skb, skb->dev ? skb->dev->name : "NULL",
			skb->skb_iif, skb->data - skb->head, skb->tail,
			skb->end, skb->len, skb->data_len, skb->mac_header,
			skb->network_header, skb->transport_header, skb->hash,
			skb->sw_hash, skb->l4_hash, skb->csum, skb->ip_summed,
			skb->csum_complete_sw, skb->csum_valid, &pkt.ip->saddr,
			&pkt.ip->daddr, ntohs(pkt.ip->tot_len),
			pkt.ip->protocol, flags, offset, ntohs(pkt.ip->id),
			ntohs(pkt.tcp->source), ntohs(pkt.tcp->dest),
			ntohl(pkt.tcp->seq), pkt.tcp->syn ? 'S' : ' ',
			pkt.tcp->psh ? 'P' : ' ', pkt.tcp->fin ? 'F' : ' ',
			pkt.tcp->ack ? 'A' : ' ');
	} else {
		pr_info("%s: skb=%px dev=%s iif=%d\n"
			" data=%ld tail=%u end=%u len=%u dlen=%u L2=%u L3=%u L4=%u\n"
			" hash=(%x sw=%u l4=%u) csum=(%x summed=%u sw=%u valid=%u)\n"
			" %pI4 > %pI4 len=%u prot=%x flag=%x off=%u id=%x\n",
			fname, skb, skb->dev ? skb->dev->name : "NULL",
			skb->skb_iif, skb->data - skb->head, skb->tail,
			skb->end, skb->len, skb->data_len, skb->mac_header,
			skb->network_header, skb->transport_header, skb->hash,
			skb->sw_hash, skb->l4_hash, skb->csum, skb->ip_summed,
			skb->csum_complete_sw, skb->csum_valid, &pkt.ip->saddr,
			&pkt.ip->daddr, ntohs(pkt.ip->tot_len),
			pkt.ip->protocol, flags, offset, ntohs(pkt.ip->id));
	}
}
EXPORT_SYMBOL(econ_print_skb);

void inline econ_rx_map_init(int cpu)
{
	int bkt;
	struct econ_rx_map *map;

	if (ECON_DEBUG)
		pr_info("===: initializing econ_rx_map on cpu %d\n", cpu);
	map = &per_cpu(econ_rx_map, cpu);
	for (bkt = 0; bkt < ECON_MAP_SIZE; bkt++)
		map->hash[bkt].first = NULL;
}

struct econ_rx_entry *econ_rx_lookup(const struct sk_buff *skb)
{
	struct econ_rx_entry *entry = NULL;
	struct ethhdr	     *eth;
	struct iphdr	     *ip;
	struct udphdr	     *udp;
	u8		     *cursor;
	struct econ_rx_map   *map = get_cpu_ptr(&econ_rx_map);
	hash_for_each_possible(map->hash, entry, node, skb->hash) {
		if (entry->key == skb->hash)
			break;
	}
	put_cpu_ptr(&econ_rx_map);
	if (!entry)
		return NULL;

	// get the headers
	cursor = skb->head + skb->mac_header;
start_from_eth:
	eth = (struct ethhdr *)cursor;
	cursor += ETH_HLEN;
	ip = (struct iphdr *)cursor;
	cursor += (ip->ihl * 4);
	udp = (struct udphdr *)cursor;
	if (ip->protocol == IPPROTO_UDP && ntohs(udp->dest) == IANA_VXLAN_UDP_PORT) {
		cursor += (8 + 8); // skip the udp + vxlan headers
		goto start_from_eth;
	}

	// check the header fields

	// skip checking MAC addresses
	// if (strncmp(entry->flow.smac, eth->h_source, 6) != 0)
	// 	return NULL;
	// if (strncmp(entry->flow.dmac, eth->h_dest, 6) != 0)
	// 	return NULL;
	if (entry->flow.saddr != ip->saddr)
		return NULL;
	if (entry->flow.daddr != ip->daddr)
		return NULL;
	if (entry->flow.proto != ip->protocol)
		return NULL;
	if (entry->flow.sport != udp->source)
		return NULL;
	if (entry->flow.dport != udp->dest)
		return NULL;

	return entry;
}
EXPORT_SYMBOL(econ_rx_lookup);

void econ_rx_insert(struct sk_buff *skb, struct sock *sk)
{
	struct econ_rx_entry *entry;
	struct econ_rx_map   *map;
	// struct ethhdr	     *eth;
	struct iphdr	     *ip;
	struct udphdr	     *udp;

	if (skb_shinfo(skb)->frag_list)
		__skb_get_hash(skb);

	map = get_cpu_ptr(&econ_rx_map);
	// only allow if timestamp difference > 100ms
	if (ktime_get_ns() - map->timestamp < 100000000UL)
		goto skip;
	// see if the given key already exists in the hashtable
	hash_for_each_possible(map->hash, entry, node, skb->hash) {
		if (entry->key == skb->hash)
			break;
	}

	// if key doesn't exist, add an entry
	if (!entry || entry->key != skb->hash) {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		entry->key = skb->hash;
		hash_add(map->hash, &entry->node, entry->key);
		if (ECON_DEBUG)
			pr_info("econ_rx_insert: [cpu %d] %x => %px (refcounted = %u)\n",
				smp_processor_id(), entry->key, entry->sk,
				sk_is_refcounted(sk));
	}

	// update the fields
	entry->sk = sk;
	entry->dev = skb->dev;

	// skip MAC addrs
	// eth = eth_hdr(skb);
	// memcpy(entry->flow.smac, eth->h_source, 6);
	// memcpy(entry->flow.dmac, eth->h_dest, 6);
	ip = ip_hdr(skb);
	entry->flow.saddr = ip->saddr;
	entry->flow.daddr = ip->daddr;
	entry->flow.proto = ip->protocol;
	udp = udp_hdr(skb);
	entry->flow.sport = udp->source;
	entry->flow.dport = udp->dest;

skip:
	put_cpu_ptr(&econ_rx_map);
}
EXPORT_SYMBOL(econ_rx_insert);

void econ_print_rx_map(struct seq_file *f)
{
	int		      cpu, bkt;
	struct econ_rx_map   *rx_map;
	struct econ_rx_entry *rx_entry;
	struct econ_tx_map   *tx_map;
	struct econ_tx_entry *tx_entry;

	seq_printf(f, "\nECON Rx maps:\n=============\n");
	for_each_possible_cpu(cpu) {
		rx_map = &per_cpu(econ_rx_map, cpu);
		if (!hash_empty(rx_map->hash)) {
			seq_printf(f, "CPU %d:\n", cpu);
			hash_for_each(rx_map->hash, bkt, rx_entry, node) {
				seq_printf(
					f,
					"   %x => %px %s(%pI4:%u > %pI4:%u)\n",
					rx_entry->key, rx_entry->sk,
					rx_entry->sk->sk_prot->name,
					&rx_entry->sk->sk_daddr,
					ntohs(rx_entry->sk->sk_dport),
					&rx_entry->sk->sk_rcv_saddr,
					rx_entry->sk->sk_num);
			}
		}
	}

	seq_printf(f, "\nECON Tx maps:\n=============\n");
	for_each_possible_cpu(cpu) {
		tx_map = &per_cpu(econ_tx_map, cpu);
		if (!hash_empty(tx_map->hash)) {
			seq_printf(f, "CPU %d:\n", cpu);
			hash_for_each(tx_map->hash, bkt, tx_entry, node) {
				seq_printf(
					f,
					"   %x => %px %s(%pI4:%u > %pI4:%u) :: %pI4:%u > %pI4:%u, vni=%x\n",
					tx_entry->key, tx_entry->sk,
					tx_entry->sk->sk_prot->name,
					&tx_entry->sk->sk_rcv_saddr,
					tx_entry->sk->sk_num,
					&tx_entry->sk->sk_daddr,
					ntohs(tx_entry->sk->sk_dport),
					&tx_entry->outer.ip.saddr,
					ntohs(tx_entry->outer.udp.source),
					&tx_entry->outer.ip.daddr,
					ntohs(tx_entry->outer.udp.dest),
					ntohl(vxlan_vni(tx_entry->outer.vxlan.vx_vni)));
			}
		}
	}
}

/**
 *	Checks if packet is VXLAN, and removes outer headers if so.
 */
int econ_rx(struct sk_buff *skb)
{
	struct iphdr	     *ip;
	struct udphdr	     *udp;
	struct econ_rx_entry *entry;
	int		      drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

	// packet has already be processed once by ECON
	if (skb->econ_sk)
		return 1;

	// flow not cached
	entry = econ_rx_lookup(skb);
	if (!entry)
		return 2;

	/* prevent socket lookup */
	skb->econ_sk = entry->sk;
	skb->econ_dev = entry->dev;
	// skb->skb_iif = entry->dev->ifindex;

	// skb->data points to L3 header
	skb->network_header = skb->mac_header + ETH_HLEN;

	ip = ip_hdr(skb);
	if (!pskb_may_pull(skb, ip->ihl*4))
		goto drop;
	if (unlikely(ip_fast_csum((u8 *)ip, ip->ihl)))
		goto ip_csum_error;
	if (pskb_trim_rcsum(skb, ntohs(ip->tot_len)))
		goto drop;
	skb->transport_header = skb->network_header + ip->ihl*4;

	// // Remove any debris in the socket control block
	// memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	// IPCB(skb)->iif = skb->skb_iif;

	// check if vxlan
	udp = udp_hdr(skb);
	if (ip->protocol == IPPROTO_UDP && ntohs(udp->dest) == IANA_VXLAN_UDP_PORT) {
		skb->inner_network_header = skb->network_header;
		skb->inner_transport_header = skb->transport_header;
		skb->mac_header = skb->transport_header + 8 + 8;
		__skb_pull(skb, skb_network_header_len(skb) + 8 + 8 + 14); // udp + vxlan + eth
		skb_postpull_rcsum(skb, skb_network_header(skb), skb_network_header_len(skb) + 8 + 8 + 14);
	}

	return 0;

ip_csum_error:
	drop_reason = SKB_DROP_REASON_IP_CSUM;
	goto drop;
drop:
	kfree_skb_reason(skb, drop_reason);
	return 3;
}
EXPORT_SYMBOL(econ_rx);

bool econ_rx_deliver(struct sk_buff *skb)
{
	struct iphdr *ip;
	int	      drop_reason = SKB_DROP_REASON_NOT_SPECIFIED, ret;

start_from_eth:
	// run outer netfilter hooks
	if (skb->inner_network_header > 0 && skb->inner_network_header < skb->network_header) {
		skb->network_header = skb->inner_network_header;
		skb->transport_header = skb->inner_transport_header;
		skb->data = skb->head + skb->network_header;
		ret = nf_hook(NFPROTO_IPV4, NF_INET_PRE_ROUTING, dev_net(skb->dev), NULL, skb, skb->dev, NULL, NULL);
		if (ret != 1)
			return false;
		ret = nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_IN, dev_net(skb->dev), NULL, skb, skb->dev, NULL, NULL);
		if (ret != 1)
			return false;
	}

	// skb->data should point to inner L3 header now
	skb->network_header = skb->mac_header + ETH_HLEN;
	skb->data = skb->head + skb->network_header;
	ip = ip_hdr(skb);
	if (!pskb_may_pull(skb, ip->ihl*4))
		goto drop;
	if (unlikely(ip_fast_csum((u8 *)ip, ip->ihl)))
		goto ip_csum_error;
	if (pskb_trim_rcsum(skb, ntohs(ip->tot_len)))
		goto drop;
	skb->transport_header = skb->network_header + ip->ihl*4;
	skb->dev = skb->econ_dev;

	// run inner netfilter hooks
	ret = nf_hook(NFPROTO_IPV4, NF_INET_PRE_ROUTING, dev_net(skb->dev), NULL, skb, skb->dev, NULL, NULL);
	if (ret != 1)
		return false;
	ret = nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_IN, dev_net(skb->dev), NULL, skb, skb->dev, NULL, NULL);
	if (ret != 1)
		return false;

	// check if vxlan
	if (ip->protocol == IPPROTO_UDP && ntohs(udp_hdr(skb)->dest) == IANA_VXLAN_UDP_PORT) {
		skb->mac_header = skb->transport_header + 8 + 8;
		__skb_pull(skb, skb_network_header_len(skb) + 8 + 8 + 14); // udp + vxlan + eth
		skb_postpull_rcsum(skb, skb_network_header(skb), skb_network_header_len(skb) + 8 + 8 + 14);
		skb->dev = skb->econ_dev ?: skb->dev;
		goto start_from_eth;
	}

	__skb_pull(skb, skb_network_header_len(skb));
	skb_postpull_rcsum(skb, skb_network_header(skb), skb_network_header_len(skb));

	// directly calling udp_rcv() works (with a minor modification, see __udp4_lib_rcv+60)
	rcu_read_lock();
	if (ip->protocol == IPPROTO_UDP)
		udp_rcv(skb);
	else if (ip->protocol == IPPROTO_TCP)
		tcp_v4_rcv(skb);
	rcu_read_unlock();

	return true;

ip_csum_error:
	drop_reason = SKB_DROP_REASON_IP_CSUM;
	goto drop;
drop:
	kfree_skb_reason(skb, drop_reason);
	return false;
}
EXPORT_SYMBOL(econ_rx_deliver);

void econ_rx_remove(const struct sock *sk)
{
	int		      cpu, bkt;
	struct econ_rx_map   *map;
	struct econ_rx_entry *entry;
	struct econ_tx_map   *tx_map;
	struct econ_tx_entry *tx_entry;

	/* remove sk entry */
	for_each_possible_cpu(cpu) {
		map = &per_cpu(econ_rx_map, cpu);
		if (!hash_empty(map->hash)) {
			hash_for_each(map->hash, bkt, entry, node) {
				if (entry->sk == sk) {
					if (ECON_DEBUG)
						pr_info("econ_rx_remove: cpu=%d sk=%px\n",
							cpu, sk);
					hash_del(&entry->node);
					kfree(entry);
				}
			}
		}
	}

	/* remove tx entry */
	for_each_possible_cpu(cpu) {
		tx_map = &per_cpu(econ_tx_map, cpu);
		if (!hash_empty(tx_map->hash)) {
			hash_for_each(tx_map->hash, bkt, tx_entry, node) {
				if (tx_entry->sk == sk) {
					if (ECON_DEBUG)
						pr_info("econ_tx_remove: cpu=%d sk=%px\n",
							cpu, sk);
					hash_del(&tx_entry->node);
					kfree(tx_entry);
				}
			}
		}
	}
}
EXPORT_SYMBOL(econ_rx_remove);

void econ_rx_remove_all(void)
{
	int		      cpu, bkt;
	struct econ_rx_map   *map;
	struct econ_rx_entry *entry;
	struct econ_tx_map   *tx_map;
	struct econ_tx_entry *tx_entry;

	for_each_possible_cpu(cpu) {
		map = &per_cpu(econ_rx_map, cpu);
		if (!hash_empty(map->hash)) {
			hash_for_each(map->hash, bkt, entry, node) {
				if (ECON_DEBUG)
					pr_info("econ_rx_remove_all: cpu=%d sk=%px\n",
						cpu, entry->sk);
				hash_del(&entry->node);
				kfree(entry);
			}
		}
		map->timestamp = ktime_get_ns();
	}

	for_each_possible_cpu(cpu) {
		tx_map = &per_cpu(econ_tx_map, cpu);
		if (!hash_empty(tx_map->hash)) {
			hash_for_each(tx_map->hash, bkt, tx_entry, node) {
				if (ECON_DEBUG)
					pr_info("econ_tx_remove_all: cpu=%d sk=%px\n",
						cpu, tx_entry->sk);
				hash_del(&tx_entry->node);
				kfree(tx_entry);
			}
		}
		tx_map->timestamp = ktime_get_ns();
	}
}
EXPORT_SYMBOL(econ_rx_remove_all);

int econ_tx_insert(struct sk_buff *skb)
{
	struct econ_tx_entry *entry;
	struct econ_tx_map   *map;
	struct flow_keys      flow = { 0 };
	struct iphdr	     *ip;
	struct udphdr	     *udp;
	struct vxlanhdr	     *vxlan;
	u8		     *inner_eth;
	u32		      hash;

	// check if fastpath is enabled
	if (!ECON_ENABLED)
		return 1;

	// filter skb flow
	if (skb->inner_network_header < 50)
		return 2;

	// filter socket protocol
	if (!skb->econ_sk)
		return 3;
	if (skb->econ_sk->sk_prot != &tcp_prot && skb->econ_sk->sk_prot != &udp_prot)
		return 4;

	// compute flow hash
	ip = inner_ip_hdr(skb);
	if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP)
		return 5;
	udp = inner_udp_hdr(skb);
	/*
	if ((ntohs(udp->source) < 9000 || ntohs(udp->source) > 9999) &&
	    (ntohs(udp->dest) < 9000 || ntohs(udp->dest) > 9999))
		return 6;
	*/
	flow.control.flags = (u32)((u64)skb->econ_sk);
	flow.addrs.v4addrs.src = ip->saddr;
	flow.addrs.v4addrs.dst = ip->daddr;
	flow.basic.ip_proto = ip->protocol;
	flow.ports.src = udp->source;
	flow.ports.dst = udp->dest;
	hash = flow_hash_from_keys(&flow);

	// check outer header
	ip = ip_hdr(skb);
	udp = udp_hdr(skb);
	if (ip->protocol != IPPROTO_UDP && ntohs(udp->dest) != IANA_VXLAN_UDP_PORT)
		return 7;
	vxlan = vxlan_hdr(skb);
	inner_eth = ((u8 *)(vxlan)) + 8;

	// see if the given key already exists in the hashtable
	map = get_cpu_ptr(&econ_tx_map);
	// only allow if timestamp difference > 100ms
	if (ktime_get_ns() - map->timestamp < 100000000UL)
		goto skip;
	hash_for_each_possible(map->hash, entry, node, hash) {
		if (entry->key == hash)
			break;
	}
	// if key exists, save sk
	if (entry && entry->key == hash) {
		entry->sk = skb->econ_sk;
		entry->dev = skb->dev;
		memcpy(&entry->outer.eth, skb_mac_header(skb), sizeof(struct ethhdr));
		memcpy(&entry->outer.ip, ip, sizeof(*ip));
		memcpy(&entry->outer.udp, udp, sizeof(*udp));
		memcpy(&entry->outer.vxlan, vxlan, sizeof(*vxlan));
		memcpy(&entry->inner_mac_addrs[0], inner_eth, 12);
	// if key doesn't exist, add a new entry
	} else {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		entry->key = hash;
		entry->sk = skb->econ_sk;
		entry->dev = skb->dev;
		memcpy(&entry->outer.eth, skb_mac_header(skb), sizeof(struct ethhdr));
		memcpy(&entry->outer.ip, ip, sizeof(*ip));
		memcpy(&entry->outer.udp, udp, sizeof(*udp));
		memcpy(&entry->outer.vxlan, vxlan, sizeof(*vxlan));
		memcpy(&entry->inner_mac_addrs[0], inner_eth, 12);
		hash_add(map->hash, &entry->node, entry->key);
		if (ECON_DEBUG)
			pr_info("econ_tx_insert: [cpu %d] %x => %px, dev=%s, %pI4:%u > %pI4:%u, vni=%x\n",
				smp_processor_id(), entry->key, entry->sk,
				entry->dev ? entry->dev->name : "",
				&entry->outer.ip.saddr, ntohs(entry->outer.udp.source),
				&entry->outer.ip.daddr, ntohs(entry->outer.udp.dest),
				ntohl(vxlan_vni(vxlan_hdr(skb)->vx_vni)));
	}
skip:
	put_cpu_ptr(&econ_tx_map);
	return 0;
}
EXPORT_SYMBOL(econ_tx_insert);

static int econ_tx_add_outer_headers(struct sk_buff	  *skb,
				     struct econ_tx_entry *entry)
{
	struct iphdr *ip;
	struct udphdr *udp;
	u8 *inner_eth_hdr;
	u16 len;

	// make sure there's enough room
	if (skb_headroom(skb) < 50) {
		if (skb_cow(skb, 50))
			return -ENOMEM;
	}

	// update skb header pointers
	len = ntohs(ip_hdr(skb)->tot_len) + 50;
	skb_reset_inner_headers(skb);
	skb_set_inner_protocol(skb, htons(ETH_P_TEB));
	skb_push(skb, 50);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, 14);
	skb_set_transport_header(skb, 14 + 20);

	// copy outer header
	memcpy(skb_mac_header(skb), &entry->outer.eth, 14);
	memcpy(skb_network_header(skb), &entry->outer.ip, 20);
	memcpy(skb_transport_header(skb), &entry->outer.udp, 8 + 8);
	ip = ip_hdr(skb);
	udp = udp_hdr(skb);
	// replace inner mac addresses too
	inner_eth_hdr = ((u8*)udp) + 16;
	memcpy(inner_eth_hdr, &entry->inner_mac_addrs[0], 12);

	// compute a random ip->id
	get_random_bytes(&ip->id, sizeof(ip->id));

	// compute ip->len
	ip->tot_len = htons(len);

	// compute the ip->hdr_csum
	// skb->ip_summed = CHECKSUM_NONE;
	ip->check = 0;
	ip->check = ip_fast_csum(ip, ip->ihl);

	// compute udp->len
	len -= 20;
	udp->len = htons(len);

	// compute outer udp checksum
	udp_set_csum(false, skb, ip->saddr, ip->daddr, len);
	skb->encapsulation = 1;

	return 0;
}

int econ_xmit(struct sk_buff *skb)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct flow_keys flow = { 0 };
	u32 hash;
	struct econ_tx_map *map;
	struct econ_tx_entry *entry;
	int ret;

	skb->econ_sk = skb->sk;

	// compute flow hash
	ip = (struct iphdr *)skb_network_header(skb);
	if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP)
		return 1;
	udp = (struct udphdr *)skb_transport_header(skb);
	flow.control.flags = (u32)((u64)skb->sk);
	flow.addrs.v4addrs.src = ip->saddr;
	flow.addrs.v4addrs.dst = ip->daddr;
	flow.basic.ip_proto = ip->protocol;
	flow.ports.src = udp->source;
	flow.ports.dst = udp->dest;
	hash = flow_hash_from_keys(&flow);

	// check if xfp entry exists
	map = get_cpu_ptr(&econ_tx_map);
	hash_for_each_possible(map->hash, entry, node, hash) {
		if (entry->key == hash && entry->sk == skb->sk)
			break;
	}
	put_cpu_ptr(&econ_tx_map);
	// if flow is not cached, return failure
	if (!entry || entry->key != hash)
		return 2;

	// else, add outer headers and xmit
	if (econ_tx_add_outer_headers(skb, entry))
		return 3;
	skb_scrub_packet(skb, !net_eq(dev_net(skb->dev), dev_net(entry->dev)));
	skb->pkt_type = PACKET_OUTGOING;
	skb->dev = entry->dev;
	skb->econ_sk = skb->sk;
	skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL_CSUM;

	// outer netfilter hooks
	ret = nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT, dev_net(skb->dev), NULL, skb, skb->dev, NULL, NULL);
	if (ret != 1)
		return false;
	ret = nf_hook(NFPROTO_IPV4, NF_INET_POST_ROUTING, dev_net(skb->dev), NULL, skb, skb->dev, NULL, NULL);
	if (ret != 1)
		return false;

	// might need to rcu_read_lock() before dev_queue_xmit()
	rcu_read_lock();
	skb_tx_timestamp(skb); // timestamp skb
	dev_queue_xmit(skb);
	rcu_read_unlock();

	return 0;
}
EXPORT_SYMBOL(econ_xmit);

/*

Vanilla (slow path)
==========

[pNIC]
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep) -> eth -> ip (routing, nf) -> udp -> vxlan -> bridge

[bridge]
pkt -> eth (forward) -> vNIC

[vNIC]
pkt -> eth -> ip (routing, nf) -> tcp -> socket


Fast path
==========

[pNIC]
overlay pkt -> pkt -> gro
overlay pkt -> pkt -> gro
overlay pkt -> pkt -> gro
overlay pkt -> pkt -> gro
overlay pkt -> pkt -> gro
overlay pkt -> pkt -> gro
overlay pkt -> pkt -> gro
overlay pkt -> pkt -> gro -> tcp -> socket


Fast path (with pre-GRO hooks)
==========

[pNIC]
overlay pkt -> pkt -> nf -> gro
overlay pkt -> pkt -> nf -> gro
overlay pkt -> pkt -> nf -> gro
overlay pkt -> pkt -> nf -> gro
overlay pkt -> pkt -> nf -> gro
overlay pkt -> pkt -> nf -> gro
overlay pkt -> pkt -> nf -> gro
overlay pkt -> pkt -> nf -> gro -> tcp -> socket


Fast path (with deep GRO)
==========

[pNIC]
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep) -> pkt -> tcp -> socket


Fast path (with deep GRO + hooks)
==========

[pNIC]
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep)
overlay pkt -> gro (deep) -> nf -> pkt -> tcp -> socket

*/
