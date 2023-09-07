#include <linux/manish.h>
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

DEFINE_PER_CPU(struct manish_sk_map, manish_sk_map);
EXPORT_PER_CPU_SYMBOL(manish_sk_map);
DEFINE_PER_CPU(struct manish_xfp_map, manish_xfp_map);
EXPORT_PER_CPU_SYMBOL(manish_xfp_map);

int MANISH_FASTPATH = 1;	// fast path enabled by default
EXPORT_SYMBOL(MANISH_FASTPATH);

int MANISH_DEBUG = 0;	// debugging disabled by default
EXPORT_SYMBOL(MANISH_DEBUG);

u32 PNIC_NET = 0xc0a800; // 192.168.0
u32 VNIC_NET = 0x010000; // 1.0.0

inline bool manish_filter_parse_skb(const struct sk_buff *skb,
				    struct manish_pkt *pkt, bool deep)
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
	    ((ntohl(ip->daddr) >> 8) != VNIC_NET))
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

bool manish_filter_skb(const struct sk_buff *skb, bool deep)
{
	return manish_filter_parse_skb(skb, NULL, deep);
}
EXPORT_SYMBOL(manish_filter_skb);

void manish_print_skb(const struct sk_buff *skb, const char *fname)
{
	struct manish_pkt pkt;
	u16		  flags, offset;

	if (!MANISH_DEBUG)
		return;

	// only print shallow headers
	if (!manish_filter_parse_skb(skb, &pkt, false))
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
EXPORT_SYMBOL(manish_print_skb);

void inline manish_sk_map_init(int cpu)
{
	int		      bkt;
	struct manish_sk_map *map;

	if (MANISH_DEBUG)
		pr_info("===: initializing manish_sk_map on cpu %d\n", cpu);
	map = &per_cpu(manish_sk_map, cpu);
	for (bkt = 0; bkt < MANISH_SK_MAP_SIZE; bkt++)
		map->hash[bkt].first = NULL;
}

struct manish_sk_entry *manish_sk_lookup(const struct sk_buff *skb)
{
	struct manish_sk_entry *entry = NULL;
	struct manish_sk_map   *map   = get_cpu_ptr(&manish_sk_map);
	hash_for_each_possible(map->hash, entry, node, skb->hash) {
		if (entry->key == skb->hash)
			break;
	}
	put_cpu_ptr(&manish_sk_map);
	return entry;
}
EXPORT_SYMBOL(manish_sk_lookup);

void manish_sk_insert(struct sk_buff *skb, struct sock *sk)
{
	struct manish_sk_entry *entry;
	struct manish_sk_map   *map;

	if (skb_shinfo(skb)->frag_list)
		__skb_get_hash(skb);

	map = get_cpu_ptr(&manish_sk_map);
	// only allow if timestamp difference > 100ms
	if (ktime_get_ns() - map->timestamp < 100000000UL)
		goto skip;
	// see if the given key already exists in the hashtable
	hash_for_each_possible(map->hash, entry, node, skb->hash) {
		if (entry->key == skb->hash)
			break;
	}
	// if key exists, save sk
	if (entry && entry->key == skb->hash) {
		entry->sk = sk;
		entry->dev = skb->dev;
	// if key doesn't exist, add a new entry
	} else {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		entry->key = skb->hash;
		entry->sk = sk;
		entry->dev = skb->dev;
		hash_add(map->hash, &entry->node, entry->key);
		if (MANISH_DEBUG)
			pr_info("manish_sk_insert: [cpu %d] %x => %px (refcounted = %u)\n",
				smp_processor_id(), entry->key, entry->sk,
				sk_is_refcounted(sk));
	}
skip:
	put_cpu_ptr(&manish_sk_map);
}
EXPORT_SYMBOL(manish_sk_insert);

void manish_print_sk_map(struct seq_file *f)
{
	int			 cpu, bkt;
	struct manish_sk_map	*map;
	struct manish_sk_entry	*entry;
	struct manish_xfp_map	*xfp_map;
	struct manish_xfp_entry *xfp_entry;

	seq_printf(f, "\nRFP maps:\n=========\n");
	for_each_possible_cpu(cpu) {
		map = &per_cpu(manish_sk_map, cpu);
		if (!hash_empty(map->hash)) {
			seq_printf(f, "CPU %d:\n", cpu);
			hash_for_each(map->hash, bkt, entry, node) {
				seq_printf(
					f,
					"   %x => %px %s(%pI4:%u > %pI4:%u)\n",
					entry->key, entry->sk, entry->sk->sk_prot->name,
					&entry->sk->sk_daddr, ntohs(entry->sk->sk_dport),
					&entry->sk->sk_rcv_saddr, entry->sk->sk_num);
			}
		}
	}

	seq_printf(f, "\nXFP maps:\n=========\n");
	for_each_possible_cpu(cpu) {
		xfp_map = &per_cpu(manish_xfp_map, cpu);
		if (!hash_empty(xfp_map->hash)) {
			seq_printf(f, "CPU %d:\n", cpu);
			hash_for_each(xfp_map->hash, bkt, xfp_entry, node) {
				seq_printf(
					f,
					"   %x => %px %s(%pI4:%u > %pI4:%u) :: %pI4:%u > %pI4:%u, vni=%x\n",
					xfp_entry->key, xfp_entry->sk, xfp_entry->sk->sk_prot->name,
					&xfp_entry->sk->sk_rcv_saddr, xfp_entry->sk->sk_num,
					&xfp_entry->sk->sk_daddr, ntohs(xfp_entry->sk->sk_dport),
					&xfp_entry->outer.ip.saddr, ntohs(xfp_entry->outer.udp.source),
					&xfp_entry->outer.ip.daddr, ntohs(xfp_entry->outer.udp.dest),
					ntohl(vxlan_vni(xfp_entry->outer.vxlan.vx_vni)));
			}
		}
	}
}

/**
 *	Checks if packet is VXLAN, and removes outer headers if so.
 */
bool manish_receive_skb(struct sk_buff *skb)
{
	struct iphdr	       *ip;
	struct udphdr	       *udp;
	int			drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;
	struct manish_sk_entry *entry;

	if (skb->manish_sk)
		return false;

	entry = manish_sk_lookup(skb);
	if (!entry)
		return false;

	/* prevent socket lookup */
	skb->manish_sk = entry->sk;
	skb->manish_dev = entry->dev;
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

	return true;

ip_csum_error:
	drop_reason = SKB_DROP_REASON_IP_CSUM;
	goto drop;
drop:
	kfree_skb_reason(skb, drop_reason);
	return false;
}
EXPORT_SYMBOL(manish_receive_skb);

bool manish_deliver_skb(struct sk_buff *skb)
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
	skb->dev = skb->manish_dev;

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
		skb->dev = skb->manish_dev ?: skb->dev;
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
EXPORT_SYMBOL(manish_deliver_skb);

void manish_sk_remove(const struct sock *sk)
{
	int			 cpu, bkt;
	struct manish_sk_map	*map;
	struct manish_sk_entry	*entry;
	struct manish_xfp_map	*xfp_map;
	struct manish_xfp_entry *xfp_entry;

	/* remove sk entry */
	for_each_possible_cpu(cpu) {
		map = &per_cpu(manish_sk_map, cpu);
		if (!hash_empty(map->hash)) {
			hash_for_each(map->hash, bkt, entry, node) {
				if (entry->sk == sk) {
					if (MANISH_DEBUG)
						pr_info("manish_sk_remove: cpu=%d sk=%px\n",
							cpu, sk);
					hash_del(&entry->node);
					kfree(entry);
				}
			}
		}
	}

	/* remove xfp entry */
	for_each_possible_cpu(cpu) {
		xfp_map = &per_cpu(manish_xfp_map, cpu);
		if (!hash_empty(xfp_map->hash)) {
			hash_for_each(xfp_map->hash, bkt, xfp_entry, node) {
				if (xfp_entry->sk == sk) {
					if (MANISH_DEBUG)
						pr_info("manish_xfp_remove: cpu=%d sk=%px\n",
							cpu, sk);
					hash_del(&xfp_entry->node);
					kfree(xfp_entry);
				}
			}
		}
	}
}
EXPORT_SYMBOL(manish_sk_remove);

void manish_sk_remove_all(void)
{
	int			 cpu, bkt;
	struct manish_sk_map	*map;
	struct manish_sk_entry	*entry;
	struct manish_xfp_map	*xfp_map;
	struct manish_xfp_entry *xfp_entry;

	for_each_possible_cpu(cpu) {
		map = &per_cpu(manish_sk_map, cpu);
		if (!hash_empty(map->hash)) {
			hash_for_each(map->hash, bkt, entry, node) {
				if (MANISH_DEBUG)
					pr_info("manish_sk_remove_all: cpu=%d sk=%px\n",
						cpu, entry->sk);
				hash_del(&entry->node);
				kfree(entry);
			}
		}
		map->timestamp = ktime_get_ns();
	}

	for_each_possible_cpu(cpu) {
		xfp_map = &per_cpu(manish_xfp_map, cpu);
		if (!hash_empty(xfp_map->hash)) {
			hash_for_each(xfp_map->hash, bkt, xfp_entry, node) {
				if (MANISH_DEBUG)
					pr_info("manish_xfp_remove_all: cpu=%d sk=%px\n",
						cpu, xfp_entry->sk);
				hash_del(&xfp_entry->node);
				kfree(xfp_entry);
			}
		}
		xfp_map->timestamp = ktime_get_ns();
	}
}
EXPORT_SYMBOL(manish_sk_remove_all);

void manish_xfp_insert(struct sk_buff *skb)
{
	struct manish_xfp_entry *entry;
	struct manish_xfp_map	*map;
	struct flow_keys	 flow = { 0 };
	struct iphdr		*ip;
	struct udphdr		*udp;
	struct vxlanhdr		*vxlan;
	u32			 hash;

	// check if fastpath is enabled
	if (!MANISH_FASTPATH)
		return;

	// filter skb flow
	if (skb->inner_network_header < 50)
		return;

	// filter socket protocol
	if (!skb->sk)
		return;
	if (skb->sk->sk_prot != &tcp_prot && skb->sk->sk_prot != &udp_prot)
		return;

	// compute flow hash
	ip = inner_ip_hdr(skb);
	if (ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_TCP)
		return;
	udp = inner_udp_hdr(skb);
	if ((ntohs(udp->source) < 9000 || ntohs(udp->source) > 9999) &&
	    (ntohs(udp->dest) < 9000 || ntohs(udp->dest) > 9999))
		return;
	flow.control.flags = (u32)((u64)skb->sk);
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
		return;
	vxlan = vxlan_hdr(skb);

	// see if the given key already exists in the hashtable
	map = get_cpu_ptr(&manish_xfp_map);
	// only allow if timestamp difference > 100ms
	if (ktime_get_ns() - map->timestamp < 100000000UL)
		goto skip;
	hash_for_each_possible(map->hash, entry, node, hash) {
		if (entry->key == hash)
			break;
	}
	// if key exists, save sk
	if (entry && entry->key == hash) {
		entry->sk = skb->sk;
		entry->dev = skb->dev;
		memcpy(&entry->outer.eth, skb_mac_header(skb), sizeof(struct ethhdr));
		memcpy(&entry->outer.ip, ip, sizeof(*ip));
		memcpy(&entry->outer.udp, udp, sizeof(*udp));
		memcpy(&entry->outer.vxlan, vxlan, sizeof(*vxlan));
	// if key doesn't exist, add a new entry
	} else {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		entry->key = hash;
		entry->sk = skb->sk;
		entry->dev = skb->dev;
		memcpy(&entry->outer.eth, skb_mac_header(skb), sizeof(struct ethhdr));
		memcpy(&entry->outer.ip, ip, sizeof(*ip));
		memcpy(&entry->outer.udp, udp, sizeof(*udp));
		memcpy(&entry->outer.vxlan, vxlan, sizeof(*vxlan));
		hash_add(map->hash, &entry->node, entry->key);
		if (MANISH_DEBUG)
			pr_info("manish_xfp_insert: [cpu %d] %x => %px, dev=%s, %pI4:%u > %pI4:%u, vni=%x\n",
				smp_processor_id(), entry->key, entry->sk,
				entry->dev ? entry->dev->name : "",
				&entry->outer.ip.saddr, ntohs(entry->outer.udp.source),
				&entry->outer.ip.daddr, ntohs(entry->outer.udp.dest),
				ntohl(vxlan_vni(vxlan_hdr(skb)->vx_vni)));
	}
skip:
	put_cpu_ptr(&manish_xfp_map);
}
EXPORT_SYMBOL(manish_xfp_insert);

static int manish_xfp_add_outer_headers(struct sk_buff		*skb,
					struct manish_xfp_entry *entry)
{
	struct iphdr *ip;
	struct udphdr *udp;
	u16 len;

	// make sure there's enough room
	if (skb_headroom(skb) < 50)
		return -ENOMEM;

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

int manish_xfp_xmit(struct sk_buff *skb)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct flow_keys flow = { 0 };
	u32 hash;
	struct manish_xfp_map *map;
	struct manish_xfp_entry *entry;

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
	map = get_cpu_ptr(&manish_xfp_map);
	hash_for_each_possible(map->hash, entry, node, hash) {
		if (entry->key == hash && entry->sk == skb->sk)
			break;
	}
	put_cpu_ptr(&manish_xfp_map);
	// if flow is not cached, return failure
	if (!entry || entry->key != hash)
		return 2;

	// inner netfilter hooks

	// else, add outer headers and xmit
	if (manish_xfp_add_outer_headers(skb, entry))
		return 3;
	skb_scrub_packet(skb, !net_eq(dev_net(skb->dev), dev_net(entry->dev)));
	skb->pkt_type = PACKET_OUTGOING;
	skb->dev = entry->dev;
	skb->manish_sk = skb->sk;
	skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_TUNNEL_CSUM;

	// inner netfilter hooks

	// might need to rcu_read_lock() before dev_queue_xmit()
	rcu_read_lock();
	skb_tx_timestamp(skb); // timestamp skb
	dev_queue_xmit(skb);
	rcu_read_unlock();

	return 0;
}
EXPORT_SYMBOL(manish_xfp_xmit);

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
