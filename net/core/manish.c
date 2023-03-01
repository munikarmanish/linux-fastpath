#include <linux/manish.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <net/busy_poll.h>
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

int MANISH_DEBUG = 0;	// debugging disabled by default
EXPORT_SYMBOL(MANISH_DEBUG);

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
	// daddr must be 192.168.1.1 or 10.0.1.10
	if (ntohl(ip->daddr) != 0xc0a80101 && ntohl(ip->daddr) != 0x0a00010a)
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

inline bool manish_filter_skb(const struct sk_buff *skb, bool deep)
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

	// if (ip_is_fragment(ip)) {
	// 	head = skb_shinfo(skb)->frag_list;
	// 	while (head) {
	// 		manish_filter_parse_skb(skb, &eth, &ip, NULL);
	// 		pr_info("%s: [%px]\n"
	// 			" frag: data=%ld, tail=%u, end=%u, len=%u, datalen=%u, hash=%x\n"
	// 			"       L2=%u, L3=%u, L4=%u, dev=%s\n"
	// 			"   ip: %pI4 > %pI4, len=%u, prot=%x, flag=%x, off=%u, id=%x\n",
	// 			fname, skb, skb->data - skb->head, skb->tail, skb->end, skb->len, skb->data_len, skb->hash,
	// 			skb->mac_header, skb->network_header, skb->transport_header, skb->dev? skb->dev->name: "NULL",
	// 			&ip->saddr, &ip->daddr, ntohs(ip->tot_len), ip->protocol, flags, offset, ntohs(ip->id));
	// 		head = head->next;
	// 	}
	// }
}
EXPORT_SYMBOL(manish_print_skb);


void inline manish_sk_map_init(int cpu)
{
	int		      bkt;
	struct manish_sk_map *map;

	if (MANISH_DEBUG)
		pr_info("===: initializing sk_map on cpu %d\n", cpu);
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

void manish_sk_insert(const struct sk_buff *skb, struct sock *sk)
{
	struct manish_sk_entry *entry;
	struct manish_sk_map   *map;

	map = get_cpu_ptr(&manish_sk_map);
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
	put_cpu_ptr(&manish_sk_map);
}
EXPORT_SYMBOL(manish_sk_insert);


void manish_print_sk_map(struct seq_file *f)
{
	int			cpu, bkt;
	struct manish_sk_map   *map;
	struct manish_sk_entry *entry;

	for_each_possible_cpu(cpu) {
		map = &per_cpu(manish_sk_map, cpu);
		if (!hash_empty(map->hash)) {
			seq_printf(f, "CPU %d:\n", cpu);
			hash_for_each(map->hash, bkt, entry, node) {
				seq_printf(f, "   %x => %px\n",
					   entry->key, entry->sk);
			}
		}
	}
}


int manish_receive_skb(struct sk_buff *skb, struct manish_sk_entry *entry)
{
	struct ethhdr *eth;
	struct iphdr  *ip;
	struct udphdr *udp;
	int	       drop_reason = SKB_DROP_REASON_NOT_SPECIFIED;

start_from_l2:
	// skb->data points to L3 header
	eth = (struct ethhdr *)(skb->head + skb->mac_header);
	skb->network_header =  skb->mac_header + ETH_HLEN;

	ip = ip_hdr(skb);
	if (!pskb_may_pull(skb, ip->ihl*4))
		goto drop;
	if (unlikely(ip_fast_csum((u8 *)ip, ip->ihl)))
		goto ip_csum_error;
	if (pskb_trim_rcsum(skb, ntohs(ip->tot_len)))
		goto drop;
	ip = ip_hdr(skb);
	skb->transport_header = skb->network_header + ip->ihl*4;
	// Remove any debris in the socket control block
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->iif = skb->skb_iif;

	__skb_pull(skb, skb_network_header_len(skb));
	skb_postpull_rcsum(skb, skb_network_header(skb), skb_network_header_len(skb));

	// check if vxlan
	udp = udp_hdr(skb);
	if (ip->protocol == IPPROTO_UDP && ntohs(udp->dest) == IANA_VXLAN_UDP_PORT) {
		skb->mac_header = skb->transport_header + 8 + 8;
		__skb_pull(skb, 8 + 8 + 14); // udp + vxlan + eth
		skb_postpull_rcsum(skb, skb_transport_header(skb), 8 + 8 + 14);
		goto start_from_l2;
	}

	// prevent socket lookup
	skb->manish_sk = entry->sk;
	skb->dev = entry->dev;
	skb->skb_iif = entry->dev->ifindex;

	// avoid checksum issue
	// skb->csum_complete_sw = 1;

	// if (ip_is_fragment(ip_hdr(skb))) {
	// 	return -EINVAL;
	// 	// struct net *net = dev_net(skb->dev);
	// 	// if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
	// 	// 	return 0;
	// }

	// directly calling udp_rcv() works (with a minor modification, see
	// __udp4_lib_rcv+60)
	rcu_read_lock();
	if (ip->protocol == IPPROTO_UDP)
		udp_rcv(skb);
	else if (ip->protocol == IPPROTO_TCP)
		tcp_v4_rcv(skb);
	rcu_read_unlock();

	return 0;

ip_csum_error:
	drop_reason = SKB_DROP_REASON_IP_CSUM;
	goto drop;
drop:
	kfree_skb_reason(skb, drop_reason);
	return 0;
}
EXPORT_SYMBOL(manish_receive_skb);

void manish_sk_remove(const struct sock *sk)
{
	int			cpu, bkt;
	struct manish_sk_map   *map;
	struct manish_sk_entry *entry;

	for_each_possible_cpu(cpu) {
		map = &per_cpu(manish_sk_map, cpu);
		if (!hash_empty(map->hash)) {
			hash_for_each(map->hash, bkt, entry, node) {
				if (entry->sk == sk) {
					if (MANISH_DEBUG)
						pr_info("manish_sk_remove: cpu=%d sk=%px\n", cpu, sk);
					hash_del(&entry->node);
				}
			}
		}
	}
}
EXPORT_SYMBOL(manish_sk_remove);

void manish_sk_remove_all(void)
{
	int			cpu, bkt;
	struct manish_sk_map   *map;
	struct manish_sk_entry *entry;

	for_each_possible_cpu(cpu) {
		map = &per_cpu(manish_sk_map, cpu);
		if (!hash_empty(map->hash)) {
			hash_for_each(map->hash, bkt, entry, node) {
				if (MANISH_DEBUG)
					pr_info("manish_sk_remove_all: cpu=%d sk=%px\n", cpu, entry->sk);
				hash_del(&entry->node);
			}
		}
	}
}
EXPORT_SYMBOL(manish_sk_remove_all);
