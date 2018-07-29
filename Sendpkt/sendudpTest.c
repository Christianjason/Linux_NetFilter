#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/seq_file_net.h>
#include <net/route.h>
#include <net/ip.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#define ICMP 1
#define ETH "eth0"
#define S_PORT 39888
#define D_PORT 8899
u_long S_IP = 0xC0A8034D; //"192.168.3.77"
u_long D_IP = 0xC0A80305; //"192.168.3.5"
unsigned char S_MAC[ETH_ALEN]={0x00,0x0c,0x29,0x41,0x3e,0x66};
unsigned char D_MAC[ETH_ALEN]={0x14,0xa5,0x1a,0xba,0xf1,0x04};

static int my_diyudp_and_send(char *eth, u_char *smac, u_char *dmac,
			u_char *pkt, int pkt_len,u_long sip, u_long dip, u_short sport, u_short dport)
{
	int ret = -1;
	unsigned int pktSize;
	struct sk_buff *skb = NULL;
	struct net_device *dev = NULL;
	struct ethhdr *ethheader = NULL;
	struct iphdr *ipheader = NULL;
	struct udphdr *udpheader = NULL;
	u_char *pdata = NULL;

	/*参数合法性检查*/
	if(NULL == smac || NULL == dmac)
		goto out;
	
	dev = dev_get_by_name(&init_net, eth);
	if(NULL == dev)
	{
		printk(KERN_ERR "unknow device name:%s\n", eth);
		goto out;
	}
	pktSize = pkt_len + sizeof(struct iphdr) + sizeof(struct udphdr) + LL_RESERVED_SPACE(dev);
	skb = alloc_skb(pktSize, GFP_ATOMIC);
	if(NULL == skb)
	{
		printk(KERN_ERR "malloc skb fail\n");
		goto out;
	}
	
	/*在头部预留需要的空间*/
	skb_reserve(skb, LL_RESERVED_SPACE(dev)+sizeof(struct iphdr));
	
	skb->dev = dev;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = __constant_htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_NONE;//udp校验和初始化
	skb->priority = 0;

	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	
	skb_put(skb, sizeof(struct udphdr));
	skb_set_transport_header(skb, sizeof(struct iphdr));

	pdata = skb_put(skb, pkt_len);
	if(NULL != pkt)
		memcpy(pdata, pkt, pkt_len);

	/*填充udp头部*/
	udpheader = (struct udphdr*)skb->transport_header;
	memset(udpheader, 0, sizeof(struct udphdr));
	udpheader->source = htons(sport);
	udpheader->dest = htons(dport);
	skb->csum = 0;
	udpheader->len = htons(sizeof(struct udphdr) + pkt_len);
	udpheader->check = 0;

	/*填充IP头*/
	ipheader = (struct iphdr*)skb->network_header;
	ipheader->version = 4;
	ipheader->ihl = sizeof(struct iphdr) >> 2;//ip头部长度
	ipheader->frag_off = 0;
	ipheader->protocol = IPPROTO_UDP;
	ipheader->tos = 0;
	ipheader->saddr = htonl(sip);
	ipheader->daddr = htonl(dip);
	ipheader->ttl = 0x40;
	ipheader->tot_len = htons(pkt_len + sizeof(struct iphdr) + sizeof(struct udphdr));
	ipheader->check = 0;
	ipheader->check = ip_fast_csum((unsigned char *)ipheader, ipheader->ihl);
	
	skb->csum = skb_checksum(skb, ipheader->ihl*4, skb->len-ipheader->ihl*4, 0);
	udpheader->check = csum_tcpudp_magic(sip, dip, skb->len-ipheader->ihl*4, IPPROTO_UDP, skb->csum);

	/*填充MAC*/
	ethheader = (struct ethhdr*)skb_push(skb, 14);
	memcpy(ethheader->h_dest, dmac, ETH_ALEN);
	memcpy(ethheader->h_source, smac, ETH_ALEN);
	ethheader->h_proto = __constant_htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	
	/*send pkt*/
	if(0 > dev_queue_xmit(skb))
	{
		printk(KERN_ERR "send pkt error");
		goto out;
	}
	ret = 0;
	
	printk(KERN_INFO "send success\n");
out:
	if(ret != 0 && NULL != skb)
	{
		dev_put(dev);
		kfree_skb(skb);
	}
	return NF_ACCEPT;

}
#if 1
static int pktcnt = 0;
static unsigned int my_hook_test(unsigned int hooknum, struct sk_buff *skb, 
	const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	const struct iphdr *iph = ip_hdr(skb);
	//filter icmp	
	if(iph->protocol == ICMP)
	{
		printk(KERN_INFO "recv pkt(%u):protocol:%u, Src:%u.%u.%u.%u, Dst:%u.%u.%u.%u\n",
			pktcnt, iph->protocol, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
		
		atomic_inc(&pktcnt);
		if(pktcnt%4 == 0)
		{
			printk(KERN_INFO "%d: drop an ICMP pkt to %u.%u.%u.%u\n", pktcnt, NIPQUAD(iph->daddr));
			my_diyudp_and_send(ETH, S_MAC, D_MAC, "Hello From Slackware", strlen("Hello From Slackware"), S_IP, D_IP, S_PORT, D_PORT);
			
			return NF_STOLEN;
		}
	}

	return NF_ACCEPT;
}
#endif

//?
static struct nf_hook_ops nfhello = {
		.hook = my_hook_test,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,//挂载在开始本地处理报文的节点
		.priority = NF_IP_PRI_FIRST,//最高优先级
};

static int my_netfilter_init(void)
{
	printk(KERN_INFO "init my nodule\n");
	nf_register_hook(&nfhello);

	return 0;
}

static void my_netfilter_exit(void)
{
	printk(KERN_INFO "Goodbye my module\n");
	nf_unregister_hook(&nfhello);
}

module_init(my_netfilter_init);
module_exit(my_netfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhaojie");

MODULE_DESCRIPTION("Hello netfilter");

