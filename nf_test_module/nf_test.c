#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPLv3");
MODULE_AUTHOR("Hao JIN");
MODULE_DESCRIPTION("Netfliter Checksum Test");

char client[15] = "192.168.1.11";
char server[15] = "192.168.1.13";

unsigned int ip_str_to_num(const char *buf)
{
    unsigned int tmpip[4] = {0};
    unsigned int tmpip32 = 0;
    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);
    tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];
    return tmpip32;
}

static unsigned int
nf_test_out_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
                const struct net_device *out, int (*okfn)(struct sk_buff*));

static struct nf_hook_ops nf_test_ops[] __read_mostly = {
  {
    .hook = nf_test_out_hook,
    .owner = THIS_MODULE,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
  },
};
    
void hdr_dump(struct ethhdr *ehdr) {
    /*
    printk("[DMAC:%x:%x:%x:%x:%x:%x	SMAC: %x:%x:%x:%x:%x:%x	    Protype:%x]\n",
           ehdr->h_dest[0],ehdr->h_dest[1],ehdr->h_dest[2],ehdr->h_dest[3],
           ehdr->h_dest[4],ehdr->h_dest[5],ehdr->h_source[0],ehdr->h_source[1],
           ehdr->h_source[2],ehdr->h_source[3],ehdr->h_source[4],
           ehdr->h_source[5],ehdr->h_proto);
`   */
}

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

static unsigned int
nf_test_out_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
                const struct net_device *out, int (*okfn)(struct sk_buff*)) {
  struct ethhdr *eth_header;
  struct iphdr *ip_header;
  struct tcphdr *tcp_header;
  int lay4_len;
  int tcp_checksum = -1;

  eth_header = (struct ethhdr *)(skb_mac_header(skb));
  ip_header = (struct iphdr *)(skb_network_header(skb));
  tcp_header = (struct tcphdr *) (tcp_hdr(skb));
  lay4_len = skb->len - (ip_header->ihl << 2);
  
  if(ip_header->saddr == ip_str_to_num(client) && ip_header->daddr == ip_str_to_num(server)) {
      //printk(KERN_INFO "skb->len:%u skb->data_len:%u\n",skb->len, skb->data_len);
      hdr_dump(eth_header);
      ip_header->tos = 0xe0;
      printk("src IP:'"NIPQUAD_FMT"', dst IP:'"NIPQUAD_FMT"' \n",
             NIPQUAD(ip_header->saddr), NIPQUAD(ip_header->daddr));
      tcp_header->res1 = 0x0f;
      tcp_header->check = 0;
      tcp_checksum = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, lay4_len, IPPROTO_TCP, csum_partial(tcp_header, lay4_len, 0));
      
      if (tcp_checksum != 0) {
	printk("TCP Checksum is %x\n", tcp_checksum);
      }
      tcp_header->check = tcp_checksum;
      skb->ip_summed =CHECKSUM_NONE;
      /*Recalculate IPCheckSum*/
      //ip_send_check(ip_header);             //implicit declaration of function ‘ip_send_check’
      ip_header->check = 0;
      ip_header->check = ip_fast_csum((unsigned char *) ip_header, ip_header->ihl);
  }
  return NF_ACCEPT;
}

static int __init init_nf_test(void) {
  int ret;
  ret = nf_register_hooks(nf_test_ops, ARRAY_SIZE(nf_test_ops));
  if (ret < 0) {
    printk("register nf hook fail\n");
    return ret;
  }
  printk(KERN_NOTICE "register nf test hook\n");
  return 0;
}

static void __exit exit_nf_test(void) {
  nf_unregister_hooks(nf_test_ops, ARRAY_SIZE(nf_test_ops));
}

module_init(init_nf_test);
module_exit(exit_nf_test);
