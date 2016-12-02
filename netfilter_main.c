//'Hello World' netfilter hooks example based a three-part blog by Paul Kiddie
//   www.paulkiddie.com/2009/10/creating-a-simple-hello-world-netfilter-module/
// and modified by K Shomper for linux 4.4 assignment in CS3320.  Dec 1, 2016.
// TODO 1: include your own information and date of modification.

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/string.h>

#define NF_IP_LOCAL_IN    1
#define NF_IP_LOCAL_OUT   3

#define PROTOCOL_ICMP     1

struct iphdr *ip_header;

/* Convinience union to convert __be32 to individual octets */
union ip_address {
    u8     a[4];
    __be32 addr;
};

//function to be called by nfho hook operations
unsigned int hook_funco(void *priv, struct sk_buff *skb, 
							  const struct nf_hook_state *state) {

	//grab network header using accessor
	ip_header = NULL; // TODO 2:  replace NULL with applicable code ... 
       
	if (ip_header->protocol == PROTOCOL_ICMP) {
   	//log to dmesg queue indicating an outbound ICMP packet was discovered 
		// TODO 3: create message here ...
	}

   //allows the packet to proceed
   return 0; // TODO 4: replace 0 with proper define to keep packet ...
}

//function to be called by nfhi hook operations
unsigned int hook_funci(void *priv, struct sk_buff *skb, 
							  const struct nf_hook_state *state) {

	//grab network header using accessor
	ip_header = NULL; // TODO 5: replace NULL with applicable code ... 
       
 	//grab the incoming ip address
	char buf[20];
	union ip_address ip;
   ip.addr = 0; // TODO 6: replace 0 with actual ip address from skb ... 

	// convert the __be32 address to a typical dotted-notation IP address
	snprintf(buf, 20, "%d.%d.%d.%d", ip.a[0], ip.a[1], ip.a[2], ip.a[3]);

	// if the ICMP packet is from telehack
	if (ip_header->protocol==PROTOCOL_ICMP && 
		 strncmp(buf, "TODO 7: fill-in-IP-address-for-telehack.com", 20)) {
   	//log to dmesg queue 
   	printk(KERN_WARNING "incoming ICMP packet allowed from telehack.com\n");
	} else {
   	//log to dmesg queue 
   	printk(KERN_WARNING "incoming ICMP packet allowed from elsewhere");
	}

   //allows the packet to proceed
   return 0; // TODO 8: replace 0 with proper define to keep packet ...
}

//struct holding set of hook function options for outbound packets
static struct nf_hook_ops nfho = {
  .hook     = hook_funco,           //function to call when conditions below met
  .hooknum  = NF_IP_LOCAL_OUT,      //call before packet sent
  .pf       = PF_INET,              //IPV4 packets
  .priority = NF_IP_PRI_FIRST       //set highest priority over other hook funcs
};

//struct holding set of hook function options for inbound packets
static struct nf_hook_ops nfhi = {
  .hook     = hook_funci,           //function to call when conditions below met
  .hooknum  = NF_IP_LOCAL_IN,       //call before packet recieved
  .pf       = PF_INET,              //IPV4 packets
  .priority = NF_IP_PRI_FIRST       //set highest priority over other hook funcs
};

//Called when module loaded using 'insmod'
int init_module() {
   printk(KERN_WARNING "registering net filter\n");
   // TODO 9:  register hooks
   printk(KERN_WARNING "registered net filter\n");

   //return 0 for success
   return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module() {
   printk(KERN_WARNING "unregistering net filter\n");
   // TODO 10:  unregister hooks
   printk(KERN_WARNING "unregistered net filter\n");
}

MODULE_AUTHOR("K. Shomper based on work by P. Kiddie");
MODULE_LICENSE("GPL");
