#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

struct etherheader{
	unsigned char srcmac[6];
	unsigned char dstmac[6];
	uint16_t type;
};
struct ip_header{
	unsigned char version[1];
	unsigned char SerField[1];
	unsigned char length[2];
	unsigned char identification[2];
	unsigned char flag[2];
	unsigned char ttl[1];
	unsigned char proto[1];
	unsigned char headersum[2];
	unsigned char dstip[4];
	unsigned char srcip[4];
};
struct arp_header{
	//28bytes
  uint16_t type;
  uint16_t proto;
  uint8_t hardsize;
  uint8_t prosize;
  uint16_t opcode;
  unsigned char srcmac[6];
  unsigned char srcip[4];
  unsigned char dstmac[6];
  unsigned char dstip[4];
};
struct tcp_header{
	u_short src_port;
	u_short dst_port;
	unsigned char seqnum[4];
	unsigned char dstnum[4];
	unsigned char flag[2];
	unsigned char windowsize[2];
	unsigned char checksum[2];
	unsigned char urgent_pointer[2];
};
struct udp_header{
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
};


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  char* dev = argv[1];
  //char* dev = "enp0s3";
  char errbuf[PCAP_ERRBUF_SIZE];
  uint16_t iptype;
  int iplength;
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  //int i = 1;	
  while (1) {

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    struct etherheader *eth =(struct etherheader*)packet;
    packet += sizeof(etherheader);
    printf("#----------------------------------------------------------------------#\n");
    printf("\t\t\t [datalink layer : ethernet type]\n");
	
    printf("srcmac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->srcmac[0],eth->srcmac[1],eth->srcmac[2],eth->srcmac[3],eth->srcmac[4],eth->srcmac[5]);
    printf("dstmac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dstmac[0],eth->dstmac[1],eth->dstmac[2],eth->dstmac[3],eth->dstmac[4],eth->dstmac[5]);
    printf("type : %x\n", ntohs(eth->type));

    if(ntohs(eth->type)==0x800){
    //printf("#----------------------------------------------------------------------#\n");	
	  printf("\t\t\t [network layer : ipv4 type]\n");
  	struct ip_header *ip = (struct ip_header*)packet;
    packet+= sizeof(ip_header);
    printf("srcip : %d.%d.%d.%d\n", ip->srcip[0],ip->srcip[1],ip->srcip[2],ip->srcip[3]);
  	printf("dstip : %d.%d.%d.%d\n", ip->dstip[0],ip->dstip[1],ip->dstip[2],ip->dstip[3]);
         
  	printf("version : %.01x\n", ip->version[0]);
  	iptype = ip->proto[0];
  	//iplength = (ip->length[1] << 8) + ip->length[0];
  	//iplength=(ip->length[0])+(ip->length[1]);
    iplength=(ip->length[0] << 8) +ip->length[1];
    printf("ip length : %d\n", (iplength));
    
    printf("iptype : %d\n",(iptype));
                  if((iptype)==6){
              	printf("\t\t\t [transport layer : tcp]\n");
              	//printf("-----------------------------------------------------------------------\n");
                  	struct tcp_header *tcp = (struct tcp_header*)packet;
                  	printf("Src port: %d\n", ntohs(tcp->src_port));
                  	printf("dst port: %d\n", ntohs(tcp->dst_port));
              	    printf("length :  %d\n", iplength-34);
                  }
                  if((iptype)==17){
              	    printf("\t\t\t [transport layer : udp]\n");
              //	printf("-----------------------------------------------------------------------\n");
                  	
                  	struct udp_header *udp = (struct udp_header*)packet;
                  	printf("Src port: %d\n", ntohs(udp->src_port));
                  	printf("dst port: %d\n", ntohs(udp->dst_port));
                  	printf("length :  %d\n", ntohs(udp->length));
                }
}
    if(ntohs(eth->type)==0x806){              
    printf("\t\t\t [network layer : arp type]\n");
    struct arp_header *arp = (struct arp_header*)packet;
    packet+= sizeof(ip_header);
    printf("srcmac : %02x:%02x:%02x:%02x:%02x:%02x\n", arp->srcmac[0],arp->srcmac[1],arp->srcmac[2],eth->srcmac[3],eth->srcmac[4],eth->srcmac[5]);
    printf("srcip : %d.%d.%d.%d\n", arp->srcip[0],arp->srcip[1],arp->srcip[2],arp->srcip[3]);
    printf("dstmac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dstmac[0],eth->dstmac[1],eth->dstmac[2],eth->dstmac[3],eth->dstmac[4],eth->dstmac[5]);
    printf("dstip : %d.%d.%d.%d\n", arp->dstip[0],arp->dstip[1],arp->dstip[2],arp->dstip[3]);



  }
    
    
    unsigned int test=( header -> caplen);
    /* 
    for(int j=0; j<test; j++)
    {
	    printf("%x ", packet[j]);
    }*/
    printf("%d bytes captured\n", header->caplen);
    printf("#----------------------------------------------------------------------#\n");	
	  
  }

  pcap_close(handle);
  return 0;
}
