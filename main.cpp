#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PUSH 0x18
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80

//flag 선언 


//이더넷 헤더
struct etherheader{  
	unsigned char srcmac[6];
	unsigned char dstmac[6];
	uint16_t type;
};

//ip header
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

//arp header
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

//tcp_header

struct tcp_header{
	u_short src_port;
	u_short dst_port;
	unsigned char seqnum[4];
	unsigned char dstnum[4];
  u_char offx2;
  #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char flag;
	unsigned char windowsize[2];
	unsigned char checksum[2];
	unsigned char urgent_pointer[2];
};

//udp_header
struct udp_header{
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
};

struct tcp_option_t{

  uint8_t kind;
  uint8_t size;
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
  uint16_t mss;
  int t_option_check;
  char dataset[16];
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
    unsigned int test=( header -> caplen);
    struct etherheader *eth =(struct etherheader*)packet; //ethernet 구조체 삽입
    packet += sizeof(etherheader);
    printf("#----------------------------------------------------------------------#\n");
    printf("\t\t\t [datalink layer : ethernet type]\n");
	
    printf("srcmac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->srcmac[0],eth->srcmac[1],eth->srcmac[2],eth->srcmac[3],eth->srcmac[4],eth->srcmac[5]);
    printf("dstmac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dstmac[0],eth->dstmac[1],eth->dstmac[2],eth->dstmac[3],eth->dstmac[4],eth->dstmac[5]);
    printf("type : %x\n", ntohs(eth->type));

    if(ntohs(eth->type)==0x800){
    //printf("#----------------------------------------------------------------------#\n");	
	  printf("\t\t\t [network layer : ipv4 type]\n");
  	struct ip_header *ip = (struct ip_header*)packet; //ipv4 구조체 삽입
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
                  if((iptype)==6){    //tcp, udp 구분
              	printf("\t\t\t [transport layer : tcp]\n");
              	//printf("-----------------------------------------------------------------------\n");
                  	struct tcp_header *tcp = (struct tcp_header*)packet;
                  	printf("Src port: %d\n", ntohs(tcp->src_port));
                  	printf("dst port: %d\n", ntohs(tcp->dst_port));
              	    printf("length :  %d\n", iplength-34);
                    //printf("tcp flag: %d\n", ntohs(tcp->flag));
                    printf("flag :");
                    if(tcp->flag & FIN){
                      printf(" FIN");
                    }
                    if(tcp->flag & SYN){
                      t_option_check+=2;
                      printf(" SYN");
                    }
                    if(tcp->flag & RST){
                      printf(" RST");
                    }
                    if(tcp->flag & PUSH){
                      printf(" PUSH");
                    }
                    if(tcp->flag & ACK){
                      t_option_check+=10;
                      printf(" ACK");
                    }
                    if(tcp->flag & URG){
                      printf(" URG");
                    }
                    if(tcp->flag & ECE){
                      printf(" ECE");
                    }
                    if(tcp->flag & CWR){
                      printf(" CWR  ");
                    }
                    if(t_option_check!=0)
                    {
                      
                      if(t_option_check==2)
                      {
                        printf("option length : ");
                        packet+=20;
                        printf("20 bytes");
                      }
                      if(t_option_check==12)
                      {
                        printf("option length : ");
                        packet+=4;
                        printf("4 bytes");
                      }
                      t_option_check=0;
                      printf("\n");
                      //16bytes
                      printf("yes options\n"); 
                      
                    
                      
                    }
                    else
                    {
                      printf("no options\n"); 
                      
                    /*
                    while( *opt !=0){
                      tcp_option_t* t_opt = (tcp_option_t*)opt;
                      if(t_opt->kind== 1)
                      {
                        ++opt;
                        continue;
                      }
                      if(t_opt->kind==2){
                        mss = ntohs((uint16_t)*(opt + sizeof(opt)));
                      }
                      opt += t_opt->size;
                    }
                    printf("mss %s\n", mss);
                    printf("opt what %x\n", opt);|
                    */
                  }
                }
                  if((iptype)==17){ //udp확인
              	    printf("\t\t\t [transport layer : udp]\n");
              //	printf("-----------------------------------------------------------------------\n");
                  	
                  	struct udp_header *udp = (struct udp_header*)packet;
                  	printf("Src port: %d\n", ntohs(udp->src_port));
                  	printf("dst port: %d\n", ntohs(udp->dst_port));
                  	printf("length :  %d\n", ntohs(udp->length));
                }
}
    if(ntohs(eth->type)==0x806){              //arp프로토콜 확인
    printf("\t\t\t [network layer : arp type]\n");
    struct arp_header *arp = (struct arp_header*)packet;
    packet+= sizeof(ip_header);
    printf("srcmac : %02x:%02x:%02x:%02x:%02x:%02x\n", arp->srcmac[0],arp->srcmac[1],arp->srcmac[2],eth->srcmac[3],eth->srcmac[4],eth->srcmac[5]);
    printf("srcip : %d.%d.%d.%d\n", arp->srcip[0],arp->srcip[1],arp->srcip[2],arp->srcip[3]);
    printf("dstmac : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dstmac[0],eth->dstmac[1],eth->dstmac[2],eth->dstmac[3],eth->dstmac[4],eth->dstmac[5]);
    printf("dstip : %d.%d.%d.%d\n", arp->dstip[0],arp->dstip[1],arp->dstip[2],arp->dstip[3]);



  }
    
    
    
 
    printf("\n%d bytes captured\n", header->caplen);  //총 패킷 길이

    printf("data 16bytes :"); //옵션 이후 data 16bytes
    for(int j=0; j<16; j++)
    {

      printf("%x", ntohs(packet[j]));
    }
    printf("\n");
    printf("#----------------------------------------------------------------------#\n");	
	  
  }

  pcap_close(handle);
  return 0;
}
