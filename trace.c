/*Author: Zarek Lazowski

  Date: 9/28/2021
  
  Description: This is the source file for my trace application. 

  This application examines *.pcap files and separates the data into meaningful
  output. 
*/

#include "trace.h"
#include "smartalloc.h"
#include "checksum.h"

/*Print usage and exit*/
void usage()
{
  fprintf(stderr, "Usage: $ trace <filename>\n");
  exit(EXIT_FAILURE);
}

/*Printing the ports for the UDP and TCP headers were functionally identical
  so to save space, the functionality was put into its own function that each
  protocol will call on, providing their respective source and destination 
  ports*/
void printPort(uint16_t src_port, uint16_t dest_port)
{
  /*Print the source port number (name of common ports)*/
  switch(src_port)
  {
    case FTP_DATA_PORT:
    case FTP_PORT:
      printf("\t\tSource Port:  FTP\n");
      break;
    case TELNET_PORT:
      printf("\t\tSource Port:  Telnet\n");
      break;
    case SMTP_PORT:
      printf("\t\tSource Port:  SMTP\n");
      break;
    case HTTP_PORT:
      printf("\t\tSource Port:  HTTP\n");
      break;
    case POP3_PORT:
      printf("\t\tSource Port:  POP3\n");
      break;
    default:
      printf("\t\tSource Port:  %u\n", src_port);
  }

  /*Print the destination port number (name of common ports)*/
  switch(dest_port)
  {
    case FTP_DATA_PORT:
    case FTP_PORT:
      printf("\t\tDest Port:  FTP\n");
      break;
    case TELNET_PORT:
      printf("\t\tDest Port:  Telnet\n");
      break;
    case SMTP_PORT:
      printf("\t\tDest Port:  SMTP\n");
      break;
    case HTTP_PORT:
      printf("\t\tDest Port:  HTTP\n");
      break;
    case POP3_PORT:
      printf("\t\tDest Port:  POP3\n");
      break;
    default:
      printf("\t\tDest Port:  %u\n", dest_port);
  }
}

/*This function reads the ICMP header from the packet and prints out the 
  relevant information.*/
void readICMP(uint8_t *icmp_start)
{
  ICMP_head icmp_header;

  /*Alloc mem for icmp header*/
  icmp_header = (ICMP_head) malloc(ICMP_HEAD_LEN);

  /*Attempt to copy data into ICMP header struct*/
  if( memcpy(icmp_header, icmp_start, ICMP_HEAD_LEN) )
  {
    printf("\n\tICMP Header\n");

    switch(icmp_header->type)
    {
      case 0:
        printf("\t\tType: Reply\n");
	      break;
      case 8:
      	printf("\t\tType: Request\n");
      	break;
      default:
      	printf("\t\tType: Unknown\n");
      	break;
    }
  }

  /*memcpy fails*/
  else
    fprintf(stderr, "Failed to obtain icmp header\n");

  free(icmp_header);
}

/*This function reads the TCP header from the packet and prints out the 
  relevant information.*/
void readTCP(uint8_t *ip_start, uint8_t ip_head_len, IP_head ip_header)
{
  TCP_head tcp_header;
  uint16_t tcp_len = ntohs(ip_header->total_length) - ip_head_len;
  uint16_t tcp_len_transmit = htons(tcp_len);
  uint8_t *tcp_start = ip_start + ip_head_len;
  uint8_t *tcp_cksum_buf;

  /*Alloc mem for icmp header*/
  tcp_header = (TCP_head) malloc(TCP_HEAD_LEN);

  /*Attempt to copy data into ICMP header struct*/
  if( memcpy(tcp_header, tcp_start, TCP_HEAD_LEN) )
  {
    printf("\n\tTCP Header\n");

    /*Print info about the source and destination ports*/
    printPort(ntohs(tcp_header->src_port), ntohs(tcp_header->dest_port));
    
    printf("\t\tSequence Number: %u\n", ntohl(tcp_header->sequence));

    printf("\t\tACK Number: %u\n", ntohl(tcp_header->ack));
    
    /*Check for synchronization flag*/
    if( tcp_header->flags & TCP_SYN_MASK )
      printf("\t\tSYN Flag: Yes\n");
    else
      printf("\t\tSYN Flag: No\n");

    /*Check for reset flag*/
    if( tcp_header->flags & TCP_RST_MASK )
      printf("\t\tRST Flag: Yes\n");
    else
      printf("\t\tRST Flag: No\n");

    /*Check for finish flag*/
    if( tcp_header->flags & TCP_FIN_MASK )
      printf("\t\tFIN Flag: Yes\n");
    else
      printf("\t\tFIN Flag: No\n");

    printf("\t\tWindow Size: %d\n", ntohs(tcp_header->window));
    
    /*Make a buffer and fill with psuedo-IP header, then tcp head and data*/
    //tcp_cksum_buf = (uint8_t *) malloc(PSU_HEAD_LEN + tcp_len);
    tcp_cksum_buf = (uint8_t *) malloc(tcp_len + PSU_HEAD_LEN);

    if( !memcpy(tcp_cksum_buf, ip_header->src_IP, 4) )
      fprintf(stderr, "Error recovering source ip for psuedo header.");
    if( !memcpy(tcp_cksum_buf + 4, ip_header->dest_IP, 4) )
      fprintf(stderr, "Error recovering destination ip for psuedo header.");
    if( !memset(tcp_cksum_buf + 8, 0x00, 1) )
      fprintf(stderr, "Error setting reserved bits of psuedo header.");
    if( !memcpy(tcp_cksum_buf + 9, &(ip_header->protocol), 1) )
      fprintf(stderr, "Error recovering protocol for psuedo header.");
    if( !memcpy(tcp_cksum_buf + 10, &tcp_len_transmit, 2) )
      fprintf(stderr, "Error recovering TCP length for psuedo header.");
    
    if( !memcpy(tcp_cksum_buf + 12, tcp_start, tcp_len) )
      fprintf(stderr, "Error recovering TCP packet for checksum.");
      
    
    /*Checksum function returns zero on success, non-zero on failure*/
    if( !in_cksum( (unsigned short *) tcp_cksum_buf, tcp_len + PSU_HEAD_LEN) )
      printf("\t\tChecksum: Correct (%#x)\n", ntohs(tcp_header->checksum));
    else
      printf("\t\tChecksum: Incorrect (%#x)\n", ntohs(tcp_header->checksum));

  }

  /*memcpy fails*/
  else
    fprintf(stderr, "Failed to obtain tcp header\n");

  /*Clean up*/
  free(tcp_cksum_buf);
  free(tcp_header);
}

/*This function reads the UDP header from the packet and prints out the 
  relevant information.*/
void readUDP(uint8_t *udp_start)
{
  UDP_head udp_header;

  /*Alloc mem for icmp header*/
  udp_header = (UDP_head) malloc(UDP_HEAD_LEN);

  /*Attempt to copy data into ICMP header struct*/
  if( memcpy(udp_header, udp_start, UDP_HEAD_LEN) )
  {
    printf("\n\tUDP Header\n");

    /*Print info about the source and destination ports*/
    printPort(ntohs(udp_header->src_port), ntohs(udp_header->dest_port));
  }

  /*memcpy fails*/
  else
    fprintf(stderr, "Failed to obtain udp header\n");

  free(udp_header);
}

/*This function reads the IP header from the packet and prints out the 
  relevant information. Additionally it determines the type of the next
  packet and calls its respective function.*/
void readIP(uint8_t *packet_start)
{
  IP_head ip_header;
  uint8_t *ip_start;
  uint8_t full_header_len;

  /*Alloc mem for IP header*/
  ip_header = (IP_head) malloc(IP_HEAD_LEN);

  /*Determine start of IP header*/
  ip_start = packet_start + ENET_HEAD_LEN;

  /*Attempt to copy data into IP header struct*/
  if( memcpy(ip_header, ip_start, IP_HEAD_LEN) )
  {
    printf("\n\tIP Header\n");
    
    printf("\t\tTOS: 0x%x\n", ip_header->TOS & IP_TOS_MASK);

    printf("\t\tTTL: %d\n", ip_header->TTL);

    /*Determines the protocol for printing out IP information*/
    switch(ip_header->protocol)
    {
      case IP_ICMP:
      	printf("\t\tProtocol: ICMP\n");
      	break;
      case IP_TCP:
      	printf("\t\tProtocol: TCP\n");
      	break;
      case IP_UDP:
      	printf("\t\tProtocol: UDP\n");
      	break;
      default:
      	printf("\t\tProtocol: Unknown\n");
      	break;
    }

    /*Calculate full header length in advance because it will be useful*/
    full_header_len = BYTES_PER_WORD * (ip_header->ver_IHL & IP_IHL_MASK);

    /*Checksum function returns zero on success, non-zero on failure*/
    if( !in_cksum( (unsigned short *) ip_start, full_header_len) )
      printf("\t\tChecksum: Correct (%#x)\n", ntohs(ip_header->checksum));
    else
      printf("\t\tChecksum: Incorrect (%#x)\n", ntohs(ip_header->checksum));


    /*Print out source and destination IP info*/
    printf("\t\tSender IP: %d.%d.%d.%d\n",
	   ip_header->src_IP[0], ip_header->src_IP[1],
	   ip_header->src_IP[2], ip_header->src_IP[3]);

    printf("\t\tDest IP: %d.%d.%d.%d\n",
	   ip_header->dest_IP[0], ip_header->dest_IP[1],
	   ip_header->dest_IP[2], ip_header->dest_IP[3]);

    /*Move on to the next packet layer, depending on the protocol. We need to
      determine where the next layer will start, in order to copy from the 
      correct position in the packet. This happens to be right after the full 
      IP header, so we just add this to the position of the IP start.

      In the case of the TCP header, there is a checksum which requires 
      checking the data of the TCP packet as well. So we need to know how long
      the full IP header length to calculate the full TCP (header & data) 
      length.*/
    switch(ip_header->protocol)
    {
      case IP_ICMP:
        readICMP(ip_start + full_header_len);
	      break;
      case IP_TCP:
      	readTCP(ip_start, full_header_len, ip_header);
      	break;
      case IP_UDP:
      	readUDP(ip_start + full_header_len);
      	break;
    }    
  }

  /*memcpy fails*/
  else
    fprintf(stderr, "Failed to obtain ip header\n");

  /*Clean up*/
  free(ip_header);
}

/*This function reads the ARP header from the packet and prints out the 
  relevant information.*/
void readARP(uint8_t *packet_start)
{
  ARP_head arp_header;
  uint8_t *arp_start;

  /*Alloc mem for ARP header*/
  arp_header = (ARP_head) malloc(ARP_HEAD_LEN);

  /*Determine start of ARP header*/
  arp_start = packet_start + ENET_HEAD_LEN;

  /*Attempt to copy data into the ARP header struct*/
  if( memcpy(arp_header, arp_start, ARP_HEAD_LEN) )
  {
    printf("\n\tARP Header\n");

    /*Print out the opcode: 1 for request and 2 for reply*/
    switch(ntohs(arp_header->opcode))
    {
      case ARP_REQ:
        printf("\t\tOpcode: Request\n");
	      break;
      case ARP_REP:
      	printf("\t\tOpcode: Reply\n");
      	break;
    }

    /*Print out source and target MAC and IP addresses*/
    printf("\t\tSender MAC: %x:%x:%x:%x:%x:%x\n",
	   arp_header->src_MAC[0], arp_header->src_MAC[1],
	   arp_header->src_MAC[2], arp_header->src_MAC[3],
	   arp_header->src_MAC[4], arp_header->src_MAC[5]);

    printf("\t\tSender IP: %d.%d.%d.%d\n",
	   arp_header->src_IP[0], arp_header->src_IP[1],
	   arp_header->src_IP[2], arp_header->src_IP[3]);
    
    printf("\t\tTarget MAC: %x:%x:%x:%x:%x:%x\n",
	   arp_header->target_MAC[0], arp_header->target_MAC[1],
	   arp_header->target_MAC[2], arp_header->target_MAC[3],
	   arp_header->target_MAC[4], arp_header->target_MAC[5]);

    printf("\t\tTarget IP: %d.%d.%d.%d\n",
	   arp_header->target_IP[0], arp_header->target_IP[1],
	   arp_header->target_IP[2], arp_header->target_IP[3]);
  }

  /*memcpy fails*/
  else
    fprintf(stderr, "Failed to obtain arp header\n");

  /*Clean up*/
  free(arp_header);
}

/*This function reads the Ethernet header from the packet and prints out the 
  relevant information. Additionally it determines the type of the next
  packet and calls its respective function.*/
void readPackets(pcap_t *packet_bundle)
{
  struct pcap_pkthdr *packet_info;
  uint8_t *packet_start;
  int packet_return, num_packets = 0;
  ENET_head enet_header;

  /*Alloc mem for ethernet header*/
  enet_header = (ENET_head) malloc(ENET_HEAD_LEN);
  
  /*Parse the packet with pcap*/
  while( (packet_return = pcap_next_ex(packet_bundle,
				    &packet_info,
				    (const u_char **) &packet_start)) == 1 )
  {
    /*Increment packet number and print packet info*/
    printf("\nPacket number: %d  Packet Len: %d\n",
	   ++num_packets, packet_info->len);
    
    /*Attempt to copy ethernet header into a reused structure*/
    if( memcpy(enet_header, packet_start, ENET_HEAD_LEN) )
    {
      /*Display ethernet header*/
      printf("\n\tEthernet Header\n");

      /*Destination mac address*/
      printf("\t\tDest MAC: %x:%x:%x:%x:%x:%x\n",
	     enet_header->dest[0], enet_header->dest[1], enet_header->dest[2],
	     enet_header->dest[3], enet_header->dest[4], enet_header->dest[5]);

      /*Source mac address*/
      printf("\t\tSource MAC: %x:%x:%x:%x:%x:%x\n",
	     enet_header->src[0], enet_header->src[1], enet_header->src[2],
	     enet_header->src[3], enet_header->src[4], enet_header->src[5]);

      /*Ether type*/
      switch(ntohs(enet_header->type))
      {
        case ENET_ARP:
      	  printf("\t\tType: ARP\n");
      	  readARP(packet_start);
      	  break;
        case ENET_IP:
      	  printf("\t\tType: IP\n");
      	  readIP(packet_start);
      	  break;
        default:
      	  printf("\t\tType: Unknown\n");
      	  break;
      }
    }
    
    /*memcpy failed, ideally we never end up here*/
    else
    {
      fprintf(stderr, "Failed to obtain ethernet header\n");
      break;
    }
      
  }

  /*Clean up the ethernet header*/
  free(enet_header);
}

int main(int argc, char *argv[])
{
  pcap_t *packet_bundle;
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
  char *pcap_file;
  
  /*If the call doesn't follow the usage, print it and exit*/
  if(argc != 2)
    usage();

  /*Allocate memory for pcap_file and zero byte*/
  pcap_file = (char *) malloc(strlen(argv[1]) + 1);
		     
  /*Copy contents of argument into pcap_file*/
  if( !strcpy(pcap_file, argv[1]) )
  {
    fprintf(stderr, "Error obtaining filename\n");
    free(pcap_file);
    exit(EXIT_FAILURE);
  }

  /*Attempt to open pcap file, if it fails, print error message and exit*/
  if( !(packet_bundle = pcap_open_offline(pcap_file, pcap_error_buffer)) )
  {
    fprintf(stderr, "Error opening file: %s\n", pcap_error_buffer);
    free(pcap_file);
    exit(EXIT_FAILURE);
  }

  /*Read and print all packets in file*/
  readPackets(packet_bundle);

  /*Clean up*/
  pcap_close(packet_bundle);
  free(pcap_file);

  return 0;
}
