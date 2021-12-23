/*Author: Zarek Lazowski

  Date: 9/28/2021
  
  Description: This is a header file containing various macros, structs, and
  function prototypes used in my trace application. */

#ifndef _TRACE_H_
#define _TRACE_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

/*Structure of an Ethernet header in the packet*/
typedef struct ethernet_header{
  uint8_t dest[6];            /*Destination MAC*/
  uint8_t src[6];             /*Source MAC*/  
  uint16_t type;              /*Ether Type*/
}* ENET_head;

/*Structure of an ARP header in the packet*/
typedef struct ARP_header{
  uint16_t hardware_type;     /*Network link type*/
  uint16_t protocol_type;     /*Protocol this is intended for*/
  uint8_t hardware_addr_len;  /*Length of MAC in bytes*/
  uint8_t protocol_addr_len;  /*Length of IP in bytes*/
  uint16_t opcode;            /*Opcode (req or resp)*/
  uint8_t src_MAC[6];         /*Sender MAC*/
  uint8_t src_IP[4];          /*Sender IP*/
  uint8_t target_MAC[6];      /*Target MAC*/
  uint8_t target_IP[4];       /*Target IP*/
}* ARP_head;

/*Structure of an IP header in the packet*/
typedef struct internet_protocol_header{
  uint8_t ver_IHL;            /*Version and header length (in 32-bit words)*/
  uint8_t TOS;                /*first 6 bits are TOS*/
  uint16_t total_length;      /*Length of header and data (num bytes)*/
  uint16_t identification;    /*Nothing useful for our purposes*/
  uint16_t flags_frag_off;    /*Flags and fragment offset*/
  uint8_t TTL;                /*Time To Live*/
  uint8_t protocol;           /*Type of IP protocol*/
  uint16_t checksum;          /*Checksum*/
  uint8_t src_IP[4];          /*Sender IP*/
  uint8_t dest_IP[4];         /*Destination IP*/
}* IP_head;

/*IP checksum consists of addition of all 2-byte chunks in header and options*/

/*Structure of an ICMP header in the packet*/
typedef struct internet_control_header{
  uint8_t type;               /*ICMP type*/
  uint8_t code;               /*ICMP subtype*/
  uint16_t checksum;          /*Checksum*/
  uint32_t misc;              /*Other field that sometimes isnt used*/
}* ICMP_head;

/*Structure of a TCP header in the packet*/
typedef struct transmission_control_header{
  uint16_t src_port;          /*Source port*/
  uint16_t dest_port;         /*Destination port*/
  uint32_t sequence;          /*Sequence number*/
  uint32_t ack;               /*Acknowledgement number*/
  uint8_t off;                /*Data offset and NS flag*/
  uint8_t flags;              /*Flags rest of the flags*/
  uint16_t window;            /*Window size*/
  uint16_t checksum;          /*Checksum*/
  uint16_t urgent;            /*Urgent pointer*/
}* TCP_head;

/*TCP checksum consists of addition of TCP header, TCP body, source IP,
  dest IP, 8 bits of zeroes, protocol, and calculated TCP length.
 */

/*Structure of a UDP header in the packet*/
typedef struct user_datagram_header{
  uint16_t src_port;          /*Source port*/
  uint16_t dest_port;         /*Destination port*/
  uint16_t length;            /*Length of header and data*/
  uint16_t checksum;          /*Checksum*/
}* UDP_head;

/*Useful macros, particularly for calculating when the payload begins*/
#define ENET_HEAD_LEN 14 /*Length of Ethernet header in bytes*/
#define ARP_HEAD_LEN 28  /*Length of ARP header in bytes*/
#define IP_HEAD_LEN 20   /*Length of IP header in bytes*/
#define ICMP_HEAD_LEN 8  /*Length of ICMP header in bytes*/
#define TCP_HEAD_LEN 20  /*Length of TCP header in bytes*/
#define PSU_HEAD_LEN 12  /*Length of Psuedo-IP header in bytes*/
#define UDP_HEAD_LEN 8   /*Length of UDP header in bytes*/

#define ENET_ARP 0x0806
#define ENET_IP  0x0800

#define ARP_REQ 1
#define ARP_REP 2

#define IP_TOS_MASK 0x03ff
#define IP_ICMP 0x01
#define IP_TCP  0x06
#define IP_UDP  0x11
#define BYTES_PER_WORD 4
#define IP_IHL_MASK 0x0f

#define ICMP_REP 0
#define ICMP_REQ 8

#define TCP_RST_MASK 0x04
#define TCP_SYN_MASK 0x02
#define TCP_FIN_MASK 0x01

#define FTP_DATA_PORT 20
#define FTP_PORT 21
#define TELNET_PORT 23
#define SMTP_PORT 25
#define HTTP_PORT 80
#define POP3_PORT 110

/*Function prototypes*/
void usage();
void readICMP(uint8_t *icmp_start);
void readTCP(uint8_t *ip_start, uint8_t ip_head_len, IP_head ip_header);
void readUDP(uint8_t *udp_start);
void readIP(uint8_t *packet_start);
void readARP(uint8_t *packet_start);
void readPackets(pcap_t *packet_bundle);

#endif
