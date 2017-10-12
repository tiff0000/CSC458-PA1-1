/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  print_hdrs(packet, len);
  printf("*** -> Received packet of length %d \n",len);

  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  uint16_t ether_type = ntohs(ethernet_header->ether_type); 

  if (ether_type == 2054){
    printf("ARP REQUEST\n");
    sr_handle_arp(sr, packet, len, interface);
  } else if (ether_type == 2048) {
      printf("IP REQUEST\n");
      sr_handle_ip(sr, packet, len, interface);
  }
}

void sr_handle_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  int min_length = sizeof(sr_ethernet_hdr_t);

  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + min_length);
  struct sr_if *intface = sr_get_interface(sr, interface); 

  printf("PRINTING DESTINATION IP\n");
  print_addr_ip_int(ip_header->ip_dst);

  if (intface->ip == ip_header->ip_dst) {
    /*icmp protocl is 1*/ 
    if (ip_header->ip_p == 1){
      /*icmp echo request*/
      printf("ICMP echo request, send reply\n");
      
    } else if ((ip_header->ip_p == 17) || (ip_header->ip_p == 6)){
      /*send port unreachable*/  
    }
  } else {
    /*Not destined to me*/
    /*check routing table*/
      
  }

  /**if (len > min_length){
    packet meets min length requirement
    check checksum
    uint16_t sum = cksum(ip_header, 20);
    printf("cksum result: %d\n", ntohs(sum));
    printf("actual checksum : %d\n", ntohs(ip_header->ip_sum));
  } else {
    printf("Packet is too small:(\n");
  }**/
}

void sr_handle_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *irface = sr_get_interface(sr, interface); 

  if (arp_header->ar_tip == irface->ip){ 
    printf("DESTINED TO ONE OF OUR ROUTER'S IPs\n");
    if (ntohs(arp_header->ar_op) == 1){
      printf("REQUEST\n");
      /*Construct ARP reply and send it back*/
      /*destination is broadcast MAC address*/
      /*New packet: 28 (for arp header) + 14 (for ethernet header)*/
      uint8_t *arp_reply = malloc(sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr)); 
      sr_arp_hdr_t *arp_header_request = (sr_arp_hdr_t*) (arp_reply + sizeof(struct sr_arp_hdr));
      sr_ethernet_hdr_t *ether_header_request = (sr_ethernet_hdr_t*) (arp_reply + sizeof(struct sr_ethernet_hdr));

      /*Source ethernet/arp header*/
      sr_arp_hdr_t *arp_header_src = (sr_arp_hdr_t*) (packet + sizeof(struct sr_arp_hdr));
      sr_ethernet_hdr_t *ether_header_src = (sr_ethernet_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr));
      
      arp_header_request->ar_hrd = htons(1);   
      arp_header_request->ar_pro = htons(2048);   
      arp_header_request->ar_hln = arp_header_src->ar_hln;   
      arp_header_request->ar_pln = arp_header_src->ar_pln;   
      arp_header_request->ar_op = 0;
      memcpy(arp_header_request->ar_sha, irface->addr, sizeof(irface->addr));
      /*Just a pointer to a list^^, need to copy character per character*/
      arp_header_request->ar_sip = irface->ip;
      memcpy(arp_header_request->ar_tha, arp_header_src->ar_tha, sizeof(arp_header_request->ar_tha));
      arp_header_request->ar_tip = arp_header_src->ar_tip;

      /*construct ethernet header*/
      ether_header_request->ether_type = ethertype_arp;
      memcpy(ether_header_request->ether_shost, ether_header_src->ether_dhost, sizeof(ether_header_src->ether_dhost)); 
      memcpy(ether_header_request->ether_dhost, ether_header_src->ether_shost, sizeof(ether_header_src->ether_shost)); 

      sr_send_packet(sr, arp_reply, 42, irface->name);

    } else if (ntohs(arp_header->ar_op) == 0){
      printf("REPLY\n");
      /*cache it, go through request queue and send outstanding packets*/
      struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);

      if (request) {
        struct sr_packet *pkt_list = request->packets;

        while(pkt_list != NULL) {
          struct sr_packet * next_request = pkt_list->next;
          sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) (pkt_list->buf); 

          /*ethernet_hdr->ether_dhost = arp_header->ar_sha;*/

          sr_send_packet(sr, pkt_list->buf, pkt_list->len, pkt_list->iface);
          pkt_list = next_request;
        }
        sr_arpcache_destroy(&sr->cache);
      } else{
       /*IP is not in the request queue*/
      } 
    } else {
      /*Invalid OP Code*/
    }
 } else {
   /*Not destined to one our interfaces*/
 }
}

/** Handle all ICMP messages
*/
void handle_icmp(struct sr_instance *sr, int type, int code,  uint8_t * packet, unsigned int len, char* interface) {

         struct sr_if *irface = sr_get_interface(sr, interface); 

         /*Consruct packet to be sent*/
         uint8_t *reply_pkt = malloc(sizeof(struct sr_icmp_hdr) + sizeof(struct sr_ethernet_hdr) + sizeof(sr_ip_hdr)); 

         sr_ethernet_hdr * eth_hdr = (sr_ethernet_hdr *) reply_pkt;
         sr_ip_hdr * ip_hdr = (sr_ip_hdr *) (reply_pkt + sizeof(sr_ip_hdr));
         sr_icmp_hdr * icmp_hdr = (sr_icmp_hdr *) (reply_pkt + sizeof(struct sr_ethernet_hdr) + sizeof(sr_ip_hdr));

         /*Packet received*/
         sr_ethernet_hdr * eth_hdr_old = (sr_ethernet_hdr *) packet;
         sr_ip_hdr * ip_hdr_old = (sr_ip_hdr *) (packet + sizeof(sr_ip_hdr));
         sr_icmp_hdr * icmp_hdr_old = (sr_icmp_hdr *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(sr_ip_hdr));

         icmp_hdr->icmp_type = type;
         icmp_hdr->icmp_code = code;
         icmp_hdr->icmp_sum = 0;

         ip_hdr->ip_tos = 0;
         ip_hdr->ip_len = htons(sizeof(icmp_hdr));
         ip_hdr->ip_off = htons(0);
         ip_hdr->ip_ttl = 64;
         ip_hdr->ip_p = 1;
         ip_hdr->ip_sum = 0;
         ip_hdr->src = irface->ip;
         ip_hdr->dst = ip_hdr_old->ip_src;

         memcpy(eth_hdr->ether_shost, irface->ip , sizeof(irface->ip)); 
         memcpy(eth_hdr->ether_dhost, eth_hdr_old->ether_shost, sizeof(eth_hdr_old->ether_shost)); 
         eth_hdr->ether_type = htons(eth_hdr_old->ether_type);
}
