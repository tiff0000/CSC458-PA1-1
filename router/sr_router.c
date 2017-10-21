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
  struct sr_if *intface = sr_get_interface(sr, interface); 

  uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; 
  /**check if our router is the dest or if it's a broadcast addr**/
  if((memcmp(ethernet_header->ether_shost, intface->addr, ETHER_ADDR_LEN) != 0) || (memcmp(ethernet_header->ether_dhost, broadcast_addr, ETHER_ADDR_LEN) != 0)){
    if (ethernet_header->ether_type == ntohs(ethertype_arp)){
      sr_handle_arp(sr, packet, len, interface);
    } else if (ethernet_header->ether_type == ntohs(ethertype_ip)) {
        sr_handle_ip(sr, packet, len, interface);
    }
  }
}

void sr_handle_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ethernet_hdr_t *ethernet_header_send = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr));
  struct sr_if *intface = sr_get_interface(sr, interface); 

  if(ip_header->ip_ttl <= 1) {
    /*send icmp time exceeded*/
    handle_icmp_type3(sr, 11, 0, packet, len, interface); 
  }

  if (intface->ip == ip_header->ip_dst) {
    /*Packet is destined to US*/ 
    if (ip_header->ip_p == ip_protocol_icmp){
      /*icmp echo request, send echo reply*/
      handle_icmp(sr, 0, 0, packet, len, interface); 
    } else {
      /*send port unreachable*/  
      handle_icmp_type3(sr, 3, 3, packet, len, interface); 
    }
    /*dunno what to do here*/ 
  } else {
       
      /*Not destined to me*/
      ip_header->ip_ttl--;
      ip_header->ip_sum = 0x0;
      ip_header->ip_sum = cksum(ip_header, sizeof(struct sr_ip_hdr));
      /*Perform LPM*/
      struct sr_rt * rtable = sr->routing_table;
      int match = 0;
      struct sr_if *next_hop_iface = malloc(sizeof(struct sr_if)); 
      uint32_t gateway = NULL; 

      while(rtable) {
        if((ip_header->ip_dst & rtable->mask.s_addr) == (rtable->dest.s_addr)){
          gateway = rtable->gw.s_addr; 
          memcpy(next_hop_iface, sr_get_interface(sr, rtable->interface), sizeof(struct sr_if));
          match = 1;
        }
        rtable = rtable->next;
      }
        
      if(match == 1) {
      /*check arp cache*/
      /* Checks if an IP->MAC mapping is in the cache. IP is in network byte order. 
      You must free the returned structure if it is not NULL. */
        struct sr_arpentry * cache_entry =  sr_arpcache_lookup(&(sr->cache), ip_header->ip_dst); 
        memcpy(ethernet_header_send->ether_shost, next_hop_iface->addr, ETHER_ADDR_LEN);

        if (cache_entry){
          /*send frame to next_hop*/
          memcpy(ethernet_header_send->ether_dhost, cache_entry->mac , ETHER_ADDR_LEN); 
          sr_send_packet(sr, packet, len, next_hop_iface->name);
          free(cache_entry);
        } else {
          /*add to arp queue*/
          sr_arpcache_queuereq(&(sr->cache), gateway , packet, len, next_hop_iface->name);
        }
      } else{
        /*ICMP network unreachable*/
        handle_icmp_type3(sr, 3, 0, packet, len, interface);
      }
  }
}

void sr_handle_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr));
  struct sr_if *irface = sr_get_interface(sr, interface);

  if (arp_header->ar_tip == irface->ip){ 
    if (ntohs(arp_header->ar_op) == 1){
      /*Construct ARP reply and send it back*/
      /*New packet: 28 (for arp header) + 14 (for ethernet header)*/

      uint8_t *arp_reply = malloc(sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr)); 
      sr_arp_hdr_t *arp_header_request = (sr_arp_hdr_t*) (arp_reply + sizeof(struct sr_ethernet_hdr));
      sr_ethernet_hdr_t *ether_header_request = (sr_ethernet_hdr_t*) arp_reply;

      /*Source ethernet/arp header*/
      sr_arp_hdr_t *arp_header_src = (sr_arp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr));
      sr_ethernet_hdr_t *ether_header_src = (sr_ethernet_hdr_t*) packet;
      
      arp_header_request->ar_hrd = htons(arp_hrd_ethernet);
      arp_header_request->ar_pro = htons(ethertype_ip); 
      arp_header_request->ar_hln = ETHER_ADDR_LEN; 
      arp_header_request->ar_pln = arp_header_src->ar_pln; 
      arp_header_request->ar_op = htons(arp_op_reply);
      memcpy(arp_header_request->ar_sha, irface->addr, ETHER_ADDR_LEN);
      memcpy(arp_header_request->ar_tha, arp_header_src->ar_sha, ETHER_ADDR_LEN);
      /*Just a pointer to a list^^, need to copy character per character*/
      arp_header_request->ar_sip = irface->ip;
      arp_header_request->ar_tip = arp_header_src->ar_sip;

      /*construct ethernet header*/
      ether_header_request->ether_type = htons(ethertype_arp);
      memcpy(ether_header_request->ether_shost, irface->addr, ETHER_ADDR_LEN); 
      memcpy(ether_header_request->ether_dhost, ether_header_src->ether_shost, ETHER_ADDR_LEN); 

      sr_send_packet(sr, arp_reply, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), interface);

    } else if (ntohs(arp_header->ar_op) == 2){
      /*cache it, go through request queue and send outstanding packets*/
      struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);

      if (request) {
        struct sr_packet *pkt_list = request->packets;

        while(pkt_list != NULL) {
          sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) (pkt_list->buf); 

          memcpy(&(ethernet_hdr->ether_dhost), &(arp_header->ar_sha), ETHER_ADDR_LEN); 

          sr_send_packet(sr, pkt_list->buf, pkt_list->len, pkt_list->iface);
          pkt_list = pkt_list->next;;
        }
        sr_arpreq_destroy(&(sr->cache), request);
      } else{
       /*IP is not in the request queue*/
      } 
    } else {
      /*Invalid OP Code*/
    } 
   } else{
      /*Not destined to one of our interfaces*/      
   }
}

/** Handle all ICMP messages
*/
void handle_icmp_type3(struct sr_instance *sr, int type, int code,  uint8_t * packet, unsigned int len, char* interface) {

         struct sr_if *irface = sr_get_interface(sr, interface); 

         /*Packet the router received*/
         sr_ethernet_hdr_t * eth_hdr_old = (sr_ethernet_hdr_t *) packet;
         sr_ip_hdr_t * ip_hdr_old = (sr_ip_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr));
         
         uint8_t *reply_pkt = malloc(sizeof(struct sr_icmp_t3_hdr) + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)); 

         sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) reply_pkt;
         sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (reply_pkt + sizeof(struct sr_ethernet_hdr));

         memcpy(&(eth_hdr->ether_shost), &(irface->addr), ETHER_ADDR_LEN);
         memcpy(&(eth_hdr->ether_dhost), &(eth_hdr_old->ether_shost), ETHER_ADDR_LEN);
         eth_hdr->ether_type = htons(ethertype_ip);

         ip_hdr->ip_tos = htons(0);
         ip_hdr->ip_v = 0x4;
         ip_hdr->ip_hl = 5;
	 ip_hdr->ip_len = htons(sizeof(struct sr_icmp_t3_hdr) + sizeof(struct sr_ip_hdr));
         ip_hdr->ip_id = 0; 
         ip_hdr->ip_ttl = 64;
         ip_hdr->ip_off = htons(IP_DF);
         ip_hdr->ip_p = ip_protocol_icmp;
         ip_hdr->ip_src = irface->ip;
         ip_hdr->ip_dst = ip_hdr_old->ip_src;
         ip_hdr->ip_sum = 0;
   
         /*Consruct packet to be sent*/
         sr_icmp_t3_hdr_t * icmp_hdr_t3 = (sr_icmp_t3_hdr_t *) (reply_pkt + sizeof(struct sr_ethernet_hdr) + sizeof( struct sr_ip_hdr));

         icmp_hdr_t3->icmp_type = type;
         icmp_hdr_t3->unused = 0;
         icmp_hdr_t3->next_mtu = 0;
         icmp_hdr_t3->icmp_code = code;
         memcpy(icmp_hdr_t3->data, ip_hdr_old, 28);
         icmp_hdr_t3->icmp_sum = 0;

         icmp_hdr_t3->icmp_sum = cksum(icmp_hdr_t3, sizeof(struct sr_icmp_t3_hdr));
         ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

         sr_send_packet(sr, reply_pkt, sizeof(struct sr_icmp_t3_hdr) + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr), interface);
         free(reply_pkt);
}

void handle_icmp(struct sr_instance *sr, int type, int code,  uint8_t * packet, unsigned int len, char* interface) {
       
         struct sr_if *irface = sr_get_interface(sr, interface); 
 
         /*Packet the router received*/
         sr_ethernet_hdr_t * eth_hdr_old = (sr_ethernet_hdr_t *) packet;
         sr_ip_hdr_t * ip_hdr_old = (sr_ip_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr));
         
         uint8_t *reply_pkt = malloc(sizeof(struct sr_icmp_hdr) + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)); 
         sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (reply_pkt + sizeof(struct sr_ethernet_hdr) + sizeof( struct sr_ip_hdr));

         sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) reply_pkt;
         sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (reply_pkt + sizeof(struct sr_ip_hdr));

         memcpy(&(eth_hdr->ether_shost), &(irface->addr), ETHER_ADDR_LEN);
         memcpy(&(eth_hdr->ether_dhost), &(eth_hdr_old->ether_shost), ETHER_ADDR_LEN);
         eth_hdr->ether_type = htons(ethertype_ip);

         ip_hdr->ip_v = 0x4;
         ip_hdr->ip_hl = 0x4;
         ip_hdr->ip_tos = htons(0);
         ip_hdr->ip_len = htons(70 - len);
         ip_hdr->ip_id = htons(70 - len);
         ip_hdr->ip_ttl = 64;
         ip_hdr->ip_off = htons(IP_DF);
         ip_hdr->ip_p = ip_protocol_icmp;
         ip_hdr->ip_sum = 0x0;
         ip_hdr->ip_src = irface->ip;
         ip_hdr->ip_dst = ip_hdr_old->ip_src;
  
         icmp_hdr->icmp_type = type;
         icmp_hdr->icmp_code = code;
         icmp_hdr->icmp_sum = 0x0;

         /*as per RFC792, data received in the echo message must be returned in the echo reply message*/
         memcpy(icmp_hdr + 4, ip_hdr_old + sizeof(struct sr_icmp_hdr) + 4, len -  sizeof(struct sr_icmp_hdr) - 4);

         icmp_hdr->icmp_sum = cksum(icmp_hdr, ICMP_DATA_SIZE);
         ip_hdr->ip_sum = cksum(ip_hdr, 20);

         sr_send_packet(sr, reply_pkt, len, interface);
         free(reply_pkt);
}
