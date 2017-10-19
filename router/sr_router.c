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
  uint16_t ether_type = ntohs(ethernet_header->ether_type); 
  printf("ETHERTYPE: %d \n", ether_type);

  struct sr_if *intface = sr_get_interface(sr, interface); 
  sr_print_if(intface);

  uint8_t broadcast_addr[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; 
  /**check if our router is the dest or if it's a broadcast addr**/
  if((memcmp(ethernet_header->ether_shost, intface->addr, ETHER_ADDR_LEN) != 0) || (memcmp(ethernet_header->ether_dhost, broadcast_addr, ETHER_ADDR_LEN) != 0)){
    if (ether_type == 2054){
      printf("ARP REQUEST\n");
      sr_handle_arp(sr, packet, len, interface);
    } else if (ether_type == 2048) {
        printf("IP REQUEST\n");
        sr_handle_ip(sr, packet, len, interface);
    }
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
  print_addr_ip_int(intface->ip);

  if (intface->ip == ip_header->ip_dst) {
    /*Packet is destined to US*/ 
    printf("Packet is destined to us !!\n");
    if (ip_header->ip_p == 1){
      /*icmp echo request, send echo reply*/
      printf("ICMP echo request, send reply\n");
      handle_icmp(sr, 0, 0, packet, len, interface); 
    } else if ((ip_header->ip_p == 17) || (ip_header->ip_p == 6)){
      /*send port unreachable*/  
      printf("PORT UNREACHABLE!!\n");
      handle_icmp(sr, 3, 3, packet, len, interface); 
    }
  } else {
      /*Not destined to me*/
      printf("Packet is NOT destined to us !!\n");
      printf("Actual checksum: %d \n", ip_header->ip_sum);
      uint16_t sum = cksum(ip_header, ip_header->ip_len); 
      printf("cksum result: %d\n", ntohs(sum));
      if (sum == ip_header->ip_sum){
        ip_header->ip_ttl--;
        ip_header->ip_sum = cksum(ip_header, 20);
        /*Perform LPM*/
          

   
      } else {
        printf("Incorrect cksum\n");
      }
  }
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

void sr_handle_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr));
  struct sr_if *irface = sr_get_interface(sr, interface);

  sr_print_if(irface);

  if (arp_header->ar_tip == irface->ip){ 
    printf("DESTINED TO ONE OF OUR ROUTER'S IPs\n");
    if (ntohs(arp_header->ar_op) == 1){
      printf("REQUEST\n");
      /*Construct ARP reply and send it back*/
      /*New packet: 28 (for arp header) + 14 (for ethernet header)*/

      uint8_t *arp_reply = malloc(sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr)); 
      sr_arp_hdr_t *arp_header_request = (sr_arp_hdr_t*) (arp_reply + sizeof(struct sr_ethernet_hdr));
      sr_ethernet_hdr_t *ether_header_request = (sr_ethernet_hdr_t*) arp_reply;

      /*Source ethernet/arp header*/
      sr_arp_hdr_t *arp_header_src = (sr_arp_hdr_t*) (packet + sizeof(struct sr_ethernet_hdr));
      sr_ethernet_hdr_t *ether_header_src = (sr_ethernet_hdr_t*) packet;
      
      arp_header_request->ar_hrd = htons(1);
      arp_header_request->ar_pro = htons(2048);   
      arp_header_request->ar_hln = ETHER_ADDR_LEN;   
      arp_header_request->ar_pln = 4;
      arp_header_request->ar_op = htons(arp_op_reply);
      memcpy(arp_header_request->ar_sha, irface->addr, ETHER_ADDR_LEN);
      /*Just a pointer to a list^^, need to copy character per character*/
      arp_header_request->ar_sip = irface->ip;
      memcpy(arp_header_request->ar_tha, arp_header_src->ar_sha, ETHER_ADDR_LEN);
      arp_header_request->ar_tip = arp_header_src->ar_sip;

      /*construct ethernet header*/
      ether_header_request->ether_type = htons(ethertype_arp);
      memcpy(ether_header_request->ether_shost, irface->addr, ETHER_ADDR_LEN); 
      memcpy(ether_header_request->ether_dhost, ether_header_src->ether_shost, ETHER_ADDR_LEN); 

      sr_send_packet(sr, arp_reply, 42, interface);

    } else if (ntohs(arp_header->ar_op) == 0){
      printf("REPLY\n");
      /*cache it, go through request queue and send outstanding packets*/
      struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);

      if (request) {
        struct sr_packet *pkt_list = request->packets;

        while(pkt_list != NULL) {
          struct sr_packet * next_request = pkt_list->next;
          sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *) (pkt_list->buf); 

          memcpy(&(ethernet_hdr->ether_dhost), &(arp_header->ar_sha), ETHER_ADDR_LEN); 

          sr_send_packet(sr, pkt_list->buf, pkt_list->len, pkt_list->iface);
          pkt_list = next_request;
        }
        sr_arpcache_destroy(&sr->cache);
      } else{
       /*IP is not in the request queue*/
       printf("IP not in request queue\n");
      } 
    } else {
      /*Invalid OP Code*/
      printf("INVALID OP CODE\n");
    } 
   } else{
      /*Not destined to one of our interfaces*/      
      printf("NOT DESTINED TO ONE OF OUR IP's interfaces\n");
   }
}

/** Handle all ICMP messages
*/
void handle_icmp(struct sr_instance *sr, int type, int code,  uint8_t * packet, unsigned int len, char* interface) {

         struct sr_if *irface = sr_get_interface(sr, interface); 

         /*Packet the router received*/
         sr_ethernet_hdr_t * eth_hdr_old = (sr_ethernet_hdr_t *) packet;
         sr_ip_hdr_t * ip_hdr_old = (sr_ip_hdr_t *) (packet + sizeof(struct sr_ip_hdr));
         sr_icmp_hdr_t * icmp_hdr_old = (sr_icmp_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
         
         /*Packet we're sending; over-allocate in case it's a type3 icmp header*/
         uint8_t *reply_pkt = malloc(sizeof(struct sr_icmp_t3_hdr) + sizeof(struct sr_icmp_hdr) + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)); 
         unsigned int total_length = 0;

         if (type == 3 || type == 11) {
           /*Consruct packet to be sent*/
           sr_icmp_t3_hdr_t * icmp_hdr_t3 = (sr_icmp_t3_hdr_t *) (reply_pkt + sizeof(struct sr_ethernet_hdr) + sizeof( struct sr_ip_hdr));

           icmp_hdr_t3->icmp_type = type;
           icmp_hdr_t3->icmp_code = code;
           icmp_hdr_t3->icmp_sum = 0x0; 
           icmp_hdr_t3->icmp_sum = cksum (icmp_hdr_t3, ICMP_DATA_SIZE);
           icmp_hdr_t3->unused = htons(0);
           icmp_hdr_t3->next_mtu = 0x0;
           memcpy(icmp_hdr_t3->data, icmp_hdr_old, ICMP_DATA_SIZE);
           total_length = sizeof(struct sr_icmp_t3_hdr) + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);

         } else {
           sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (reply_pkt + sizeof(struct sr_ethernet_hdr) + sizeof( struct sr_ip_hdr));

           icmp_hdr->icmp_type = type;
           icmp_hdr->icmp_code = code;
           icmp_hdr->icmp_sum = 0x0;
           icmp_hdr->icmp_sum = cksum (icmp_hdr, ICMP_DATA_SIZE); 
           total_length = sizeof(struct sr_icmp_hdr) + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);
         }

         sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) reply_pkt;
         sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (reply_pkt + sizeof(struct sr_ip_hdr));

         ip_hdr->ip_tos = htons(0);
         ip_hdr->ip_len = htons(sizeof(icmp_hdr));
         ip_hdr->ip_off = htons(0);
         ip_hdr->ip_ttl = 64;
         ip_hdr->ip_p = 1;
         ip_hdr->ip_sum = 0x0;
         ip_hdr->ip_sum = cksum(ip_hdr, 20);
         ip_hdr->ip_src = irface->ip;
         ip_hdr->ip_dst = ip_hdr_old->ip_src;

         memcpy(&(eth_hdr->ether_shost), &(irface->ip), ETHER_ADDR_LEN); 
         memcpy(&(eth_hdr->ether_dhost), &(eth_hdr_old->ether_shost), ETHER_ADDR_LEN); 
         eth_hdr->ether_type = htons(eth_hdr_old->ether_type);
         
         sr_send_packet(sr, reply_pkt, total_length, interface);
         free(reply_pkt);
}
