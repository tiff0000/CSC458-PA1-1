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
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#define IP_BEGIN 14
#define ARP_BEGIN 14

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

  sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)packet;

  uint16_t ether_type = ntohs(ethernet_header->ether_type); 
  int min_length = sizeof(sr_ethernet_hdr_t);

  if (ether_type == 2054){
    /*ARP REQUEST*/
    printf("ARP REQUEST\n");
    sr_handle_arp(sr, packet, len, interface);
  } else if (ether_type == 2048) {
      /*IP REQUEST*/
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
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + IP_BEGIN);

  printf("PRINTING DESTINATION IP\n");
  print_addr_ip_int(ip_header->ip_dst);

  if (len > min_length){
    /*packet meets min length requirement*/
    /*check checksum*/
    uint16_t sum = cksum(ip_header, 20);
    printf("cksum result: %d\n", ntohs(sum));
    printf("actual checksum : %d\n", ntohs(ip_header->ip_sum));
  } else {
    printf("Packet is too small:(\n");
  }
}

void sr_handle_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + ARP_BEGIN);
  struct sr_if *irface = sr_get_interface(sr, interface); 

  if (arp_header->ar_tip == irface->ip){ 
    printf("DESTINED TO ONE OF OUR ROUTER'S IPs\n");
    if (ntohs(arp_header->ar_op) == 1){
      printf("REQUEST\n");
      /*Construct ARP reply and send it back*/
      /*destination is broadcast MAC address*/ 
      





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

          send_packet(sr, pkt_list->buf, pkt_list->len, pkt_list->iface);
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
