#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_icmp.h"
#include "sr_if.h"
#include "sr_protocol.h"


void handle_icmp(struct sr_instance *sr, int type, int code,  uint8_t * packet,
        unsigned int len,
        char* interface) {

         sr_icmp_hdr * icmp_msg;
         sr_ethernet_hdr * eth_hdr;
         sr_ip_hdr * ip_hdr;

         icmp_msg->icmp_type = type;
         icmp_msg->icmp_code = code;
         icmp_msg->icmp_sum = 0;

         ip_hdr->ip_tos = 0;
         ip_hdr->ip_len = htons(sizeof(/*whatever data is being sent*/));
         ip_hdr->ip_off = htons(0);
         /*ip_hdr->ip_ttl = ;*/
         ip_hdr->ip_p = 1;
         ip_hdr->ip_sum = 0;
         ip_hdr->src = /*interface ip*/;
         ip_hdr->dst = /*interface ip*/;

         eth_hdr->ether_dhost = ;
         eth_hdr->ether_shost = ;
         eth_hdr->ether_type = ;
}
