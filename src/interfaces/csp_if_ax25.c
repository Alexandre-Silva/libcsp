#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_ether.h>

#include <csp/arch/csp_malloc.h>
#include <csp/arch/csp_thread.h>
#include <csp/csp_debug.h>
#include <csp/csp_endian.h>
#include <csp/csp_error.h>
#include <csp/csp_interface.h> /* csp_route_add_if */
#include <csp/interfaces/csp_if_ax25.h>

#include <netax25/ax25.h>
#include <netax25/axconfig.h>
#include <netax25/axlib.h>

/* Private functions */

char *csp_ax25_localcall(char *ax25_port);

/* Mappings CSP_ID -> Callsign suffix */
char *csp_ax25_map_callsign(int call);

/* Functions used by rx thread/task */
CSP_DEFINE_TASK(ax25_rx);

/* Globals (but within this file only) */
static int g_txsock, g_rxsock;
static char *g_localcall;
static csp_thread_handle_t g_handle_rx;
static struct full_sockaddr_ax25 g_src;
static int g_slen;

/* This array maps csp host addresses to ax25 callsigns. To map a csp addt to a
   call retrieve the char* in csp_ax25_rtable[csp_addr] */
char *csp_ax25_rtable[CSP_ID_HOST_MAX + 1];

/** Interface definition */
csp_iface_t csp_if_ax25 = {.name = "AX.25",
                           .nexthop = &csp_ax25_tx,
                           // 255 AX.25 MTU - Header AX.25 - Header CSP
                           .mtu = (255 - sizeof(csp_id_t))};

int csp_ax25_init(char *ax25_port) {
  /* regist the AX.25 interface into CSP stack */
  csp_route_add_if(&csp_if_ax25);
  printf(
      "\n\n\
			:::::::::::::::::::::::::::: INFO ::::::::::::::::::::::::::::::\n\
			You are using the CSP/AX.25 adaptation layer\n\
			This software was written by Joao Ferreira (joaoahf@gmail.com) \n\
			For more information please visit: http://istnanosat.ist.utl.pt\n\
			::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

  /* init csp_ax25_rtable */
  for (int i = 0; i < CSP_ID_HOST_MAX + 1; i++) csp_ax25_rtable[i] = NULL;

  return csp_ax25_set_call(ax25_port);
}

int csp_ax25_set_call(char *ax25_port) {
  char localshifted[32];

  /* load ports from configuration */
  if (ax25_config_load_ports() == 0) {
    fprintf(stderr, "No AX.25 ports defined\n");
    return CSP_ERR_DRIVER;
  }

  /* get local callsign */
  g_localcall = csp_ax25_localcall(ax25_port);

  if (g_localcall == NULL) {
    fprintf(stderr, "Error reading local callsign..");
    return CSP_ERR_DRIVER;
  }

  /* fill the g_src structure */
  memset(&g_src, 0, sizeof(g_src));
  if ((g_slen = ax25_aton(g_localcall, &g_src)) == -1) {
    perror("Unable to convert source callsign \n");
    return CSP_ERR_DRIVER;
  }

  /* let's validate our local call */
  if (ax25_aton_entry(g_localcall, localshifted) == -1) {
    perror("Can't shift local callsign: \n");
    return CSP_ERR_DRIVER;
  }

  if (ax25_validate(localshifted) == 0) {
    fprintf(stderr, "Local callsign not valid\n");
    return CSP_ERR_DRIVER;
  }

  return CSP_ERR_NONE;
}

int csp_ax25_start() {
  /* Prepare tx socket
   * 	PID=0xF0 =>  l3 protocol not specified..
   * 	http://www.tapr.org/pub_ax25.html#2.2.4
   **/
  if ((g_txsock = socket(AF_AX25, SOCK_DGRAM, 0xF0)) == -1) {
    perror("libcsp:if_ax25:rxsocket() error:");
    return CSP_ERR_DRIVER;
  }

  /* bind local callsign to our g_txsock */
  if (bind(g_txsock, (struct sockaddr *)&g_src, g_slen) == -1) {
    perror("libcsp:if_ax25:bind() error:");
    return CSP_ERR_DRIVER;
  }

  /* Prepare rx socket
   *
   * NOTE:
   * PF_PACKET/SOCK_PACKET confiuration is used here,
   * because the AF_AX25/SOCK_DRAM does not
   * allow wildcards in remoteaddr, then recvfrom() would need match,
   * both dest and g_src addresses.
   *
   **/
  if ((g_rxsock = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_AX25))) == -1) {
    perror("socket() error: ");
    return CSP_ERR_DRIVER;
  }

  /* launch reception thread... */
  csp_thread_create(&ax25_rx, (signed char *)"AX25-RX", 1000, NULL, 0,
                    &g_handle_rx);

  return CSP_ERR_NONE;
}

int csp_ax25_stop() { return CSP_ERR_NONE; }

CSP_DEFINE_TASK(ax25_rx) {
  struct full_sockaddr_ax25 src;
  int size;
  socklen_t srcs = sizeof(src);
  int payload_s;
  char buffer[csp_if_ax25.mtu];
  csp_packet_t *packet = NULL;

  while (1) {
    /* clean the receive buffer */
    memset(buffer, 0, csp_if_ax25.mtu + CSP_HEADER_LENGTH + AX25_HEADER_S);

    /* hold for incomming packets */
    size = recvfrom(g_rxsock, buffer,
                    csp_if_ax25.mtu + CSP_HEADER_LENGTH + AX25_HEADER_S, 0,
                    (struct sockaddr *)&src, &srcs);
    if (size == -1) {
      perror("Error in AX.25 frame reception..\n");
      fprintf(stderr, "error in ax.25 fram reception..\n");
      return NULL;
    }

    /* offset eval */
    payload_s = size - AX25_HEADER_S - CSP_HEADER_LENGTH;

    /* alloc new packet */
    // packet = csp_buffer_get(csp_if_ax25.mtu);
    packet = csp_buffer_get(sizeof(csp_packet_t) + payload_s);
    if (packet == NULL) {
      perror("Cannot allocate packet memory: ");
      fprintf(stderr, "cannot allocate packet mem");
      continue;
    }

    /* fill the packet with incomming CSP data */
    /* copy packet header and convert it into host endianess */
    memcpy(&(packet->id.ext), &(buffer[AX25_HEADER_S]), CSP_HEADER_LENGTH);
    packet->id.ext = csp_ntoh32(packet->id.ext);

    /* set the packet payload and size*/
    memcpy(&(packet->data), &(buffer[CSP_HEADER_LENGTH + AX25_HEADER_S]),
           payload_s);
    packet->length = payload_s;

    /* The next validation filters the unknown packets,
     * because the g_rxsock have very permissive filter (all UI Frames)
     * later, the application must also filter, acording to
     * the binded port.
     */
    if (packet->id.dst != my_address) {
      csp_log_warn(
          "CSP Packet dropped: DST CSP_ID[%d] differ FROM local ADDR[%d]\n",
          packet->id.dst, my_address);
      csp_buffer_free(packet);
    } else {
      /* update stats */
      csp_if_ax25.frame++;

      /* inject packet into routing system */
      csp_new_packet(packet, &csp_if_ax25,
                     NULL);  // NULL -> Called from task (csp_interface.h)
    }
  }
  printf("asdasdaad\n");
  return CSP_TASK_RETURN;
}

int csp_ax25_tx(struct csp_iface_s *interface, csp_packet_t *packet,
                uint32_t timeout) {
  struct full_sockaddr_ax25 dest;
  int dlen;
  char *destcall;
  char txbuf[csp_if_ax25.mtu + CSP_HEADER_LENGTH];

  /* wich callsign is associated with this CSP ID ? */
  destcall = csp_ax25_map_callsign(packet->id.dst);

  if (csp_if_ax25.mtu < packet->length) {
    csp_log_error("packet->length is bigger than txbuf\n");
    exit(-1);
  }
  /* fill the dest ax25 structure */
  if ((dlen = ax25_aton(destcall, &dest)) == -1) {
    fprintf(stderr, "Unable to convert destination callsign '%s'\n", destcall);
    return CSP_ERR_DRIVER;
  }

  //	printf("\n######## I will send the packet: \n");
  //	printf("-> Payload is: %s\n", packet->data);
  //	printf("-> Packet size (bytes) [ %d ]\n", packet->length);
  //	printf("-> FROM: CSP_id [ %d ] || Callsign [ %s ] \n", packet->id.g_src,
  // g_localcall);
  //	printf("-> TO: CSP_id [ %d ] port [ %d ] || Callsign [ %s ]\n",
  // packet->id.dst, packet->id.dport, destcall);
  //	printf("#################################\n");

  /* prepare (alloc&clean) transmition buffer */
  /* char *txbuf = (char *)malloc(packet->length + CSP_HEADER_LENGTH); */
  /* if (txbuf == NULL) { */
  /*   perror("Unable to alloc AX.25 outgoing buffer"); */
  /*   return CSP_ERR_TX; */
  /* } */

  memset(txbuf, 0, CSP_HEADER_LENGTH + packet->length);

  /* fill the buffer with packet header (in network format) */
  packet->id.ext = csp_hton32(packet->id.ext);
  memcpy(txbuf, &packet->id.ext, CSP_HEADER_LENGTH);

  /* copy the packet payload to the buffer */
  memcpy(&txbuf[CSP_HEADER_LENGTH], &packet->data, packet->length);

  /* send the CSP packet inside our AX.25 frame through g_txsock FD */
  if (sendto(g_txsock, txbuf, packet->length + CSP_HEADER_LENGTH, 0,
             (struct sockaddr *)&dest, dlen) == -1) {
    perror("Unable to send AX.25 frame: \n");
    return CSP_ERR_TX;
  }

  /* release memory... */
  csp_buffer_free(packet);
  /* free(txbuf); */
  csp_free(destcall);
  return CSP_ERR_NONE;
}

int csp_ax25_rtable_set(uint8_t csp_addr, char *ax25_call) {
  if (csp_addr > CSP_ID_HOST_MAX + 1) {
    csp_log_error(
        "Failed to set csp_ax25_rtable mapping because the provided csp_addr "
        "is invalid.");
    return CSP_ERR_DRIVER;
  }

  char *old_call = csp_ax25_rtable[csp_addr];
  csp_log_info("csp_ax25_rtable: %d --> %s , (was: %s)", csp_addr, old_call,
               ax25_call);
  if (old_call != NULL) csp_free(old_call);
  csp_ax25_rtable[csp_addr] = ax25_call;

  return CSP_ERR_NONE;
}
/* Mappings CSP_ID -> Callsign suffix */
char *csp_ax25_map_callsign(int call) {
  int call_suf = 0;
  char *ret;
  ret = (char *)malloc(10 * sizeof(char));

  if (call == SAT_ADDR) call_suf = 11;  // 11 -> Callsign

  if (call == GS_ADDR) call_suf = 1;

  sprintf(ret, "CS5CEP-%d", call_suf);
  return ret;
}

char *csp_ax25_localcall(char *ax25_port) {
  char *ret = NULL;

  if ((ret = ax25_config_get_addr(ax25_port)) == NULL) {
    fprintf(stderr, "Invalid AX.25 port [ %s ]\n", ax25_port);
    return NULL;
  }
  return ret;
}
