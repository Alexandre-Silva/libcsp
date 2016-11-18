#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
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

#include <pthread.h>  // only while csp_thread_join is not implemented

/* Private functions */

/* Functions used by rx thread/task */
CSP_DEFINE_TASK(ax25_rx);

/* Globals (but within this file only) */
static int g_txsock = 0, g_rxsock = 0;
static char *g_localcall = NULL;
static ax25_address g_localcall_addr;
static csp_thread_handle_t g_handle_rx;
static bool g_rx_stop_flag = false;
static struct full_sockaddr_ax25 g_src;
static int g_slen;

/** Interface definition */
csp_iface_t csp_if_ax25 = {.name = "AX.25",
                           .nexthop = &csp_ax25_tx,
                           // 255 AX.25 MTU - Header AX.25 - Header CSP
                           .mtu = (255 - sizeof(csp_id_t))};

/* This array maps csp host addresses to ax25 callsigns. */
/* Inside this file, the read directly in csp_ax25_tx() and written to in
 * ax25_rx_task */
ax25_address csp_ax25_ctable[CSP_ID_HOST_MAX + 1];

int csp_ax25_init(char *ax25_port) {
  printf(
      "\n\n\
			:::::::::::::::::::::::::::: INFO ::::::::::::::::::::::::::::::\n\
			You are using the CSP/AX.25 adaptation layer\n\
			This software was written by Joao Ferreira (joaoahf@gmail.com) \n\
			For more information please visit: http://istnanosat.ist.utl.pt\n\
			::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

  /* register the AX.25 interface into CSP stack */
  csp_route_add_if(&csp_if_ax25);

  /* inits and veirfies local callsign */
  if (csp_ax25_set_call(ax25_port) != CSP_ERR_NONE) return CSP_ERR_DRIVER;

  /* init csp_ax25_ctable */
  bzero(csp_ax25_ctable, sizeof(csp_ax25_ctable));
  if (csp_ax25_ctable_set(my_address, g_localcall)) return CSP_ERR_DRIVER;

  return CSP_ERR_NONE;
}

int csp_ax25_set_call(char *ax25_port) {
  char localshifted[32];

  /* load ports from configuration */
  if (ax25_config_load_ports() == 0) {
    csp_log_error("set_call(), No AX.25 ports defined\n");
    return CSP_ERR_DRIVER;
  }

  if (g_localcall != NULL) csp_free(g_localcall);

  /* get local callsign */
  if ((g_localcall = ax25_config_get_addr(ax25_port)) == NULL) {
    csp_log_error("set_call(), invalid ax.25 port:%s\n", ax25_port);
    return CSP_ERR_DRIVER;
  }

  /* fill the g_src structure */
  memset(&g_src, 0, sizeof(g_src));
  if ((g_slen = ax25_aton(g_localcall, &g_src)) == -1) {
    csp_log_error("set_call(), Unable to convert source callsign \n");
    return CSP_ERR_DRIVER;
  }

  /* let's validate our local call */
  if (ax25_aton_entry(g_localcall, localshifted) == -1) {
    csp_log_error("set_call(), Can't shift local callsign: \n");
    return CSP_ERR_DRIVER;
  }

  if (ax25_validate(localshifted) == 0) {
    csp_log_error("set_call(), Local callsign not valid\n");
    return CSP_ERR_DRIVER;
  }

  /* size_t call_len = strlen(g_localcall); */
  /* for (int i = sizeof(ax25_address) - 1; i >= 0; i--) */
  /*   if (i < call_len) */
  /*     g_localcall_addr.ax25_call[i] = g_localcall[i]; */
  /*   else */
  /*     g_localcall_addr.ax25_call[i] = ' '; */

  /* memcpy(g_localcall_addr, g_localcall, sizeof(ax25_address)); */

  ax25_aton_entry(g_localcall, g_localcall_addr.ax25_call);

  return CSP_ERR_NONE;
}

int csp_ax25_start(void) {
  /* Prepare tx socket
   * 	PID=0xF0 =>  l3 protocol not specified..
   * 	http://www.tapr.org/pub_ax25.html#2.2.4
   **/
  if ((g_txsock = socket(AF_AX25, SOCK_DGRAM, 0xF0)) == -1) {
    perror("start(), rxsocket() error");
    return CSP_ERR_DRIVER;
  }

  /* bind local callsign to our g_txsock */
  if (bind(g_txsock, (struct sockaddr *)&g_src, g_slen) == -1) {
    perror("start(), bind() error");
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
    perror("start(), socket() error");
    return CSP_ERR_DRIVER;
  }

  // sets a recv timout such that the rcthread can periodically check
  // g_rx_stop_flag
  struct timeval tv;
  tv.tv_sec = 5;   /* in Secs Timeout */
  tv.tv_usec = 0;  // Not init'ing this can cause strange errors
  setsockopt(g_rxsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
             sizeof(struct timeval));

  g_rx_stop_flag = false;

  /* launch reception thread... */
  csp_thread_create(&ax25_rx, (signed char *)"AX25-RX", 1000, NULL, 0,
                    &g_handle_rx);

  return CSP_ERR_NONE;
}

int csp_ax25_stop(void) {
  if (close(g_rxsock) != 0) {
    csp_log_error("Failed to succesfully close CSP's AX25 layer rx socket.\n");
    return CSP_ERR_DRIVER;
  }

  if (close(g_txsock) != 0) {
    csp_log_error("Failed to succesfully close CSP's AX25 layer tx socket.\n");
    return CSP_ERR_DRIVER;
  }

  // Next verification rxthread should return
  g_rx_stop_flag = true;

  /* csp_thread_join(&ax25_rx); */  // join is not yet implemented
  if (pthread_join(g_handle_rx, NULL) != 0) {
    csp_log_error("Failed to succesfully terminate CSP:AX25 rx task.\n");
    return CSP_ERR_DRIVER;
  }

  printf("Joined rx task\n");

  return CSP_ERR_NONE;
}

CSP_DEFINE_TASK(ax25_rx) {
  struct full_sockaddr_ax25 src;
  int size;
  socklen_t srcs = sizeof(src);
  int payload_s;
  char buffer[AX25_MAX_LEN];
  csp_packet_t *packet = NULL;

  while (1) {
    /* clean the receive buffer */
    memset(buffer, 0, AX25_MAX_LEN);

    /* hold for incomming packets */
    size = recvfrom(g_rxsock, buffer, AX25_MAX_LEN, 0, (struct sockaddr *)&src,
                    &srcs);
    if (size == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (g_rx_stop_flag) {
          return CSP_TASK_RETURN;
        } else {
          continue;
        }
      } else {
        csp_log_warn("Error in AX.25 frame reception..\n");
        return CSP_TASK_RETURN;
      }
    }

    ax25_address *dest_call_p, *src_call_p;
    dest_call_p = (ax25_address *)&buffer[KISS_HEADER_S];
    src_call_p = (ax25_address *)&buffer[KISS_HEADER_S + AX25_NCALL_S];

    if (ax25_cmp(dest_call_p, &g_localcall_addr) != 0) {
      //  csp_log_info("ax25_rx: received frame's dest callsign != my
      //  callsign.\n"); //TODO remove this
      continue;
    }

    // TODO remove this and use `src`
    char dest_s[7], src_s[7];
    memcpy(dest_s, ax25_ntoa(dest_call_p), sizeof(dest_s));
    memcpy(src_s, ax25_ntoa(src_call_p), sizeof(src_s));
    csp_log_info("ax25_rx: recv frame dest:%s src:%s\n", dest_s, src_s);

    /* offset eval */
    payload_s = size - AX25_HEADER_I_S - CSP_HEADER_LENGTH;

    /* alloc new packet */
    // packet = csp_buffer_get(csp_if_ax25.mtu);
    packet = csp_buffer_get(sizeof(csp_packet_t) + payload_s);
    if (packet == NULL) {
      csp_log_warn("ax25_rx: Cannot allocate packet memory\n");
      continue;
    }

    /* fill the packet with incomming CSP data */
    /* copy packet header and convert it into host endianess */
    memcpy(&(packet->id.ext), &(buffer[AX25_HEADER_I_S]), CSP_HEADER_LENGTH);
    packet->id.ext = csp_ntoh32(packet->id.ext);

    if (packet->id.src > CSP_ID_HOST_MAX || packet->id.dst > CSP_ID_HOST_MAX) {
      csp_free(packet);
      csp_log_error("rx_task: received a packet with invalid control field.");
      continue;
    }

    /* update ax25 call sign table */
    memcpy(&csp_ax25_ctable[packet->id.src], src_call_p, sizeof(ax25_address));

    /* set the packet payload and size*/
    memcpy(&(packet->data), &(buffer[CSP_HEADER_LENGTH + AX25_HEADER_I_S]),
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
  return CSP_TASK_RETURN;
}

int csp_ax25_tx(struct csp_iface_s *interface, csp_packet_t *packet,
                uint32_t timeout) {
  if (csp_if_ax25.mtu < packet->length) {
    csp_log_error("ax25_tx(), packet->length is bigger than txbuf\n");
    exit(-1);
  }

  struct sockaddr_ax25 dest_addr;
  bzero((char *)&dest_addr, sizeof(dest_addr));
  dest_addr.sax25_family = AF_AX25;
  dest_addr.sax25_ndigis = 0;
  memcpy(&dest_addr.sax25_call, &csp_ax25_ctable[packet->id.dst],
         sizeof(ax25_address));

  //	printf("\n######## I will send the packet: \n");
  //	printf("-> Payload is: %s\n", packet->data);
  //	printf("-> Packet size (bytes) [ %d ]\n", packet->length);
  //	printf("-> FROM: CSP_id [ %d ] || Callsign [ %s ] \n", packet->id.g_src,
  // g_localcall);
  //	printf("-> TO: CSP_id [ %d ] port [ %d ] || Callsign [ %s ]\n",
  // packet->id.dst, packet->id.dport, destcall);
  //	printf("#################################\n");

  char txbuf[csp_if_ax25.mtu + CSP_HEADER_LENGTH];
  bzero(txbuf, CSP_HEADER_LENGTH + packet->length);

  /* fill the buffer with packet header (in network format) */
  packet->id.ext = csp_hton32(packet->id.ext);
  memcpy(txbuf, &packet->id.ext, CSP_HEADER_LENGTH);

  /* copy the packet payload to the buffer */
  memcpy(&txbuf[CSP_HEADER_LENGTH], &packet->data, packet->length);

  /* send the CSP packet inside our AX.25 frame through g_txsock FD */
  if (sendto(g_txsock, txbuf, packet->length + CSP_HEADER_LENGTH, 0,
             (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1) {
    csp_log_error("ax25_tx(), Unable to send AX.25 frame: \n");
    return CSP_ERR_TX;
  }

  /* release memory... */
  csp_buffer_free(packet);
  return CSP_ERR_NONE;
}

int csp_ax25_ctable_set(uint8_t csp_addr, char *ax25_call) {
  if (csp_addr > CSP_ID_HOST_MAX) {
    csp_log_error(
        "ctable_set(): supplied csp_addr:%d is larger than "
        "CSP_ID_HOST_MAX\n");
    return CSP_ERR_DRIVER;
  }

  char *old_call = ax25_ntoa(&csp_ax25_ctable[csp_addr]);
  csp_log_info("csp_ax25_ctable: %d --> %s , (was: %s)\n", csp_addr, ax25_call,
               old_call);

  ax25_aton_entry(ax25_call, csp_ax25_ctable[csp_addr].ax25_call);

  return CSP_ERR_NONE;
}

char *csp_ax25_ctable_get(uint8_t csp_addr) {
  if (csp_addr > CSP_ID_HOST_MAX) {
    csp_log_error(
        "ctable_get(): supplied csp_addr:%d is larger than CSP_ID_HOST_MAX\n",
        csp_addr);
    return NULL;
  }

  char *ret = NULL;
  char *call = ax25_ntoa(&csp_ax25_ctable[csp_addr]);
  if (call != NULL) {
    size_t call_len = strlen(call) + 1;  // str size + '\0' char
    ret = csp_malloc(call_len);
    memcpy(ret, call, call_len);
  }

  return ret;
}
