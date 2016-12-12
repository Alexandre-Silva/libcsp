#include <errno.h>
#include <fcntl.h>
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
/**
 * Returns a reference to the ax25 address stored in csp_ax25_ctable which maps
 * from `csp_addr`.
 *
 * @param[in]: csp_addr, The key for which a next hop is needed.
 * @returns: pointer to ax25_address in the table, even if the value is null.
 */
ax25_address *csp_ax25_ctable_get_(uint8_t csp_addr);

/**
 * Updates the AX25 next hop for `csp_addr` with `hop`.
 *
 * @param[in]: csp_addr, The key for which a next hop is to be set.
 * @param[in]: hop, The new update ax25 next hop.
 * @returns: true if the new ax25 addr was set, false if new value is equal to
 * old one.
 */
bool csp_ax25_ctable_set_(uint8_t csp_addr, ax25_address *hop);

/* Functions used by rx thread/task */
CSP_DEFINE_TASK(ax25_rx);

/* Constants */
typedef enum {
  CSP_IF_AX25_NONE,
  CSP_IF_AX25_UI,
  CSP_IF_AX25_CO,  // connections oriented
} if_mode;
/* Globals (but within this file only) */

/*  sockets */
static int g_txsock = 0, g_rxsock = 0;

static csp_thread_handle_t g_handle_rx;
static bool g_rx_stop_flag = false;
static struct full_sockaddr_ax25 g_src;
static int g_slen;
static if_mode g_mode = CSP_IF_AX25_NONE;

// local callsign in network format (with depends in g_src)
static ax25_address *g_localcall = &g_src.fsa_ax25.sax25_call;

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

  /* set local csp addr --> ax25 call mapping */
  csp_ax25_ctable_set_(my_address, g_localcall);

  return CSP_ERR_NONE;
}

int csp_ax25_set_call(char *ax25_port) {
  char localshifted[32];

  /* load ports from configuration */
  if (ax25_config_load_ports() == 0) {
    csp_log_error("set_call(), No AX.25 ports defined\n");
    return CSP_ERR_DRIVER;
  }

  /* get local callsign */
  static char *localcall = NULL;
  if ((localcall = ax25_config_get_addr(ax25_port)) == NULL) {
    csp_log_error("set_call(), invalid ax.25 port:%s\n", ax25_port);
    return CSP_ERR_DRIVER;
  }

  /* fill the g_src structure */
  memset(&g_src, 0, sizeof(g_src));
  if ((g_slen = ax25_aton(localcall, &g_src)) == -1) {
    csp_log_error("set_call(), Unable to convert source callsign \n");
    return CSP_ERR_DRIVER;
  }

  /* let's validate our local call */
  if (ax25_aton_entry(localcall, localshifted) == -1) {
    csp_log_error("set_call(), Can't shift local callsign: \n");
    return CSP_ERR_DRIVER;
  }

  if (ax25_validate(localshifted) == 0) {
    csp_log_error("set_call(), Local callsign not valid\n");
    return CSP_ERR_DRIVER;
  }

  return CSP_ERR_NONE;
}

int csp_ax25_start_ui(void) {
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
  tv.tv_sec = 5;   /* in secs Timeout */
  tv.tv_usec = 0;  // Not init'ing this can cause strange errors
  setsockopt(g_rxsock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
             sizeof(struct timeval));

  g_rx_stop_flag = false;

  /* launch reception thread... */
  csp_thread_create(&ax25_rx, (signed char *)"AX25-RX", 1000, NULL, 0,
                    &g_handle_rx);

  return CSP_ERR_NONE;
}

int csp_ax25_start_co(int connfd) {
  if (g_mode != CSP_IF_AX25_NONE) {
    csp_log_error("AX25 layer is already initialized");
    return CSP_ERR_DRIVER;
  }

  if (connfd < 0) return CSP_ERR_DRIVER;

  // set socket in non blocking mode
  int flags = fcntl(connfd, F_GETFL, 0);
  if (flags < 0) return CSP_ERR_DRIVER;
  flags = flags | O_NONBLOCK;
  if (fcntl(connfd, F_SETFL, flags)) return CSP_ERR_DRIVER;

  g_rxsock = connfd;
  g_txsock = connfd;
  g_mode = CSP_IF_AX25_CO;

  /* launch reception thread... */
  if (csp_thread_create(&ax25_rx, (signed char *)"AX25-RX", 1000, NULL, 0,
                        &g_handle_rx)) {
    csp_log_error("AX25 layer failed to spawn task/thread\n");
    return CSP_ERR_DRIVER;
  }

  return CSP_ERR_NONE;
}

int csp_ax25_stop(void) {
  switch (g_mode) {
    case CSP_IF_AX25_NONE:
      return CSP_ERR_NONE;

    case CSP_IF_AX25_UI: {
      if (close(g_rxsock) != 0) {
        csp_log_error(
            "Failed to succesfully close CSP's AX25 layer rx socket.\n");
        return CSP_ERR_DRIVER;
      }

      if (close(g_txsock) != 0) {
        csp_log_error(
            "Failed to succesfully close CSP's AX25 layer tx socket.\n");
        return CSP_ERR_DRIVER;
      }

      break;
    }

    case CSP_IF_AX25_CO: {
      if (close(g_rxsock) != 0) {
        csp_log_error(
            "Failed to succesfully close CSP's AX25 layer connection "
            "socket.\n");
        return CSP_ERR_DRIVER;
      }
      break;
    }
  }

  // Next verification rxthread should return
  g_rx_stop_flag = true;

  /* csp_thread_join(&ax25_rx); */  // join is not yet implemented
  if (pthread_join(g_handle_rx, NULL) != 0) {
    csp_log_error("Failed to succesfully terminate CSP:AX25 rx task.\n");
    return CSP_ERR_DRIVER;
  }
  printf("Joined rx task\n");

  g_mode = CSP_IF_AX25_NONE;
  return CSP_ERR_NONE;
}

/**
 * Handles the reception of data from the socket.
 *
 * @param[in,out] buffer: where received data (if any) will be stored. Must be
 * at least AX25_MAX_LEN large.
 * @returns: -2 on unexpected error, -1 if nothing was received, 0 if connection
 * was lost. Values larger than 0 are the size of the data written to buffer.
 */
static ssize_t rx_recv(char *buffer) {
  ssize_t size = 0;

  switch (g_mode) {
    case CSP_IF_AX25_NONE: {
      csp_log_warn(
          "AX25 layer rxtask is returning because layer mode is NONE\n");
      return -2;
    }

    case CSP_IF_AX25_UI: {
      size = recvfrom(g_rxsock, buffer, AX25_MAX_LEN, 0, NULL, NULL);
      break;
    }

    case CSP_IF_AX25_CO: {
      size = recv(g_rxsock, buffer, AX25_MAX_LEN, 0);
      break;
    }
  }

  if (size == 0) {
    csp_log_info("AX25 layer rxsocket disconnected");

  } else if (size == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return -1;

    } else {
      perror("csp_if_ax25:");
      csp_log_warn("Error in AX.25 frame reception..\n");
      return -2;
    }
  }

  return size;
}

// Checks if the dest addr of the ax25 frame is the local host
static int check_ax25_dest(const char *buffer) {
  ax25_address *dest_call_p, *src_call_p;
  dest_call_p = (ax25_address *)&buffer[KISS_HEADER_S];
  src_call_p = (ax25_address *)&buffer[KISS_HEADER_S + AX25_NCALL_S];

  if (ax25_cmp(dest_call_p, g_localcall) != 0) {
    /* csp_log_info("ax25_rx: received frame's dest callsign != my
     * callsign.\n"); */
    return -1;
  }

  // TODO remove this and use `src`
  char dest_s[7], src_s[7];
  memcpy(dest_s, ax25_ntoa(dest_call_p), sizeof(dest_s));
  memcpy(src_s, ax25_ntoa(src_call_p), sizeof(src_s));
  csp_log_info("ax25_rx: recv frame dest:%s src:%s\n", dest_s, src_s);

  return 0;
}

static csp_packet_t *frame_payload2packet(const char *buffer, size_t size,
                                          bool has_ax25_header) {
  size_t header_offset = 0;
  size_t payload_offset = 0;
  ssize_t payload_s = 0;

  if (has_ax25_header) {
    header_offset = AX25_HEADER_I_S;
    payload_offset = CSP_HEADER_LENGTH + AX25_HEADER_I_S;
    payload_s = size - AX25_HEADER_I_S - CSP_HEADER_LENGTH;
  } else {
    header_offset = 0;
    payload_offset = CSP_HEADER_LENGTH;
    payload_s = size - CSP_HEADER_LENGTH;
  }

  if (payload_s < 0) {
    csp_log_warn("ax25_rx: Received invalid/corrupts frame.");
    return NULL;
  }

  /* alloc new packet */
  // packet = csp_buffer_get(csp_if_ax25.mtu);
  csp_packet_t *packet = csp_buffer_get(sizeof(csp_packet_t) + payload_s);
  if (packet == NULL) {
    csp_log_warn("ax25_rx: Cannot allocate packet memory\n");
    return NULL;
  }

  /* fill the packet with incomming CSP data */
  /* copy packet header and convert it into host endianess */
  memcpy(&(packet->id.ext), &(buffer[header_offset]), CSP_HEADER_LENGTH);
  packet->id.ext = csp_ntoh32(packet->id.ext);

  if (packet->id.src > CSP_ID_HOST_MAX || packet->id.dst > CSP_ID_HOST_MAX) {
    csp_free(packet);
    csp_log_error("rx_task: received a packet with invalid control field.");
    return NULL;
  }

  /* set the packet payload and size*/
  memcpy(&(packet->data), &(buffer[payload_offset]), payload_s);
  packet->length = payload_s;

  return packet;
}

static csp_packet_t *new_empty_packet(void) {
  csp_packet_t *packet = csp_buffer_get(sizeof(csp_packet_t));
  if (packet == NULL) {
    csp_log_warn("ax25_rx: Cannot allocate packet memory\n");
    return NULL;
  }

  packet->length = 0;
  packet->id.ext = 0;  // initialize

  packet->id.pri = 2;

  packet->id.dst = my_address;
  packet->id.dport = CSP_ANY;

  return packet;
}

static void deliver_packet(csp_packet_t *packet) {
  /* The next validation filters the unknown packets, because the g_rxsock
   * have very permissive filter (all UI Frames) later, the application must
   * also filter, acording to the bound port.
   *
   * TODO remove this check to allow forwading of csp packets.
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
    // NULL -> Called from task (csp_interface.h)
    csp_new_packet(packet, &csp_if_ax25, NULL);
  }
}
static void update_ctable(uint8_t csp_src, const char *buffer) {
  ax25_address *ax25_src =
      (ax25_address *)&buffer[KISS_HEADER_S + AX25_NCALL_S];

  /* returns true if new value != old */
  if (csp_ax25_ctable_set_(csp_src, ax25_src)) {
    char *new_call = ax25_ntoa(csp_ax25_ctable_get_(csp_src));
    csp_log_info("csp_ax25_ctable: %d --> %s\n", csp_src, new_call);
  }
}

CSP_DEFINE_TASK(ax25_rx) {
  char buffer[AX25_MAX_LEN];
  ssize_t size;
  csp_packet_t *packet = NULL;

  while (1) {
    /* hold for incomming packets */
    size = rx_recv(buffer);

    switch (size) {
      // Connection lost (normaly i.e 0, or forcefully i.e. -2)
      case -2:
      case 0: {
        packet = new_empty_packet();
        if (packet) deliver_packet(packet);
        return CSP_TASK_RETURN;
      }

      // No data to be 'recv()'ied. But socket in non-blocking mode so...
      case -1:
        // TODO remove this. workaround for libax25 being half-duplex on send()
        // and recv()
        sleep(1);
        continue;

      default: {
        /* Checks if ax25 destination addr matches the local callsign. i.e. the
           frame was sent to local host */
        if (g_mode == CSP_IF_AX25_UI && check_ax25_dest(buffer)) continue;

        // in CO mode, and size is 0 (i.e. sock disconnected) a empty csp packet
        // will be produced and delivered.
        packet = frame_payload2packet(buffer, size, g_mode == CSP_IF_AX25_UI);
        if (packet == NULL) continue;

        if (g_mode == CSP_IF_AX25_UI) update_ctable(packet->id.src, buffer);

        /* Deliver the packet to libcsp proper */
        deliver_packet(packet);
      }
    }
  }
  return CSP_TASK_RETURN;
}

/**
 * Discovers and fills `ax25_addr` with the AX25 address of the next hop host
 * for the provided `csp_addr`
 *
 * @ruturns: 0 on success, -1 if CSP addr has no determined next hop;
 */
static int next_hop(struct sockaddr_ax25 *ax25_addr, uint8_t csp_addr) {
  if (csp_ax25_ctable_is_null(csp_addr)) return -1;

  bzero((char *)ax25_addr, sizeof(struct sockaddr_ax25));
  ax25_addr->sax25_family = AF_AX25;
  ax25_addr->sax25_ndigis = 0;

  memcpy(&ax25_addr->sax25_call, (void *)csp_ax25_ctable_get_(csp_addr),
         sizeof(ax25_addr->sax25_call));

  return 0;
}

// Inserts the csp `packet` into `buffer` which will be the payload of the AX25
// send().
static size_t packet2frame(const csp_packet_t *packet, char *buffer) {
  //	printf("\n######## I will send the packet: \n");
  //	printf("-> Payload is: %s\n", packet->data);
  //	printf("-> Packet size (bytes) [ %d ]\n", packet->length);
  //	printf("-> FROM: CSP_id [ %d ] || Callsign [ %s ] \n", packet->id.g_src,
  // g_localcall);
  //	printf("-> TO: CSP_id [ %d ] port [ %d ] || Callsign [ %s ]\n",
  // packet->id.dst, packet->id.dport, destcall);
  //	printf("#################################\n");

  bzero(buffer, CSP_HEADER_LENGTH + packet->length);

  /* fill the buffer with packet header (in network format) */
  uint32_t id_n = csp_hton32(packet->id.ext);
  memcpy(buffer, &id_n, CSP_HEADER_LENGTH);

  /* copy the packet payload to the buffer */
  memcpy(&buffer[CSP_HEADER_LENGTH], &packet->data, packet->length);

  return packet->length + CSP_HEADER_LENGTH;
}

int csp_ax25_tx(struct csp_iface_s *interface, csp_packet_t *packet,
                uint32_t timeout) {
  if (g_mode == CSP_IF_AX25_NONE) {
    csp_log_error(
        "ax25_tx(), Cannot send frame when AX25 layer is not running.\n");
    return CSP_ERR_TX;
  }

  if (csp_if_ax25.mtu < packet->length) {
    csp_log_error("ax25_tx(), packet->length is bigger than txbuf\n");
    exit(-1);
  }

  if (csp_ax25_ctable_is_null(packet->id.dst)) {
    csp_log_error("csp_ax25_tx(), No know next hop\n");
    return CSP_ERR_TX;
  }

  /* get next node's ax25 address via csp addr */
  struct sockaddr_ax25 dest_addr;
  if (g_mode == CSP_IF_AX25_UI) {
    if (next_hop(&dest_addr, packet->id.dst)) return CSP_ERR_TX;
  }

  char buffer[csp_if_ax25.mtu + CSP_HEADER_LENGTH];
  size_t length = packet2frame(packet, buffer);

  if (g_mode == CSP_IF_AX25_UI) {
    /* send the CSP packet inside our AX.25 frame through g_txsock FD */
    /* note: sento's dest_ddr field is ignored for connection-mode sockets */
    if (sendto(g_txsock, buffer, length, 0, (struct sockaddr *)&dest_addr,
               sizeof(dest_addr)) == -1) {
      csp_log_error("csp_ax25_tx(), Unable to send AX.25 frame: \n");
      return CSP_ERR_TX;
    }
  } else {
    if (send(g_txsock, buffer, length, 0) == -1) {
      csp_log_error("csp_ax25_tx(), Unable to send AX.25 frame: \n");
      return CSP_ERR_TX;
    }
  }

  csp_buffer_free(packet);
  return CSP_ERR_NONE;
}

ax25_address *csp_ax25_ctable_get_(uint8_t csp_addr) {
  return &csp_ax25_ctable[csp_addr];
}

bool csp_ax25_ctable_set_(uint8_t csp_addr, ax25_address *hop) {
  ax25_address *old = csp_ax25_ctable_get_(csp_addr);
  if (ax25_cmp(hop, old) == 0) return false;

  memcpy(&csp_ax25_ctable[csp_addr], hop, sizeof(ax25_address));
  return true;
}

bool csp_ax25_ctable_is_null(uint8_t csp_addr) {
  return csp_ax25_ctable[csp_addr].ax25_call == 0;
}

int csp_ax25_ctable_set(uint8_t csp_addr, char *ax25_call) {
  if (csp_addr > CSP_ID_HOST_MAX) {
    csp_log_error(
        "ctable_set(): supplied csp_addr:%d is larger than "
        "CSP_ID_HOST_MAX\n");
    return CSP_ERR_DRIVER;
  }

  char *old_call = ax25_ntoa(csp_ax25_ctable_get_(csp_addr));
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

  if (!csp_ax25_ctable_is_null(csp_addr)) {
    char *ret = NULL;
    char *call = ax25_ntoa(csp_ax25_ctable_get_(csp_addr));
    if (call != NULL) {
      size_t call_len = strlen(call) + 1;  // str size + '\0' char
      ret = csp_malloc(call_len);
      memcpy(ret, call, call_len);
    }
    return ret;

  } else {
    return NULL;
  }
}
