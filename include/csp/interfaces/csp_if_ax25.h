#ifndef _CSP_IF_AX25_H_
#define _CSP_IF_AX25_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <csp/csp.h>
#include <csp/csp_interface.h>
#include <stdint.h>
#include <netax25/ax25.h>

// sizes of various fields
#define KISS_HEADER_S 1                    //
#define AX25_NCALL_S sizeof(ax25_address)  // callsign in network format
#define AX25_CONTROL_S 1                   // control field
#define AX25_PID_S 1                       // Protocol ID (I frames only)
#define AX25_HEADER_I_S \
  (KISS_HEADER_S + AX25_NCALL_S * 2 + AX25_CONTROL_S + AX25_PID_S)
#define AX25_TAIL_S 3

extern csp_iface_t csp_if_ax25;

/** CSP Host addr to  for layer 2 -- AX25 callsign table
 * Never use this directly, only interact with it using.
 * Only leaving it public for debugging convenience.
 */
extern ax25_address csp_ax25_rtable[];


#define AX25_MAX_LEN AX25_HEADER_I_S + CSP_HEADER_LENGTH + csp_if_ax25.mtu

/** Intializes the csp<->ax25 interface
 * Registers the ax25 interface in libcsp and sets the callsign, via
 * csp_ax25_set_call(), to use in rx/tx sockets and rxtask.
 *
 * @note this should be called once (and only once) at the beggining of the
 * process execution.
 *
 * @param[in] ax25_port The string with the ax25 callsign port name. (because a
 * ax25 callsign also has a port name)
 * @returns: CSP_ERROR_NONE on success, CSP_ERROR_DRIVER if an error ocurred.
 */

int csp_ax25_init(char *ax25_port);
/** Validate and set ax25 callsign to use by ax25 tx/rx sockets and rxtask.
 *
 * This function can be called multiple times. And even after the
 * sockets/rxthread has been started. However in that case the new callsign will
 * only take effect after the csp_ax25 layer has been stopped and started again.
 *
 * @param[in] ax25_port The string with the ax25 callsign port name. (because a
 * ax25 callsign also has a port name)
 * @returns: CSP_ERROR_NONE on success, CSP_ERR_DRIVER if an error ocurred.
 */
int csp_ax25_set_call(char *ax25_port);

/** Starts the csp_ax25 layer
 * Internaly binds the sockets using the callsign set via csp_ax25_set_call()
 * and starts rxtask.
 * @returns: CSP_ERROR_NONE on success, CSP_ERROR_DRIVER if an error ocurred.
 */
int csp_ax25_start(void);

/** Stops the csp_ax25 layer
 * This then frees the callsign to be used for other purposes.
 *
 * Internaly the rx/tx sockets are closed rxtask is killed.
 *
 * @returns: CSP_ERROR_NONE on success, CSP_ERROR_DRIVER if an error ocurred.
 */
int csp_ax25_stop(void);

/** Sets a static mapping between a csp address and a ax25 callsign.
 *
 * This mapping is consulted after the csp layer delivers a packet to the ax25
 * layer for it to send. In this stage the ax25 layer must know wich callsign to
 * send the packet (inside a frame the layer constructs)
 *
 * @param[in] csp_addr The csp addr to serve as keys in csp_ax25_map_callsign.
 * @param[in] ax25_call The callsign to use for the csp_addr (The caller *must*
 * discard this point, a copy is made internally). Can be NULL to delete a
 * previous mapping.
 * @returns CSP_ERR_NONE on success, CSP_ERR_DRIVER on failure
 */
int csp_ax25_ctable_set(uint8_t csp_addr, char *ax25_call);

/** Returns the ax25 callsign associated with the host of csp_addr
 *
 * @see csp_ax25_ctable_set()
 *
 * @param[in] csp_addr The csp addr to serve as keys in csp_ax25_map_callsign.
 * @returns A char* which the caller must then free. If the addr has no assigned
 * callsign, NULL is returned instead.
 */
char *csp_ax25_ctable_get(uint8_t csp_addr);

int csp_ax25_tx(struct csp_iface_s *interface, csp_packet_t *packet,
                uint32_t timeout);
char *csp_ax25_rx(void);

/* funcions */
#define GARC 1 /* get all received commands */
#define AFST 2 /* ask for fulll self test */
#define CBS 3  /* check beacon status */
#define BON 4  /* check beacon status */
#define BOFF 5 /* check beacon status */

#define CRLIS 6 /* check radio link interface status */
#define GASD 7  /* get all sensor data */
#define GAGR 8  /* get all gyroscope readings */
#define CBATS 9 /* check battery status */
#define FAI 10  /* fetch all images */
#define RET 11  /* ask for fragment retransmition */

/* errors */
#define SEMANTIC_ERR -1 /* app semantic error */
#define NOT_IMP -2      /* function not implemented */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _CSP_IF_AX25_H_ */
