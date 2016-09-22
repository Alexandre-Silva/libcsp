#ifndef _CSP_IF_AX25_H_
#define _CSP_IF_AX25_H_

#include <csp/csp.h>
#include <csp/csp_interface.h>
#include <stdint.h>

#define PORT 10           // PriSIS listen port....
#define PORT_F 9          // listen port for photo service
#define SAT_ADDR 1        // CSP ID
#define GS_ADDR 11        // CSP ID
#define AX25_HEADER_S 17  // 17 bytes for header
#define AX25_TAIL_S 3     // 3 bytes for tail

extern csp_iface_t csp_if_ax25;

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
 * @returns: CSP_ERROR_NONE on success, CSP_ERROR_DRIVER if an error ocurred.
 */
int csp_ax25_set_call(char *ax25_port);

/** Starts the csp_ax25 layer
 * Internaly binds the sockets using the callsign set via csp_ax25_set_call()
 * and starts rxtask.
 * @returns: CSP_ERROR_NONE on success, CSP_ERROR_DRIVER if an error ocurred.
 */
int csp_ax25_start();

/** Stops the csp_ax25 layer
 * This then frees the callsign to be used for other purposes.
 *
 * Internaly the rx/tx sockets are closed rxtask is killed.
 *
 * @returns: CSP_ERROR_NONE on success, CSP_ERROR_DRIVER if an error ocurred.
 */
int csp_ax25_stop();

/** Sets a static mapping between a csp address and a ax25 callsign.
 *
 * This mapping is consulted after the csp layer delivers a packet to the ax25
 * layer for it to send. In this stage the ax25 layer must know wich callsign to
 * send the packet (inside a frame the layer constructs)
 *
 * @param[in] csp_addr The csp addr to serve as keys in csp_ax25_map_callsign.
 * @param[in] ax25_call The callsign to use for the csp_addr (The caller *must*
 * discard this pointer). Can be NULL to delete a previous mapping.
 */
int csp_ax25_rtable_set(uint8_t csp_addr, char *ax25_call);
char *csp_ax25_map_callsign(int call);
char *csp_ax25_localcall(char *ax25_port);

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

#endif /* _CSP_IF_AX25_H_ */
