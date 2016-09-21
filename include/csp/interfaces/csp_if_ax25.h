#ifndef _CSP_IF_AX25_H_
#define _CSP_IF_AX25_H_


#include <stdint.h>
#include <csp/csp.h>
#include <csp/csp_interface.h>

#define PORT	10 // PriSIS listen port.... 
#define PORT_F	9 // listen port for photo service
#define SAT_ADDR	1 //CSP ID
#define GS_ADDR	11 // CSP ID
#define AX25_HEADER_S	17 // 17 bytes for header	
#define AX25_TAIL_S	3 // 3 bytes for tail

extern csp_iface_t csp_if_ax25;

char * csp_ax25_map_callsign(int call);
char * csp_ax25_localcall(char *ax25_port);
int csp_ax25_init(char *ax25_port);
int csp_ax25_tx(csp_packet_t *packet, uint32_t timeout);
char * csp_ax25_rx(void);


/* funcions */
#define GARC	1 /* get all received commands */
#define AFST	2 /* ask for fulll self test */
#define CBS	3 /* check beacon status */
#define BON	4 /* check beacon status */
#define BOFF	5 /* check beacon status */

#define CRLIS	6 /* check radio link interface status */
#define GASD	7 /* get all sensor data */
#define GAGR	8 /* get all gyroscope readings */
#define CBATS	9 /* check battery status */
#define FAI	10 /* fetch all images */
#define RET	11 /* ask for fragment retransmition */

/* errors */
#define	SEMANTIC_ERR 	-1	/* app semantic error */
#define	NOT_IMP 	-2	/* function not implemented */

#endif /* _CSP_IF_AX25_H_ */
