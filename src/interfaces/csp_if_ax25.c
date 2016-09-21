#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h> 

#include <linux/if_ether.h>

#include <csp/csp_endian.h>
#include <csp/csp_error.h>
#include <csp/csp_interface.h> // csp_route_add_if 
#include <csp/interfaces/csp_if_ax25.h>

#include <netax25/axlib.h>
#include <netax25/ax25.h>
#include <netax25/axconfig.h>

#include "../src/arch/csp_thread.h"


static int txsock, rxsock;
static char *localcall;

CSP_DEFINE_TASK(ax25_rx) {

	struct full_sockaddr_ax25 src;
	int size; 	
	socklen_t srcs = sizeof(src);
	int payload_s;
	char buffer[csp_if_ax25.mtu];
	csp_packet_t *packet = NULL;

	
	while(1){

		/* clean the receive buffer */
		memset(buffer, 0, csp_if_ax25.mtu+CSP_HEADER_LENGTH+AX25_HEADER_S);

		/* hold for incomming packets */
		size = recvfrom(rxsock, buffer, csp_if_ax25.mtu+CSP_HEADER_LENGTH+AX25_HEADER_S, 0, (struct sockaddr *)&src, &srcs);
		if(size == -1){
			perror("Error in AX.25 frame reception..\n");
			fprintf(stderr, "error in ax.25 fram reception..\n");
			return NULL;
		}


		/* offset eval */
		payload_s = size-AX25_HEADER_S-CSP_HEADER_LENGTH;

		/* alloc new packet */	
		//packet = csp_buffer_get(csp_if_ax25.mtu); 		
		packet = csp_buffer_get(sizeof(csp_packet_t)+payload_s); 		
		if(packet == NULL){
			perror("Cannot allocate packet memory: ");
			fprintf(stderr, "cannot allocate packet mem");
			continue;
		}

		/* fill the packet with incomming CSP data */
		/* copy packet header and convert it into host endianess */	
		memcpy(&(packet->id.ext), &(buffer[AX25_HEADER_S]), CSP_HEADER_LENGTH);
		packet->id.ext = csp_ntoh32(packet->id.ext);
		
		/* set the packet payload and size*/
		memcpy(&(packet->data), &(buffer[CSP_HEADER_LENGTH+AX25_HEADER_S]), payload_s);
		packet->length = payload_s;

		/* The next validation filters the unknown packets,
		 * because the rxsock have very permissive filter (all UI Frames) 
		 * later, the application must also filter, acording to 
		 * the binded port.
		 */
		if(packet->id.dst != my_address){
//			printf("\nWARN: CSP Packet dropped: DST CSP_ID[%d] differ FROM local ADDR[%d] \n", packet->id.dst, my_address);
			csp_buffer_free(packet);
		}else{
			/* update stats */
			csp_if_ax25.frame++;

			/* inject packet into routing system */
			csp_new_packet(packet, &csp_if_ax25, NULL); // NULL -> Called from task (csp_interface.h)
		}
	}
	return CSP_TASK_RETURN;
}

int csp_ax25_init(char *ax25_port){

	struct full_sockaddr_ax25 src;
	char localshifted[32];
	int slen;

	/* regist the AX.25 interface into CSP stack */
	csp_route_add_if(&csp_if_ax25);
	printf("\n\n\
			:::::::::::::::::::::::::::: INFO ::::::::::::::::::::::::::::::\n\
			You are using the CSP/AX.25 adaptation layer\n\
			This software was written by Joao Ferreira (joaoahf@gmail.com) \n\
			For more information please visit: http://istnanosat.ist.utl.pt\n\
			::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");


	/* load ports from configuration */
	if (ax25_config_load_ports() == 0) {
		fprintf(stderr, "No AX.25 ports defined\n");
		return CSP_ERR_DRIVER;
	}

	/* get local callsign */
	localcall = csp_ax25_localcall(ax25_port);

	if(localcall == NULL){
		fprintf(stderr, "Error reading local callsign..");
		return CSP_ERR_DRIVER;
	}

	/* fill the src structure */
	memset(&src, 0, sizeof src);
	if ((slen = ax25_aton(localcall, &src)) == -1) {
		perror("Unable to convert source callsign \n");
		return CSP_ERR_DRIVER;
	}

	/* let's validate our local call */
	if (ax25_aton_entry(localcall, localshifted) == -1) {
		perror("Can't shift local callsign: \n");
		return CSP_ERR_DRIVER;
	}

	if (ax25_validate(localshifted) == 0) {
		fprintf(stderr, "Local callsign not valid\n");
		return CSP_ERR_DRIVER;

	}

	/* Prepare tx socket 
	 * 	PID=0xF0 =>  l3 protocol not specified..
	 * 	http://www.tapr.org/pub_ax25.html#2.2.4
	 **/
	if ((txsock = socket(AF_AX25, SOCK_DGRAM, 0xF0)) == -1) { 
		perror("rxsocket() error:");
		return CSP_ERR_DRIVER;
	}

	/* bind local callsign to our txsock */
	if (bind(txsock, (struct sockaddr *)&src, slen) == -1) {
		perror("bind() error: ");
		return CSP_ERR_DRIVER;
	}

	/* Prepare rx socket 
	 *
	 * NOTE:
	 * PF_PACKET/SOCK_PACKET confiuration is used here, 
	 * because the AF_AX25/SOCK_DRAM does not 
	 * allow wildcards in remoteaddr, then recvfrom() would need match, 
	 * both dest and src addresses. 
	 *
	 **/
	if ((rxsock = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_AX25))) == -1) {
		perror("socket() error: ");
		return CSP_ERR_DRIVER;
	}

	/* launch reception thread... */
	csp_thread_handle_t handle_rx;
	csp_thread_create(ax25_rx, (signed char *) "AX25-RX", 1000, NULL, 0, &handle_rx);

	return CSP_ERR_NONE;
}


int csp_ax25_tx(csp_packet_t *packet, uint32_t timeout) {

	struct full_sockaddr_ax25 dest;
	int dlen;
	char *destcall;
	char *txbuf;

	/* wich callsign is associated with this CSP ID ? */
	destcall = csp_ax25_map_callsign(packet->id.dst);

	/* fill the dest ax25 structure */
	if ((dlen = ax25_aton(destcall, &dest)) == -1) {
		fprintf(stderr, "Unable to convert destination callsign '%s'\n", destcall);
		return CSP_ERR_DRIVER;
	}

//	printf("\n######## I will send the packet: \n");
//	printf("-> Payload is: %s\n", packet->data);
//	printf("-> Packet size (bytes) [ %d ]\n", packet->length);
//	printf("-> FROM: CSP_id [ %d ] || Callsign [ %s ] \n", packet->id.src, localcall);
//	printf("-> TO: CSP_id [ %d ] port [ %d ] || Callsign [ %s ]\n", packet->id.dst, packet->id.dport, destcall);
//	printf("#################################\n");


	/* prepare (alloc&clean) transmition buffer */
	txbuf = (char *) malloc(packet->length+CSP_HEADER_LENGTH);
	if(txbuf == NULL) { perror("Unable to alloc AX.25 outgoing buffer"); return CSP_ERR_TX; }
 
	memset(txbuf, 0, CSP_HEADER_LENGTH+packet->length);

	
	/* fill the buffer with packet header (in network format) */
	packet->id.ext = csp_hton32(packet->id.ext);
	memcpy(txbuf, &packet->id.ext, CSP_HEADER_LENGTH);
	
	/* copy the packet payload to the buffer */
	memcpy(&txbuf[CSP_HEADER_LENGTH], &packet->data, packet->length);

	/* send the CSP packet inside our AX.25 frame through txsock FD */
	if (sendto(txsock, txbuf, packet->length+CSP_HEADER_LENGTH, 0, (struct sockaddr *)&dest, dlen) == -1) {
		perror("Unable to send AX.25 frame: \n");
		return CSP_ERR_TX;
	}
	
	/* release memory... */
	csp_buffer_free(packet);
	free(txbuf);
	free(destcall);
	return CSP_ERR_NONE;
}


/* Mappings CSP_ID -> Callsign suffix */
char * csp_ax25_map_callsign(int call){
	int call_suf = 0;
	char *ret;
	ret =  (char *) malloc(10*sizeof(char));

	if(call == SAT_ADDR)
		call_suf = 11;	// 11 -> Callsign

	if(call == GS_ADDR)
		call_suf = 1;

	sprintf(ret, "CS5CEP-%d", call_suf);
	return ret;

}


char * csp_ax25_localcall(char *ax25_port){
	char *ret = NULL;

	if ((ret = ax25_config_get_addr(ax25_port)) == NULL) {
		fprintf(stderr, "Invalid AX.25 port [ %s ]\n", ax25_port);
		return NULL;
	}
	return ret;
}


/** Interface definition */
csp_iface_t csp_if_ax25 = {
	.name = "AX.25",
	.nexthop = csp_ax25_tx,
	.mtu = (255 - sizeof(csp_id_t)), // 255 AX.25 MTU - Header AX.25 - Header CSP
};
