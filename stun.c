/******************************************************************************

TUN/TAP References:
	Universal TUN/TAP device driver:  https://www.kernel.org/doc/html/latest/networking/tuntap.html
	Tutorial:  https://piratelearner.com/en/bookmarks/tuntap-interface-tutorial/14/
	Introduction:  https://www.gabriel.urdhr.fr/2021/05/08/tuntap/
	Misc. developer notes:  https://ldpreload.com/p/tuntap-notes.txt

NAT and UDP References:
	NAT and UDP replies:  https://superuser.com/questions/456812/nat-and-udp-replies
	Blocking discussion:  https://news.ycombinator.com/item?id=17846891

TCP Nagle and Delayed ACK References:
	https://www.extrahop.com/company/blog/2016/tcp-nodelay-nagle-quickack-best-practices/

Reliable UDP Algorithms:
	https://io7m.com/documents/udp-reliable/

*/

/*
General TODO's:
	1.  Client and server connections are currently a one-and-done.  Add capability to retry/reestablish connections.
	2.  All sockets are currently SOCK_DGRAM (UDP).  Investigate using TCP with Nagle and Delayed ACK disabled.
	3.  IP addresses and ports are set in code.  Create automation for CRUD.
	4.  Implement encryption of packets to eliminate need for external VPN.
	5.  If external VPN is used (#4), STUNHEADER will be in the clear.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/string.h>
#include <linux/if_tun.h> // IFF_TUN, IFF_NO_PI
#include <linux/socket.h>

#include <sys/ioctl.h>
#include "chacha20.h"
#include "request_mgr.h"
#include "hkdf_conn.h"

int pdisplay = 1;						// set with "D" on the CLI to enable packet information display

// ******************************************************************************
// ******************************************************************************
// local function prototypes
void stun_client();						// creates stun client endpoint
void stun_server();						// creates stun server endpoint
void stun_loop(char *, int, int *, int msg_request_socket);		// common processing loop used by both stun_client and stun_server
int stun_tunnel(char *, char *, int);	// creates and configures stun tunnel
int tun_alloc(char *);					// creates linux tunnel interface, eg: "STUN0"
int getrand(unsigned char *, int);		// reads a hunk of random from OS for stun channel selection

// ******************************************************************************
// ******************************************************************************
// STUN defines and structures

// number of stun channels between client and server
#define	CHANNELCOUNT		4

// linux tunnel interface information
#define	TUNNELNAME			"stun0"
#define	TUNNELSERVERIPMASK	"10.11.12.1/24"
#define	TUNNELCLIENTIPMASK	"10.11.12.2/24"

// arbitray MTU value for testing
#define	TUNNELMTU			1234

// serial number arithmetic for data packets per RFC1982
// if SERNUMMATH(A, B) < 0, then A is before B
// if SERNUMMATH(A, B) > 0, then A is after B
#define	SERNUMMATH(A, B)	(signed int) (A - B)

#define	MAXBUFF				TUNNELMTU+sizeof(STUNHEADER)+NONCE_LENGTH	// buffer size used to receive network packets

#define	RANDBUFF			50000							// temp buffer to store random values from OS

#define	QUELENGTH			100								// number of packets in fifo queue

#define	HEARTBEATINTERVAL	21								// seconds between client-server network heartbeats

// local structure definition for fifo packet queue
// The queue is a doubly linked list.  Packets are queued at "inhead" in descending sequence number order, so that
// when packets are dequeued at "outhead", they will be in ascending sequence number order.
typedef struct _buff
{
	struct _buff *fifonext;		// pointer used by outhead list, pointing to next highest sequence number in list
	struct _buff *fifoprev;		// pointer used by inhead list, pointing to next lowest sequence number in list
	struct _buff *freenext;		// pointer used to maintain free list
	uint32_t sequence;			// sequence number of this packet
	uint16_t packet;			// size of this packet in bytes
	char buff[MAXBUFF];			// packet data
} BUFF;

/*****************************************************/
/*****************************************************/
/*  key data  										*/
char result[MAXBUFF];
int size_random_key = 0;
int size_random_nonce = 0;
AUTH_DATA auth_data[CHANNELCOUNT];
int key_sent_to_client = 0;
int encrypt = 1; 
int port_for_key_xfer = 20000;
const char* server_ip_for_key_xfer = "10.42.0.30";
int print_raw_encryption_logs = 2;  // controls print of encryption logs; 0-none, 1-medium, 2-all logs
int transfer_keys = 0;    // create keys and send via TCP connection 
unsigned int cntr_nonce = 253;
uint8_t chacha20SymKey_buf[SYMMETRIC_KEY_SIZE_BYTES+1];
uint8_t * chacha20SymKey = &chacha20SymKey_buf[0];

int update_key_from_server(uint8_t key_buf[], int key_size, uint8_t key_version);
uint16_t get_current_key_version();
uint8_t get_next_key_version();
int key_size = SYMMETRIC_KEY_SIZE_BYTES; 
uint16_t symmetric_key_version = 1;
long long int server_cntr_nonce = 100;
long long int client_cntr_nonce = 200;
/*****************************************************/
/*****************************************************/

void main(int argc, char *argv[])
{

	// enable packet display
	if (argv[2])
	{
		if (*argv[2] == 'D')
		{
			pdisplay = 1;
		}
	}

	for(int i=0;i<CHANNELCOUNT;i++)
	{
		auth_data[i].client_cntr_nonce = BASE_VALUE_FOR_CLIENT_NONCE + i;
		auth_data[i].server_cntr_nonce = BASE_VALUE_FOR_SERVER_NONCE + i;
		strcpy(chacha20SymKey, "one test cha keyone test cha key"); // fww temporary initial key
		strncpy(auth_data[i].key, chacha20SymKey, sizeof(chacha20SymKey_buf));

		printf(" key %d: \n", i);
		print_buf(chacha20SymKey, 32);
		print_buf(auth_data[i].key, 32);

	} 


	// client role
	if (*argv[1] == 'C')
	{
		// fww
		if(encrypt)
		{
			for(int i=0;i<CHANNELCOUNT;i++)
			{			
					memset(auth_data[i].nonce, 0, NONCE_LENGTH);
					memcpy(auth_data[i].nonce, (uint8_t *)&auth_data[i].client_cntr_nonce,  sizeof(auth_data[i].client_cntr_nonce));
			
					printf("\n key: %ld", auth_data[i].client_cntr_nonce );
					for(int i=0;i<KEY_LENGTH;i++) printf("%02x",auth_data[i].key[i]);
					printf("\n client nonce: ");
					for (int i = 0; i < NONCE_LENGTH; i++) printf("%02x", auth_data[i].nonce[i]);
					printf("\n");

					printf(" calling update key\n");
					//chacha20_libgcrypt_init(auth_data[i].key, print_raw_encryption_logs);				

					update_key_from_server(auth_data[i].key, KEY_LENGTH, INIT_KEY_VERSION_MAJOR);
					update_nonce("CLIENT", i);

					printf("\n memcpy nonce\n");
					print_buf(auth_data[i].nonce, NONCE_LENGTH);	
			}		
		}
		stun_client();
	}

	// server role
	else
	{
		// fww
		if(encrypt)
		{
			for(int i=0;i<CHANNELCOUNT;i++)
			{			
				memset(auth_data[i].nonce, 0, sizeof(auth_data[i].nonce));
				memcpy(auth_data[i].nonce, (uint8_t *)&auth_data[i].server_cntr_nonce, sizeof(auth_data[i].client_cntr_nonce));
				printf("\n key: ");
				for (int i = 0; i < KEY_LENGTH; i++)printf("%02x", auth_data[i].key[i]);
				printf("\n server nonce: ");
				for (int i = 0; i < NONCE_LENGTH; i++)printf("%02x", auth_data[i].nonce[i]);
				printf("\n");


				printf(" calling update key\n");
				//chacha20_libgcrypt_init(auth_data[i].key, print_raw_encryption_logs);		
				KEY_VERSION key_version;
				key_version.major = INIT_KEY_VERSION_MAJOR;
				key_version.minor = INIT_KEY_VERSION_MINOR;							
				update_key_from_server(auth_data[i].key, KEY_LENGTH, INIT_KEY_VERSION_MAJOR);
				//size_random_key = getrand((unsigned char *)auth_data[i].key, KEY_LENGTH);
				//size_random_nonce = getrand((unsigned char *)auth_data[i].nonce, NONCE_LENGTH);
				update_nonce("SERVER",i);
			}
	
		}
		stun_server();
	}


}

// ******************************************************************************
// ******************************************************************************
// Configuration stuff eventually to be automation CRUD

/*char *client_ip[] =
{
	"10.200.1.97",
	"10.200.1.97",
	"10.200.1.97",
	"10.200.1.97",
}; /* */ 

char *client_ip[] =
{
	"10.42.0.201",
	"10.42.0.201",
	"10.42.0.201",
	"10.42.0.201"
};  // FWW  */

int client_port[] =
{
	42001,
	42002,
	42003,
	42004
};

/*char *server_ip[] =
{
	"10.200.1.92",
	"10.200.1.92",
	"10.200.1.92",
	"10.200.1.92"
}; /* */ 
char *server_ip[] =
{
	"10.42.0.200",
	"10.42.0.200",
	"10.42.0.200",
	"10.42.0.200"
};  // FWW */


int server_port[] =
{
	41001,
	41002,
	41003,
	41004
};


// ******************************************************************************
// ******************************************************************************
// Local functions

void stun_client()
{
	char msg[MAXBUFF];
	int lp;
	int len;
	int sts;
	int retval = 0;

	int fd_tun, fd_net[CHANNELCOUNT];
	
	struct sockaddr_in servaddr, cliaddr;
	int msg_request_socket;

	printf("\nSTUN Client (%s)\n", __TIMESTAMP__);

	// setup local tunnel interface
	fd_tun = stun_tunnel(TUNNELNAME, TUNNELCLIENTIPMASK, TUNNELMTU);
	if (fd_tun < 0)
	{
		// TODO:  better failure
		printf("Cannot create tunnel interface\n");
		return;
	}

	// allocate sockets
	for(lp=0; lp<CHANNELCOUNT; lp++)
	{
		if ((fd_net[lp] = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
		{
			// TODO:  better failure
			printf("socket() failed\n");
			return;
		}

		printf(" bind addr %s %d", client_ip[lp], client_port[lp]);

		// bind() to ensure use of specific IP address and port instead of INADDR_ANY
		memset(&cliaddr, 0, sizeof(servaddr));
		cliaddr.sin_family = AF_INET;
		cliaddr.sin_port = htons(client_port[lp]);
		inet_pton(AF_INET, client_ip[lp], &cliaddr.sin_addr);
		retval = bind(fd_net[lp], (const struct sockaddr *)&cliaddr, sizeof(cliaddr));

		if(retval < 0)
		{
			// TODO:  better failure
			printf("bind() failed\n");
			return;
		}

		// connect() to set server IP addresses and ports, so that send() can be used to send packets
		memset(&servaddr, 0, sizeof(servaddr));
		len = sizeof(servaddr);
		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons(server_port[lp]);
		inet_pton(AF_INET, server_ip[lp], &servaddr.sin_addr);
		if (connect(fd_net[lp], (const struct sockaddr *) &servaddr, len) < 0)
		{
			// TODO:  better failure
			printf("connect() failed\n");
			return;
		}

		// send CALL request to server
		strcpy(msg, "CALL");
		printf(" client sending CALL\n");
		sts = send(fd_net[lp], (const char *) msg, strlen(msg), 0);

		// wait for ANSWER reply from server
		sts = recv(fd_net[lp], (char *) msg, MAXBUFF, 0);
		if (sts <= 0)
		{
			// TODO:  better failure
			perror("recv() failed");
			return;
		}
		if (memcmp(msg, "ANSWER", 6) != 0)
		{
			// TODO:  better failure
			printf("ANSWER failed\n");
			return;
		}
		else
		{	
			printf(" client  rec'd ANSWER\n");
		}
	}

	// set up socket for handling message requests between client and server
	msg_request_socket = set_up_msg_request_socket("CLIENT");
	if(msg_request_socket < 0)
	{
		printf(" error in setting up socket for msg requests\n");
	}
	else
	{
		printf("\n msg request socket: %d\n", msg_request_socket);
		sts = client_send_init_msg_to_server("CLIENT");
		client_send_request_new_key_to_server("CLIENT");

	}
	// all good, so enter main stun loop as client
	printf("connected\n");

	stun_loop("CLIENT", fd_tun, fd_net, msg_request_socket);
}

void stun_server()
{
	char msg[MAXBUFF];
	char ip[100];
	int len;
	int sts;
	int lp;
	int fd_tun, fd_net[CHANNELCOUNT];
	int msg_request_socket;
	int retval = 0;

	struct sockaddr_in servaddr, cliaddr;

	printf("\nSTUN Server (%s)\n", __TIMESTAMP__);

	// setup local tunnel interface
	fd_tun = stun_tunnel(TUNNELNAME, TUNNELSERVERIPMASK, TUNNELMTU);
	if (fd_tun < 0)
	{
		// TODO:  better failure
		printf("Cannot create tunnel interface\n");
		return;
	}

	// loop for each stun channel to allocate sockets and bind to specific addresses and ports
	for(lp=0; lp<CHANNELCOUNT; lp++)
	{
		// socket() gets a new socket
		if ((fd_net[lp] = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
		{
			// TODO:  better failure
			printf("socket() failed\n");
			return;
		}

		printf("bind server to %s\n", server_ip[lp]);
		// bind() to ensure use of specific IP address and port instead of INADDR_ANY
		memset(&servaddr, 0, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons(server_port[lp]);
		inet_pton(AF_INET, server_ip[lp], &servaddr.sin_addr);
		if (bind(fd_net[lp], (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
		{
			// TODO:  better failure
			printf("bind failed()\n");
			return;
		}
		else
		{
			printf(" bind addr %s %d\n", server_ip[lp], server_port[lp]);

		}
	}

	// loop to wait for client CALL requests
	for(lp=0; lp<CHANNELCOUNT; lp++)
	{
		memset(&cliaddr, 0, sizeof(cliaddr));
		len = sizeof(cliaddr);
		sts = recvfrom(fd_net[lp], (char *)msg, MAXBUFF, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
		if (sts > 0)
		{

			if (memcmp(msg, "CALL", 4) == 0)
			{
				printf(" server rec'd  CALL\n");
				// connect() to set client IP addresses and ports, so that send() can be used to send packets
				inet_ntop(AF_INET, (const void *) &cliaddr.sin_addr, ip, len);
				sts = connect(fd_net[lp], (const struct sockaddr *) &cliaddr, len);
				if (sts < 0)
				{
					// TODO:  better failure
					perror("connect()");
					return;
				}
				inet_ntop(AF_INET, (const void *) &cliaddr.sin_addr, ip, len);

				// send ANSWER reply back to client
				strcpy(msg, "ANSWER");
				printf(" server sending ANSWER\n");
				sts = send(fd_net[lp], (const char *) msg, strlen(msg), 0);
				if (sts < 0)
				{
					// TODO:  better failure
					perror(" server error on sending ANSWER");
					return;
				}


			}
		}
	}

	// set up socket for handling message requests between client and server
	msg_request_socket = set_up_msg_request_socket("SERVER");
	if(msg_request_socket < 0)
	{
		printf(" error in setting up socket for msg requests\n");
	}
	else
	{
		printf("\n msg request socket: %d\n", msg_request_socket);
	}

	// all good, so enter main stun loop as server
	printf("connected\n");
	
	
	stun_loop("SERVER", fd_tun, fd_net, msg_request_socket);
}

// main stun loop
void stun_loop(char *role, int fd_tun, int *fd_net, int msg_request_socket)
{
	// pointer to access packet control information header
	STUNHEADER *stunhead;

	// pointers to maintain packet fifo list
	BUFF *freehead, *inhead, *outhead, *bptr, **pbptr;

	// misc. local buffers and work variables
	char tempbuff[MAXBUFF], stmp[MAXBUFF];
	unsigned char randb[RANDBUFF];
	int lp, sts, fd_max, heartbeat, randx = 0;
	long pdline = 0;

	// used for select() call
	fd_set rd_set;
	struct timeval tout;

	// packet sequence numbers for tx and rx
	unsigned char version;
	uint32_t tmp_sequence;
	uint16_t tmp_packet;
	uint32_t tx_sequence;
	uint32_t next_sequence;
	uint32_t retval;

	// allocate packet buffer space
	freehead = inhead = outhead = NULL;
	for(lp=0; lp<QUELENGTH; lp++)
	{

		bptr = malloc(sizeof(BUFF));
		if (!bptr)
		{
			// TODO:  better failure
			printf("malloc() error\n");
			return;
		}

		// clear fifo pointers
		bptr->fifoprev = bptr->fifonext = NULL;

		// add new node to free list
		bptr->freenext = freehead;
		freehead = bptr;

	}

	// initialze fd_max based on tunnel and channel socket handles for use later with select()
	fd_max = fd_tun;
	for(lp=0; lp<CHANNELCOUNT; lp++)
	{
		if (fd_net[lp] > fd_max)
		{
			fd_max = fd_net[lp];
		}
		if (msg_request_socket > fd_max)  //fwww
		{
			fd_max = msg_request_socket;
		}		
	}

	heartbeat = 0;
	tx_sequence = 0;
	next_sequence = 0;
	for(;;)
	{

		// setup array of handles for use with select()
		FD_ZERO(&rd_set);
		FD_SET(fd_tun, &rd_set);
		for(lp=0; lp<CHANNELCOUNT; lp++)
		{
			FD_SET(fd_net[lp], &rd_set);
		}
		FD_SET(msg_request_socket, &rd_set);

		// simultaneously wait on all handles for the heartbeat interval
		tout.tv_sec = HEARTBEATINTERVAL;
		tout.tv_usec = 0;
		sts = select(fd_max + 1, &rd_set, NULL, NULL, &tout);  // file desc are tested from 0 to nfds-1

		// if select() returns 0, heartbeat interval has elapsed
		if (!sts)
		{
			// check if heartbeat already in progress, thus it timed out
			if (heartbeat)
			{
				// TODO:  better failure
				printf("stun_loop heartbeat timeout\n");
				return;
			}

			// otherwise, start heartbeat sequence
			heartbeat = 1;

			// if client role, send heartbeat to server
			if (*role == 'C')
			{
				printf(" send heartbeat \n");
				for(lp=0; lp<CHANNELCOUNT; lp++)
				{
					stunhead = (STUNHEADER *) tempbuff;
					stunhead->sequence = htonl(0);
					stunhead->packet = htonl(0);
					send(fd_net[lp], tempbuff, sizeof(STUNHEADER), 0);
					//if (pdisplay) printf("client heartbeat, rx_seq=%d, tx_seq=%d\n", next_sequence, tx_sequence);
				}
			}

			// loop to wait for heartbeat reply or timeout
			continue;

		}

		// some other select() failure
		if (sts < 0)
		{
			// TODO:  better failure
			printf("stun_loop:  select(): %d\n", sts);
			return;
    	}

		// data from tunnel to network
		if (FD_ISSET(fd_tun, &rd_set))
		{
			//  tempbuff layout:  [ NONCE_LENGTH bytes for nonce |  sizeof(STUNHEADER) bytes for stun header |  payload data bytes ]
			//     size of nonce + stun header + payload is:  tmp_packet
			// read data from tunnel while leaving space at the start of the buffer for the header and nonce
			char *tempbuff_start_of_stun_header = tempbuff + NONCE_LENGTH;
			char *tempbuff_start_of_payload = tempbuff_start_of_stun_header + sizeof(STUNHEADER);

			tmp_packet = read(fd_tun, tempbuff_start_of_payload, MAXBUFF - sizeof(STUNHEADER) - NONCE_LENGTH);
			if (print_raw_encryption_logs >= 1)
			{
				printf("\n tunnel recv tmp_packet = %d\n", tmp_packet);
				printf(" stunnel to netwk bytes: ");
				for (int i = 0; i < tmp_packet+NONCE_LENGTH+sizeof(STUNHEADER); i++)
				{
					printf("%02x ", (uint8_t)tempbuff[i]);
				}
				printf("\n");
				/*for(int i=0;i<tmp_packet+sizeof(STUNHEADER);i++)
				{
					printf("%d ", (uint8_t)tempbuff[i]);
				}
				printf("\n");		
				*/
			}
			if (tmp_packet < 1)
			{
				// TODO:  better failure
				continue;
			}

			// pass only IPv4 packets
			version = ((unsigned char)tempbuff_start_of_stun_header[sizeof(STUNHEADER)] >> 4);
			if (version != 4)
			{
				continue;
			}


			// write data to network via channel selection
			if (!randx)
			{
				randx = getrand(randb, RANDBUFF);
			}
			sts = (unsigned)((float)randb[--randx] / 256 * CHANNELCOUNT);

			// dump_packet(packet, buff+sizeof(STUNHEADER));
			stunhead = (STUNHEADER *)tempbuff_start_of_stun_header;
			if (print_raw_encryption_logs >= 1)
				printf("\n hdr be ch %d:  seq num: %d, pkt len: %d\n", sts, tx_sequence, tmp_packet);

			// set sequence number
			stunhead->sequence = htonl(tx_sequence);

			// add packet length to head of buffer
   			stunhead->packet = htons(tmp_packet);			

			if (print_raw_encryption_logs >= 1)
			{
				printf(" a stun header:  ");
				for(int i=0;i<sizeof(STUNHEADER);i++)
				{
					printf("%x ", (uint8_t)tempbuff_start_of_stun_header[i]);
				}
				printf("\n");
			}	
					
			update_nonce(role, sts); // copy cntr_nonce to auth_data.nonce  ; nonce is sent in the clear
			if(print_raw_encryption_logs>=2)
			{	printf("\n nonce before encryption: ");
				for (int i = 0; i < 12; i++)
					printf("%02x ", auth_data[sts].nonce[i]);
				printf("\n");
			}

			// encrypt function 
			if (encrypt)
			{
				if (print_raw_encryption_logs >= 1)
					printf("calling encrypt-decrypt (encrypt tunnel to netwk), role = %c\n", (char)*role);

				retval = chacha20_libgcrypt_encrypt_decrypt(tempbuff_start_of_stun_header, tmp_packet+sizeof(STUNHEADER),
														auth_data[sts], result, print_raw_encryption_logs);
				if (print_raw_encryption_logs >= 1)
					printf(" num bytes encrypted = %d\n", retval);
			}

			memcpy(tempbuff, auth_data[sts].nonce, NONCE_LENGTH);

			tmp_packet = send(fd_net[sts], tempbuff, tmp_packet + NONCE_LENGTH + sizeof(STUNHEADER), 0);
			// TODO:  handle send() failure

			if (pdisplay) printf("\n%ld TUN -->[tx=%d]--> NET%d, %d bytes\n", ++pdline, tx_sequence, sts, tmp_packet);

			// update sequence number for next time
			tx_sequence++;

		}
  


		// check for data from network to tunnel
		for(lp=0; lp<CHANNELCOUNT; lp++)
		{

			// if this channel has data to read, do it
			if (FD_ISSET(fd_net[lp], &rd_set))
			{

				// get buffer for data
				bptr = freehead;
				if (!bptr)
				{
					// TODO:  better failure (shouldn't fail as oldest packet will auto dequeue when full - see below)
					printf("No network buffer space!\n");
					return;
				}

				// read data from network
				tmp_packet = recv(fd_net[lp], (char *)bptr->buff, MAXBUFF, 0); // buffer will have nonce + stun header + payload

				// a header-only packet could be a heartbeat
				if (tmp_packet == sizeof(STUNHEADER))
				{
					STUNHEADER *st = (STUNHEADER *)(bptr->buff);					
					// process heartbeat messsage
					if (ntohl(st->sequence) == 0 && ntohs(st->packet) == 0)
					{
						// if server role, send heartbeat reply to client
						if (*role == 'S')
						{
							tmp_packet = send(fd_net[lp], bptr->buff, sizeof(STUNHEADER), 0);
							// TODO:  handle failure
							//if (pdisplay) printf("server heartbeat, rx_seq=%ld, tx_seq=%ld\n", next_sequence, tx_sequence);
						}

						// clear heartbeat process
						heartbeat = 0;

						continue;
					}
				}				

																				// nonce is not encrypted
				if (print_raw_encryption_logs >= 1)
				{
					printf("\n network recv tmp_packet = %d\n", tmp_packet);
					printf(" netwk to tunnel bytes: ");
					for(int i=0;i<tmp_packet;i++)
					{
						printf("%02x ", (uint8_t)bptr->buff[i]);
					}
					printf("\n");
				}
				// nonce is first 12 bytes, sent in the clear 
				memcpy(auth_data[lp].nonce, bptr->buff, NONCE_LENGTH);

				// decrypt function 
				if (encrypt)
				{
					// nonce is first 12 bytes, sent in the clear 
					memcpy(auth_data[lp].nonce, bptr->buff, NONCE_LENGTH);

					if (print_raw_encryption_logs >= 1)
						printf("\ncalling encrypt-decrypt (decrypt netwk to tunnel), role = %c\n", (char)*role);

					retval = chacha20_libgcrypt_encrypt_decrypt(bptr->buff + NONCE_LENGTH, tmp_packet - NONCE_LENGTH,
															auth_data[lp], result, print_raw_encryption_logs);
					if (print_raw_encryption_logs >= 1)
						printf(" num bytes decrypted = %d\n", retval);
				}

				if (tmp_packet < (sizeof(STUNHEADER) + NONCE_LENGTH))
				{
					// TODO:  better failure
					continue;
				}

				stunhead = (STUNHEADER *)(bptr->buff + NONCE_LENGTH);

				STUNHEADER *st = (STUNHEADER *)(bptr->buff + NONCE_LENGTH);
				if (print_raw_encryption_logs >= 1)
					printf(" hdr ad: seq num: %d, pkt len: %d\n", ntohl(st->sequence), ntohs(st->packet));


				// extract packet size
				tmp_packet = ntohs(stunhead->packet);
				if (tmp_packet <= 0)
				{
					// TODO:  better failure
					continue;
				}

				// extract sequence number
				tmp_sequence = ntohl(stunhead->sequence);

				// if packet is next expected sequence number, just write it to tunnel
				if (next_sequence == tmp_sequence)
				{
					if (print_raw_encryption_logs >= 1)
					{
						printf(" b4 write tmp_packet = %d\n", tmp_packet);
					}
					tmp_packet = write(fd_tun, bptr->buff+NONCE_LENGTH+sizeof(STUNHEADER), tmp_packet);
					// TODO:  handle failure
					if(tmp_packet == 65555)
						printf(" Error in sending data to tunnel\n");
					if (pdisplay)
						printf("\n%lu NET%d -->[rx=%d]--> TUN, %d bytes\n", ++pdline, lp, next_sequence, tmp_packet);
					next_sequence++;
				}

				// otherwise, if duplicate packet (eg:  packet previously received), dump it
				else if (SERNUMMATH(tmp_sequence, next_sequence) < 0)
				{
					if (pdisplay) printf("\n%lu NET -->[rx=%d]--> DUMP: expected [%d], %d bytes\n", ++pdline, tmp_sequence, next_sequence, tmp_packet);
				}

				// otherwise, packet is out of order, so queue it
				else
				{

					// find this packet's position in the fifo queue
					if (pdisplay) printf("%lu NET%d -->[rx=%d]--> QUE: expected [%d], %d bytes\n", ++pdline, lp, tmp_sequence, next_sequence, tmp_packet);
					pbptr = &inhead;
					while (*pbptr)
					{
						// if duplicate packet found, set to dump this packet and break
						if (tmp_sequence == (*pbptr)->sequence)
						{
							pbptr = NULL;
							break;
						}
						// if this packet comes after the previously newest packet in queue, break
						if (SERNUMMATH(tmp_sequence, (*pbptr)->sequence) > 0)
						{
							break;
						}
						pbptr = &(*pbptr)->fifoprev;
					}

					// if a valid queue position were found, queue packet
					if (pbptr)
					{

						// dequeue packet from free list
						freehead = bptr->freenext;

						// if queue full, set to dequeue oldest packet
						if (!freehead)
						{
							next_sequence = outhead->sequence;
						}

						// link packet into the fifo queue
						bptr->sequence = tmp_sequence;
						bptr->packet = tmp_packet;
						bptr->fifoprev = *pbptr;
						*pbptr = bptr;
						if (bptr->fifoprev)
						{
							bptr->fifonext = bptr->fifoprev->fifonext;
							bptr->fifoprev->fifonext = bptr;
						}
						else
						{
							bptr->fifonext = outhead;
							outhead = bptr;
						}

					}

				}

			}

			// process queue to write any eligible packets to tunnel
			while(outhead)
			{

				// if packet is not next in sequence, exit queue processing
				bptr = outhead;
				if (bptr->sequence != next_sequence)
				{
					break;
				}

				// write packet to tunnel
                                //tmp_packet = write(fd_tun, bptr->buff+sizeof(STUNHEADER), bptr->packet);
				tmp_packet = write(fd_tun, bptr->buff+NONCE_LENGTH+sizeof(STUNHEADER), bptr->packet);
				// TODO:  handle failure
				if (pdisplay) printf("%lu QUE -->[rx=%d]--> TUN, %d bytes\n", ++pdline, next_sequence, tmp_packet);
				next_sequence++;
	
				// dequeue packet
				if (bptr->fifoprev)
				{
					bptr->fifoprev->fifonext = bptr->fifonext;
				}
				else
				{
					outhead = bptr->fifonext;
				}
				if (bptr->fifonext)
				{
					bptr->fifonext->fifoprev = bptr->fifoprev;
				}
				else
				{
					inhead = bptr->fifoprev;
				}

				// put packet back in free list
				bptr->freenext = freehead;
				freehead = bptr;
			}

		}

		if (FD_ISSET(msg_request_socket, &rd_set))
		{
			// verify and proccess the request
			char msg[MAXBUFF];
			printf("msg_request_socket got data\n ");


			int num_bytes_read = recv(msg_request_socket, (char *)msg, MAXBUFF, 0);
			if(num_bytes_read < 0)
			{
				perror(" Error reading data on msg_request_socket\n");
			}
			else
			{
				if( num_bytes_read == 0)
				{
					printf(" 0 bytes read from msg req socket\n");
				}
				else
					handle_request(role, msg, num_bytes_read);
			}
		}
		
		// check to see if any requests need to be sent to server
		//create_msg_requests(role);
	}
}

// create and configure local tunnel interface
int stun_tunnel(char *tunnelname, char *tunnelipmask, int tunnelmtu)
{
	char cmd[100];
	int fd_tun;
	
	printf(" tunnelname: %s  tunnelipmask: %s", tunnelname, tunnelipmask);
	fd_tun = tun_alloc(tunnelname);
	if (fd_tun < 0)
	{
		printf(" error allocating tun %s", tunnelname);
		return(fd_tun);
	}
	printf(" fd_tun = %d\n", fd_tun);

	sprintf(cmd, "ip addr add %s dev %s", tunnelipmask, tunnelname);
	system(cmd);
	sprintf(cmd, "ip link set dev %s mtu %d", tunnelname, tunnelmtu);
	system(cmd);
	sprintf(cmd, "ip link set dev %s up", tunnelname);
	system(cmd);

	return(fd_tun);
}

int tun_alloc(char *dev)
{
	printf(" tun alloc\n");
	char *clonedev = "/dev/net/tun";

	struct ifreq ifr;
	int fd, err;

	if( (fd = open(clonedev, O_RDWR)) < 0 )
	{
		return(fd);
	}


	memset(&ifr, 0, sizeof(ifr));

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *
	 *        IFF_NO_PI - Do not provide packet information
	 */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	printf(" tun alloc mem, name = %s\n", dev);
	if(*dev)
	{
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}
	
	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 )
	{
		close(fd);
		return(err);
	}
	printf(" stunnel %s successfully created\n", dev);
	
	return(fd);
}

// read a hunk of random goodness from the OS
int getrand(unsigned char *buff, int len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	len = read(fd, buff, len);
	close(fd);
	if (len < 1)	// TODO:  handle failure
	{
		len = 1;
	}
	return (len);
}

int update_nonce(char *role, int sts)
{

	if(sts <= CHANNELCOUNT)
	{

		if(*role == 'C')
		{
			printf("max value of nonce: %ld\n",MAX_VALUE_NONCE );
			auth_data[sts].client_cntr_nonce++;
			if(auth_data[sts].client_cntr_nonce > MAX_VALUE_NONCE)
				auth_data[sts].client_cntr_nonce = BASE_VALUE_FOR_CLIENT_NONCE;
			memset(auth_data[sts].nonce, 0, sizeof(auth_data[sts].nonce));
			printf("1 libg nonce: client.cntr_nonce: %ld\n",auth_data[sts].client_cntr_nonce ); 
			print_buf(auth_data[sts].nonce, NONCE_LENGTH);		
			memcpy(auth_data[sts].nonce, (uint8_t *)&auth_data[sts].client_cntr_nonce, NONCE_LENGTH);
			printf("2 libg nonce: "); 
			print_buf((uint8_t *)auth_data[sts].nonce, NONCE_LENGTH);		
			if(print_raw_encryption_logs >= 1)
				printf("counter nonce: %ld, size of client_cntr_nonce: %d\n", auth_data[sts].client_cntr_nonce, NONCE_LENGTH);	
		}
		if(*role == 'S')
		{
			auth_data[sts].server_cntr_nonce++;
			if(auth_data[sts].server_cntr_nonce > MAX_VALUE_NONCE)
				auth_data[sts].server_cntr_nonce = BASE_VALUE_FOR_SERVER_NONCE;			
			memset(auth_data[sts].nonce, 0, sizeof(auth_data[sts].nonce));
			memcpy(auth_data[sts].nonce, (uint8_t *)&auth_data[sts].server_cntr_nonce,  NONCE_LENGTH);
			if(print_raw_encryption_logs >= 1)
				printf("counter nonce: %ld, size of server_cntr_nonce: %d\n", auth_data[sts].server_cntr_nonce, NONCE_LENGTH);			
		}

		if(print_raw_encryption_logs >= 1)
		{
			printf("\n memcpy nonce %s: ", role);
			print_buf(auth_data[sts].nonce, NONCE_LENGTH);
		}
		
		printf(" 2 update nonce %ld\n", auth_data[sts].client_cntr_nonce);
	}
}

int update_key_from_server(uint8_t key_buf[], int key_size, uint8_t key_version)  // store the updated key and init the algo with the new key value
{
	if (encrypt)
	{
		for(int i=0;i<CHANNELCOUNT;i++)
		{
			printf(" in update_key(), len:%d key %d: %s\n", key_size, i, key_buf);
			memset(auth_data[i].key, 0, key_size);
			memcpy(auth_data[i].key, key_buf, key_size);	
			
			// previous key version set to current key version
			auth_data[i].previous_key_version.version = auth_data[i].current_key_version.version;

			// current key version set to new key version
			auth_data[i].current_key_version.version = key_version;

			if(print_raw_encryption_logs >= 1) 
				print_buf((uint8_t *)auth_data[i].key, key_size);
			
			chacha20_libgcrypt_init(auth_data[i].key, print_raw_encryption_logs);
		}
	}

	return 0;
}

uint16_t get_current_key_version()
{
	return symmetric_key_version;
}

uint8_t get_next_key_version()
{
	symmetric_key_version += 1;
	if(symmetric_key_version == 0)
		symmetric_key_version = 1;
	
	return  symmetric_key_version;
}
