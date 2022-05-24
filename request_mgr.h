#ifndef REQUEST_MGR_H
#define REQUEST_MGR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>

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

void handle_request(char *role, char buf[], int num_bytes_read);
int set_up_msg_request_socket();
int client_send_init_msg_to_server(char *role);
int recv_init_msg_from_client();
void client_send_request_new_key_to_server(char *role);
void create_msg_requests();

extern uint16_t get_current_key_version();
extern uint8_t get_next_key_version();

#define MAX_MSG_DATA_SIZE 1000
#define MSG_REQUEST_PORT_CLIENT 20000 
#define MSG_REQUEST_PORT_SERVER 20000
#define IP_ADDR_SERVER "10.42.0.153"
#define IP_ADDR_CLIENT "10.42.0.29"
#define KEY_ROTATION_INTERVAL 2*60  // 2 min interval

// messages between server and client stun unit. These messages will be transmitted over wireguard i/f
enum system_message
{   
    MIN_SYSTEM_MSG_NUMBER = 101,
    INIT,                                             // 102  0x66
    CLIENT_REQUEST_SYMMETRIC_KEY_FROM_SERVER,         // 103  0x67
    SERVER_SEND_SYMMETRIC_KEY_TO_CLIENT,              // 104  0x68
    SERVER_REQUEST_SYMMETRIC_KEY_VERIFICATION,        // 105  0x69
    CLIENT_SYMMETRIC_KEY_VERIFICATION_STATUS,         // 106  0x6a
    CLIENT_STUNNEL_STATUS,                            // 107  0x6b
    SERVER_REQUEST_CURRENT_CLIENT_KEY_VERSION,            // 108  0x6c
    CLIENT_REQUEST_CURRENT_SERVER_KEY_VERSION,            // 109  0x6d
    CLIENT_REQUEST_MULTI_SYMM_KEY_FROM_SERVER,        // 110 0x6e  // create multiplle keys on server and send to client - one per channel
    SERVER_SEND_MULTI_SYMM_KEY_TO_CLIENT,             // 111 0x6f
    MAX_SYSTEM_MSG_NUMBER
};

typedef struct {
    enum system_message sm;  // message number
    uint16_t len_data_bytes;
    uint16_t key_version; 
    uint8_t data[MAX_MSG_DATA_SIZE];    // associated data 

    // IP address, Port, hostname, etc., to identify this client connection for monitoring, ettc.
    //     - struct with key and other elements

} message;
#define SIZE_OF_MESSAGE_HEADER_BYTES 8

#endif