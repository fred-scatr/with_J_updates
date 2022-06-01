
#include "request_mgr.h"
#include "hkdf_conn.h"

#define	CHANNELCOUNT		4    // FWW  needs to be imported from stun.c instead of copied here

int msg_request_socket;
time_t time_last_key_rotation, current_time;
unsigned char key_rotation_required = 0;
extern int update_key_from_server(uint8_t key_buf[], int key_size, uint8_t key_version);

int send_msg(message msg, char *role)  // server to client or  client to server
{
    int msg_req_addr;
    int sts;

    unsigned int size_of_ip = 15;
	struct sockaddr_in servaddr, cliaddr;
    char client_ip[size_of_ip], server_ip[size_of_ip];

    bzero(&client_ip,sizeof(client_ip));
    bzero(&server_ip,sizeof(server_ip));
    if(*role == 'C')
    {
        strncpy(server_ip, IP_ADDR_SERVER, sizeof(IP_ADDR_SERVER));  // 
    }
    else if(*role == 'S')
    { 
        strncpy(server_ip, IP_ADDR_CLIENT, sizeof(IP_ADDR_CLIENT));  // 
    }
    else
    {
        perror(" error in send_msg(): role not found");
    }

    if(msg_request_socket)
    {  
        //int sts = send(msg_request_socket, (const char *) msg, msg_length, 0);
        printf("role: %c, msg %d, data msg len: %d data: %s\n", *role, msg.sm, msg.len_data_bytes+SIZE_OF_MESSAGE_HEADER_BYTES, msg.data);            
        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(20000);
        inet_pton(AF_INET, server_ip, &servaddr.sin_addr);        
        sts = sendto(msg_request_socket, (const char *)&msg, msg.len_data_bytes + SIZE_OF_MESSAGE_HEADER_BYTES,
            0, (const struct sockaddr *) &servaddr, 
                sizeof(servaddr));

        if (sts > 0)
        {
            printf(" data sent len: %d,  msg len: %d data: %s\n", sts, msg.len_data_bytes+SIZE_OF_MESSAGE_HEADER_BYTES, msg.data);
            //print_buf(msg.data, msg.len_data_bytes);
        }	
        else if(sts < 0)
        {
            printf(" error in sending data for role: %c,  msg %d, data msg len: %d data: %s\n", 
                *role, msg.sm, msg.len_data_bytes+SIZE_OF_MESSAGE_HEADER_BYTES, msg.data); 
        }
        return 0;
    }
    else
    {
        perror("Error in client_send_init_msg_to_server: msg_request_socket not valid");
        return -1;
    }
    return 0;
}

void client_send_request_new_key_to_server(char *role)
{
   
    printf("msg: Client requests new Key from server\n");  // request new key here
    
    message msg;
    msg.sm = CLIENT_REQUEST_SYMMETRIC_KEY_FROM_SERVER;
    msg.len_data_bytes = 0;

    send_msg(msg, role);
}

int client_check_key_rotation_required()
{
    time(&current_time);
    double diff = difftime(current_time, time_last_key_rotation);

    time_last_key_rotation = current_time;
    if(diff > KEY_ROTATION_INTERVAL)
        return 1;
    else
        return 0;
}

void handle_request(char *role, char buf[], int num_bytes_read)
{
    printf(" in handle request\n");
    print_buf(buf, num_bytes_read);
    message *msg = (message *)buf;
    message new_msg;
    uint16_t next_key_version = 0;  // zero is invalid version number

    int msg_id =  (int)msg->sm;
    if(!(MIN_SYSTEM_MSG_NUMBER < msg->sm < MAX_SYSTEM_MSG_NUMBER))
    {
        printf(" error: rec'd out of bounds msg id: %d\n", msg_id);
    }

    if (*role == 'S')
    {
        printf("handle_request() server: msg id %d, len: %d\n", msg_id, msg->len_data_bytes);
        print_buf(buf, num_bytes_read);
        
        switch(msg_id)
        {
            // messages initiated by server intended for client
            case INIT:
                printf(" server init\n");
            break;

            case SERVER_REQUEST_SYMMETRIC_KEY_VERIFICATION:
                printf(" server sending request for symmetric key verification\n");
            break;

            case SERVER_REQUEST_CURRENT_CLIENT_KEY_VERSION:
                printf(" server sending request for current symmetric key version on client\n");
                
            break;


            // messages rec'd from client which require action
            case CLIENT_REQUEST_SYMMETRIC_KEY_FROM_SERVER:
                printf(" server rec'd key request update\n");
                uint8_t key_buf[SYMMETRIC_KEY_SIZE_BYTES]; // 
                hkdf(key_buf, SYMMETRIC_KEY_SIZE_BYTES);
                print_buf_char(key_buf, SYMMETRIC_KEY_SIZE_BYTES);

                // increment symmetric key version to send to client
                next_key_version = get_next_key_version();
                printf(" next version of key: %d\n", next_key_version);
                
                printf(" server updating key in stun\n");
                update_key_from_server(key_buf, SYMMETRIC_KEY_SIZE_BYTES, next_key_version);  // get an updated key
                printf(" server sending symm key to client\n");
                
                new_msg.sm = SERVER_SEND_SYMMETRIC_KEY_TO_CLIENT;
                new_msg.len_data_bytes = SYMMETRIC_KEY_SIZE_BYTES;
                new_msg.key_version = next_key_version; 
                memcpy(new_msg.data, key_buf, SYMMETRIC_KEY_SIZE_BYTES);  // fww change from copy here; just send new_msg.data
                print_buf(new_msg.data, new_msg.len_data_bytes);
                send_msg(new_msg, role); 
            break;

            case CLIENT_REQUEST_CURRENT_SERVER_KEY_VERSION:
                printf("    client request symm key from server\n");
                uint16_t current_key_version = get_current_key_version();
                printf(" current version of key: %d\n", next_key_version);                

                new_msg.sm = CLIENT_REQUEST_SYMMETRIC_KEY_FROM_SERVER;
                new_msg.len_data_bytes = 0;
                send_msg(new_msg, role);   
            break;

/*            case CLIENT_REQUEST_MULTI_SYMM_KEY_FROM_SERVER:  // key version is same for all; send bytes packed into msg.data
                printf("    client request multi symm key from server\n");
                int num_keys_requested = 0;
                if(msg->len_data_bytes > 0)
                    num_keys_requested = msg->data[0];
                printf(" num keys requested: %d\n", num_keys_requested);
            
                // increment symmetric key version to send to client; all common issuances of the key will have same version #
                next_key_version = get_next_key_version();
                printf(" next version of key: %d\n", next_key_version);

                new_msg.sm = SERVER_SEND_MULTI_SYMM_KEY_TO_CLIENT;
                new_msg.len_data_bytes = SYMMETRIC_KEY_SIZE_BYTES * num_keys_requested;
                new_msg.key_version = next_key_version; 

                for(int i=0;i<num_keys_requested;i++)  // get num_keys_requested keys and pack them into the key_buf
                {
                    printf(" %d, server rec'd key request update\n", i);

                    hkdf(&new_msg.data[i * SYMMETRIC_KEY_SIZE_BYTES], SYMMETRIC_KEY_SIZE_BYTES);
                    print_buf_char(new_msg.data, SYMMETRIC_KEY_SIZE_BYTES);

                    print_buf(new_msg.data, new_msg.len_data_bytes);

                }

                send_msg(new_msg, role);                     
                printf(" server updating multi key in stun\n");
                //update_multi_key_from_server(key_buf, SYMMETRIC_KEY_SIZE_BYTES, next_key_version, num_keys_requested);  // get an updated key
                printf(" server sending multi symm key to client\n");
                    


            break;        
*/
            default:
            break;
        }

    }
    // 
    else if (*role == 'C')
    {
        printf("    client handle_request(): %d bytes\n", num_bytes_read);
        print_buf(buf, num_bytes_read);

        msg = (message *)buf;
        printf("    msg req: %d, len: %d\n", (int)msg->sm, msg->len_data_bytes);

        
        switch(msg_id)
        {
            // messages initiated by client intended for server
            case INIT:
                printf("    client init \n");
              
            break;

            case CLIENT_REQUEST_SYMMETRIC_KEY_FROM_SERVER:
                printf("    client request symm key from server\n");

                new_msg.sm = CLIENT_REQUEST_SYMMETRIC_KEY_FROM_SERVER;
                new_msg.len_data_bytes = 0;
                send_msg(new_msg, role);                  
            break;

            case CLIENT_REQUEST_CURRENT_SERVER_KEY_VERSION:
                printf(" client sending request for current symmetric key version on server\n");

                new_msg.sm = CLIENT_REQUEST_CURRENT_SERVER_KEY_VERSION;
                new_msg.len_data_bytes = 0;
                send_msg(new_msg, role);                
            break;

 /*           case CLIENT_REQUEST_MULTI_SYMM_KEY_FROM_SERVER:
                printf(" client sending request for updated multiple symm key to server\n");

                new_msg.sm = CLIENT_REQUEST_MULTI_SYMM_KEY_FROM_SERVER;
                new_msg.len_data_bytes = 1;
                new_msg.data[0] = CHANNELCOUNT;
                send_msg(new_msg, role);                
            break;


            // messages rec'd from server and require action
            case SERVER_SEND_SYMMETRIC_KEY_TO_CLIENT:
                printf("    client rec'd symmetric key from server, key size: %d\n", msg->len_data_bytes );
                print_buf(msg->data, msg->len_data_bytes);
                printf("client rec'd updated key version %d\n", msg->key_version);
                update_key_from_server(msg->data, msg->len_data_bytes, msg->key_version);  // take updated key and write to stun key storage
            break;
*/
            default:
            break;
        }        
    }    
}

void create_msg_requests(char *role)
{
    if (*role == 'S')
    {

    }
    // 
    else if (*role == 'C')
    {
        // check key rotation required
        if(client_check_key_rotation_required())
        {
            printf(" create_msg_requests - chk key rotation true: \n");
        }
        
    }
}


int client_send_init_msg_to_server(char *role)
{
    printf(" sending init msg to server \n");
    time(&time_last_key_rotation);  // init time_last_key_rotation to start of msg req process
    
    message msg;
    msg.sm = INIT;
    msg.len_data_bytes = 0;

    return send_msg(msg, role);
}


int set_up_msg_request_socket(char *role)
{

    unsigned int size_of_ip = 15;
	struct sockaddr_in servaddr, cliaddr;
    int msg_request_port_client = MSG_REQUEST_PORT_CLIENT;
    int msg_request_port_server = MSG_REQUEST_PORT_SERVER;

    int retval = 0;

    if ((msg_request_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("Error on creating msg request socket\n");
        return -1;
    }
    else
    {
        printf(" msg_request_socket: %d\n", msg_request_socket);
    }

    char client_ip[size_of_ip], server_ip[size_of_ip];
    if (*role == 'S')
    {
        strncpy(server_ip, IP_ADDR_CLIENT, sizeof(IP_ADDR_SERVER));  // 
        strncpy(client_ip, IP_ADDR_SERVER, sizeof(IP_ADDR_CLIENT));  // 
        printf("\n msg request bind address for server: %s:%d\n", server_ip, msg_request_port_server);   

        // bind() to ensure use of specific IP address and port instead of INADDR_ANY
        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(msg_request_port_client);
        cliaddr.sin_addr.s_addr = inet_addr(server_ip);
        retval = bind(msg_request_socket, (struct sockaddr *)&servaddr, sizeof(servaddr));

        if (retval < 0)
        {
            printf("msg request bind failed\n");
            return retval;
        }
        else 
            return msg_request_socket;


    }
    else if (*role == 'C')
    {
        strncpy(client_ip, IP_ADDR_CLIENT, sizeof(IP_ADDR_CLIENT));  // 
        strncpy(server_ip, IP_ADDR_SERVER, sizeof(IP_ADDR_SERVER));  // 
        printf(" msg request bind address for client: %s:%d\n", client_ip, msg_request_port_client);        

        // bind() to ensure use of specific IP address and port instead of INADDR_ANY
        memset(&cliaddr, 0, sizeof(cliaddr));
        cliaddr.sin_family = AF_INET;
        cliaddr.sin_port = htons(msg_request_port_client);
        cliaddr.sin_addr.s_addr = inet_addr(client_ip);
        retval = bind(msg_request_socket, (const struct sockaddr *)&cliaddr, sizeof(cliaddr));

        if (retval < 0)
        {
            printf("msg request bind failed\n");
            return retval;
        }
        else 
            return msg_request_socket;        
     
    }        
}

 int recv_init_msg_from_client()  // fww - still needed??
{
    int retval = 0;
    int msg_req_addr;
    int num_bytes_recd = 0;
    char msg[MAX_MSG_DATA_SIZE];
    memset(&msg_req_addr, 0, sizeof(msg_req_addr));
    if(msg_request_socket)
    {    
        int sts = recvfrom(msg_request_socket, (char *)msg, MAX_MSG_DATA_SIZE, MSG_WAITALL, (struct sockaddr *) &msg_req_addr, &msg_req_addr);
        if (sts > 0)
        {

            /*    printf("Error on init msg request: rec'd msg from client, num bytes:%d: %s : \n",  sts, msg);
            else
                printf(" rec'd Init Request Msg\n");*/
        }
        else
        {
            perror(" Error in recv_init_msg_from_client: data invalid");
            retval = -1;
        }	
    }
    else
    {
        perror("Error in recv_init_msg_from_client: msg_request_socket not valid");
        retval = -1;
    }
    return retval;
}
