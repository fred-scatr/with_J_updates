
#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#ifndef CHACHA20_H
#define CHACHA20_H

#ifdef __cplusplus 
extern "C" {
#endif

typedef struct
{
	uint32_t	sequence;	// sequence number
	uint16_t	packet;		// packet bytes
	uint16_t	spare;		// unused
} __attribute__((packed)) STUNHEADER;

#define KEY_LENGTH 32
#define KEY_VERSION_LENGTH 2  
#define NONCE_LENGTH 12
#define MAX_VALUE_NONCE (unsigned long)(pow(2, NONCE_LENGTH) - 1)

#define BASE_VALUE_FOR_CLIENT_NONCE 100
#define BASE_VALUE_FOR_SERVER_NONCE 200

typedef struct 
{
	uint8_t major;
	uint8_t minor;
} KEY_VERSION;

typedef struct 
{
	unsigned long client_cntr_nonce;
	unsigned long server_cntr_nonce;
	uint8_t key[KEY_LENGTH];
	uint8_t nonce[NONCE_LENGTH];
	KEY_VERSION current_key_version;
	KEY_VERSION previous_key_version;	
} AUTH_DATA;


struct chacha20_context
{
	uint32_t keystream32[16];
	size_t position;

	uint8_t key[32];
	uint8_t nonce[12];
	uint64_t counter;

	uint32_t state[16];
};

int chacha20_libgcrypt_init(char * chacha20SymKey, int print_raw_encryption_logs);
int chacha20_libgcrypt_encrypt_decrypt(char * input_msg_buf, int input_msg_len, AUTH_DATA auth_data, char result[], int print_raw_encryption_logs);

int update_nonce(char * role, int sts);

#ifdef __cplusplus 
}
#endif 

#endif