
/* 
 github.com/Ginurx/chacha20-c

README.md:
ChaCha20 stream cipher implemented in C

struct chacha20_context ctx;
chacha20_init_context(&ctx, key, nonce, counter);
chacha20_xor(&ctx, buffer, size_of_buffer);
*/

#include "chacha20.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>

uint64_t counter = 0;
int nonce_ctr = 1;

extern int getrand(unsigned char *buff, int len);

static uint32_t rotl32(uint32_t x, int n) 
{
	return (x << n) | (x >> (32 - n));
}

static uint32_t pack4(const uint8_t *a)
{
	uint32_t res = 0;
	res |= (uint32_t)a[0] << 0 * 8;
	res |= (uint32_t)a[1] << 1 * 8;
	res |= (uint32_t)a[2] << 2 * 8;
	res |= (uint32_t)a[3] << 3 * 8;
	return res;
}

static void unpack4(uint32_t src, uint8_t *dst) {
	dst[0] = (src >> 0 * 8) & 0xff;
	dst[1] = (src >> 1 * 8) & 0xff;
	dst[2] = (src >> 2 * 8) & 0xff;
	dst[3] = (src >> 3 * 8) & 0xff;
}

static void chacha20_init_block(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[])
{
	memcpy(ctx->key, key, sizeof(ctx->key));
	memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

	const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";
	ctx->state[0] = pack4(magic_constant + 0 * 4);
	ctx->state[1] = pack4(magic_constant + 1 * 4);
	ctx->state[2] = pack4(magic_constant + 2 * 4);
	ctx->state[3] = pack4(magic_constant + 3 * 4);
	ctx->state[4] = pack4(key + 0 * 4);
	ctx->state[5] = pack4(key + 1 * 4);
	ctx->state[6] = pack4(key + 2 * 4);
	ctx->state[7] = pack4(key + 3 * 4);
	ctx->state[8] = pack4(key + 4 * 4);
	ctx->state[9] = pack4(key + 5 * 4);
	ctx->state[10] = pack4(key + 6 * 4);
	ctx->state[11] = pack4(key + 7 * 4);
	// 64 bit counter initialized to zero by default.
	ctx->state[12] = 0;
	ctx->state[13] = pack4(nonce + 0 * 4);
	ctx->state[14] = pack4(nonce + 1 * 4);
	ctx->state[15] = pack4(nonce + 2 * 4);

	memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));
}

static void chacha20_block_set_counter(struct chacha20_context *ctx, uint64_t counter)
{
	ctx->state[12] = (uint32_t)counter;
	ctx->state[13] = pack4(ctx->nonce + 0 * 4) + (uint32_t)(counter >> 32);
}

static void chacha20_block_next(struct chacha20_context *ctx) {
	// This is where the crazy voodoo magic happens.
	// Mix the bytes a lot and hope that nobody finds out how to undo it.
	for (int i = 0; i < 16; i++) ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

	for (int i = 0; i < 10; i++) 
	{
		CHACHA20_QUARTERROUND(ctx->keystream32, 0, 4, 8, 12)
		CHACHA20_QUARTERROUND(ctx->keystream32, 1, 5, 9, 13)
		CHACHA20_QUARTERROUND(ctx->keystream32, 2, 6, 10, 14)
		CHACHA20_QUARTERROUND(ctx->keystream32, 3, 7, 11, 15)
		CHACHA20_QUARTERROUND(ctx->keystream32, 0, 5, 10, 15)
		CHACHA20_QUARTERROUND(ctx->keystream32, 1, 6, 11, 12)
		CHACHA20_QUARTERROUND(ctx->keystream32, 2, 7, 8, 13)
		CHACHA20_QUARTERROUND(ctx->keystream32, 3, 4, 9, 14)
	}

	for (int i = 0; i < 16; i++) ctx->keystream32[i] += ctx->state[i];

	uint32_t *counter = ctx->state + 12;
	// increment counter
	counter[0]++;
	if (0 == counter[0]) 
	{
		// wrap around occured, increment higher 32 bits of counter
		counter[1]++;
		// Limited to 2^64 blocks of 64 bytes each.
		// If you want to process more than 1180591620717411303424 bytes
		// you have other problems.
		// We could keep counting with counter[2] and counter[3] (nonce),
		// but then we risk reusing the nonce which is very bad.
		assert(0 != counter[1]);
	}
}

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[], uint64_t counter)
{
	memset(ctx, 0, sizeof(struct chacha20_context));

	chacha20_init_block(ctx, key, nonce);
	chacha20_block_set_counter(ctx, counter);

	ctx->counter = counter;
	ctx->position = 64;
}

int chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes, char result[], int print_raw_encryption_logs)
{
	uint8_t *keystream8 = (uint8_t*)ctx->keystream32;
	uint8_t test;
	uint8_t *ptr = &result[0];
	int bytes_converted = 0;
	if(print_raw_encryption_logs == 2)
	{
		printf("\n n_bytes: %ld\n", n_bytes);
		printf(" chacha input: ");
		for(int i=0;i<n_bytes;i++)
		{
			printf("%02x ", (uint8_t)bytes[i]);
		}
		printf("\n");

		printf("\n");
		for(int i=0;i<n_bytes;i++)
		{
			printf("%c", (uint8_t)bytes[i]);
		}
		printf("\n");		
	}
	
	for (size_t i = 0; i < n_bytes; i++) 
	{
		//printf(" ctx pos: %ld\n", ctx->position);
		if (ctx->position >= 64) 
		{
			chacha20_block_next(ctx);
			ctx->position = 0;
		}

		if(print_raw_encryption_logs >= 2)
		{
			test = bytes[i] ^ keystream8[ctx->position];
			printf(" converted: %02x  pos: %ld  xor val: %02x\n", test, ctx->position, keystream8[ctx->position]);
			*ptr++ = test;
		}	
		bytes[i] ^= keystream8[ctx->position];

		ctx->position++;
		bytes_converted++;
	}

	if(print_raw_encryption_logs >= 2)
	{	
		printf(" chacha output: ");
		for(int i=0;i<n_bytes;i++)
		{
			printf("%02x ", (uint8_t)bytes[i]);
		}


		printf("\n");
		for(int i=0;i<n_bytes;i++)
		{
			printf("%c", (uint8_t)bytes[i]);
		}
		printf("\n");	
	}
	return 	bytes_converted++;
;

}

int encrypt_decrypt_buffer_chacha_(char * input_msg_buf, int input_msg_len, uint8_t key_buf[], 
        int keylen, uint8_t nonce_buf[], int nonce_len, char result[], int print_raw_encryption_logs)
{
	struct chacha20_context ctx;
	int i = 0;
	int retval = 0;
	if(print_raw_encryption_logs >= 1)
	{
		printf(" chacha.c key: ");
		for(i=0;i<keylen;i++) printf("%02x",key_buf[i]);
		printf("\n nonce: ");
		for(i=0;i<nonce_len;i++) printf("%02x",nonce_buf[i]);
		printf("\n");
	}

	//printf(" init context \n");

	/*printf(" key: ");
	for(i=0;i<KEY_LENGTH;i++) printf("%02x",key_buf[i]);
	printf("\n nonce len %d  : ", NONCE_LENGTH);
	for(i=0;i<NONCE_LENGTH;i++) printf("%02x",nonce_buf[i]);
	printf("\n");
	*/

	//printf(" init context \n");
	chacha20_init_context(&ctx, key_buf, nonce_buf, counter);
	retval = chacha20_xor(&ctx, input_msg_buf, input_msg_len, result, print_raw_encryption_logs);


  return retval;
}

