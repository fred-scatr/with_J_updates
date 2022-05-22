
#ifndef HKDF_CONN_H
#define HKDF_CONN_H

#ifdef __cplusplus
extern "C" {
#endif

#define SYMMETRIC_KEY_SIZE_BYTES 32

int hkdf(uint8_t key_buf[], int key_size);
void print_buf_char(char buf[], int num_bytes);
void print_buf(uint8_t buf[], int num_bytes);


 #ifdef __cplusplus
}
#endif

#endif