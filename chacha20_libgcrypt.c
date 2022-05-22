#include <stdio.h>
#include <gcrypt.h>
#include <assert.h>
#include <stdlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>  
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "hkdf_conn.h"
#include "chacha20.h"

gcry_error_t     gcryError;
gcry_cipher_hd_t gcryCipherHd;


int chacha20_libgcrypt_init(char * chacha20SymKey, int print_raw_encryption_logs)
{
    #define GCRY_CIPHER GCRY_CIPHER_CHACHA20   // Pick the cipher here
    #define GCRY_C_MODE GCRY_CIPHER_MODE_POLY1305 // Pick the cipher mode here
    //#define GCRY_C_MODE GCRY_CIPHER_MODE_STREAM

    int retval;
    const char * ver;

    ver = gcry_check_version(NULL);   // this statement is part of the init for the lib and is required    
    printf("\n libgcrypt version = %s\n", ver);

    size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
    printf("algo set key length: %ld\n", keyLength);

    gcryError = gcry_cipher_open(
        &gcryCipherHd, // gcry_cipher_hd_t *
        GCRY_CIPHER,   // int
        GCRY_C_MODE,   // int
        0);            // unsigned int
    if (gcryError)
    {
        printf("gcry_cipher_open failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
        return -1;
    }
    if (print_raw_encryption_logs >= 0) ("gcry_cipher_open    worked\n");

    gcryError = gcry_cipher_setkey(gcryCipherHd, chacha20SymKey, keyLength);
    if (gcryError)
    {
        printf("gcry_cipher_setkey failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
        return -1;
    }
    if (print_raw_encryption_logs >= 0) printf("gcry_cipher_setkey  worked\n");

    uint64_t c = 0;
    gcryError = gcry_cipher_setctr (gcryCipherHd, NULL, 0);
    if (gcryError)
    {
        printf("gcry_cipher_setctr failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
        return -1;
    }
    else
    {
        if(print_raw_encryption_logs >= 0)printf("gcry_cipher_setctr worked \n");
    }
}

int chacha20_libgcrypt_encrypt_decrypt(char * input_msg_buf, int input_msg_len, AUTH_DATA auth_data,
    char result[], int print_raw_encryption_logs)
{
    int retval, i;
    size_t  index;

    char * txtBuffer_in_out = input_msg_buf;
    size_t txtLength_in_out = input_msg_len + 1; // string plus termination
    char * encBuffer = NULL;   //set to NULL for in-place buffer encryption
    size_t outBuffer_len = 0;       // set to 0 for in-place buffer encryption

	if(print_raw_encryption_logs >= 2)
    {
        if(input_msg_len > 0)
        {
            printf("input bytes len: %d, data: ", input_msg_len);
            for (index = 0; index<input_msg_len; index++)
                printf("%02X ", (unsigned char)input_msg_buf[index]);
            printf("\n");
            printf("input ascii = ");
            for (index = 0; index<input_msg_len; index++)
                printf("%c", (unsigned char)input_msg_buf[index]);
            printf("\n\n");
        }
    }

	if(print_raw_encryption_logs >= 2)
    {
        printf(" chacha20 key: ");
        //for(i=0;i<keylen;i++) printf("%02x ",key_buf[i]);
        print_buf(auth_data.key, KEY_LENGTH);
        printf("nonce: ");
        //for(i=0;i<nonce_len;i++) printf("%02x ",nonce_buf[i]);
        print_buf(auth_data.nonce, NONCE_LENGTH);
        printf("\n");
    }


    if (print_raw_encryption_logs >= 2) printf(" Encrypt-Decrypt algo: %s\n", gcry_cipher_algo_name(GCRY_CIPHER) );

    /*int what;
    size_t nbytes;
    gcryError = gcry_cipher_gettag(gcryCipherHd, GCRY_CIPHER_MODE_STREAM, NULL, &nbytes);
    if (gcryError)
    {
        printf("gcry_cipher_authenticate failed:  %s/%s\n",
            gcry_strsource(gcryError),
            gcry_strerror(gcryError));
        return;
    }
    else
    {
        printf(" cipher info: GCRYCTL_GET_TAGLEN is %ld\n", nbytes);
    } */
    
    
    printf("3 libg nonce: "); 
    print_buf(auth_data.nonce, NONCE_LENGTH);
    gcryError = gcry_cipher_setiv(gcryCipherHd, auth_data.nonce, NONCE_LENGTH);
    if (gcryError)
    {
        printf("gcry_cipher_setiv failed:  %s/%s\n",
               gcry_strsource(gcryError),
               gcry_strerror(gcryError));
        return -1;
    }
    if (print_raw_encryption_logs >= 2) printf("gcry_cipher_setiv   worked\n");

    gcryError = gcry_cipher_encrypt(
        gcryCipherHd, // gcry_cipher_hd_t
        txtBuffer_in_out,    // void *   - out buffer
        txtLength_in_out,    // size_t
        encBuffer,    // const void *   - in buffer
        outBuffer_len);   // size_t
    if (gcryError)
    {
        printf("gcry_cipher_encrypt failed:  %s/%s\n",
            gcry_strsource(gcryError),
            gcry_strerror(gcryError));
        return -1;
    }
    if (print_raw_encryption_logs >= 2) printf("gcry_cipher_encrypt worked\n");

    retval = txtLength_in_out - 1;

	if(print_raw_encryption_logs >= 2)
    {
        printf("data len: %ld, encoded/decoded Data:  ", txtLength_in_out);
        for (index = 0; index<txtLength_in_out-1; index++)
            printf("%02X", (unsigned char)txtBuffer_in_out[index]);
        printf("\n");
        printf("ascii = ");
        for (index = 0; index<txtLength_in_out-1; index++)
            printf("%c", (unsigned char)txtBuffer_in_out[index]);
        printf("\n");        
    }


return retval;
}
