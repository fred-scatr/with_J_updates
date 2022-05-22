#include <iostream>
#include <string>

#include "/usr/include/crypto++/cryptlib.h"
#include "/usr/include/crypto++/hkdf.h"
#include "/usr/include/crypto++/sha.h"
#include "/usr/include/crypto++/filters.h"
#include "/usr/include/crypto++/hex.h"

#include "hkdf_conn.h"
#ifdef __cplusplus
extern "C" {
#endif

void print_buf(uint8_t  buf[], int num_bytes)
{
    printf("  ");
    for (int i = 0; i < num_bytes; i++)
        printf("%02x ", buf[i]);
    printf("  ");
    for (int i = 0; i < num_bytes; i++)
        printf("%c", buf[i]);        
    printf("\n");
}
void print_buf_char(char buf[], int num_bytes)
{
    printf("  ");
    for (int i = 0; i < num_bytes; i++)
        printf("%c", buf[i]);        
    printf("\n");
}

int hkdf(uint8_t key_buf[], int key_size)
{
    using namespace CryptoPP;

    byte password[] ="password";   // test version: passwords should be used with a Password-Based Key Derivation Function, 
                                    //   such as scrypt or Argon2id, not HKDF 
    size_t plen = strlen((const char*)password);

    byte salt[] = "salt";
    size_t slen = strlen((const char*)salt);

    byte info[] = "HKDF key derivation";
    size_t ilen = strlen((const char*)info);

    byte derived[SHA256::DIGESTSIZE];

    HKDF<SHA256> hkdf;
    hkdf.DeriveKey(derived, sizeof(derived), password, plen, salt, slen, info, ilen);

    std::string result;
    HexEncoder encoder(new StringSink(result));

    encoder.Put(derived, sizeof(derived));
    encoder.MessageEnd();

    std::cout << "Derived: " << result << std::endl;
    printf(" size of result: %ld\n", sizeof(result));

    std::cout<<"p/w: "<<(byte *)password<<std::endl;
    std::cout<<    sizeof(result)<<std::endl;
    
    if(key_size <= sizeof(derived))  // verifiy key size if compatible with digest size
    {
        for(int i=0;i<key_size;i++)
        {
            key_buf[i] = derived[i];
        }
    }
    else
    {
        std::cout << "Error in hkdf(): key size is different from digest size" << std::endl;
    }

    printf("server new key: ");
    print_buf(key_buf, key_size);

    return 0;
}

#ifdef __cplusplus
}
#endif