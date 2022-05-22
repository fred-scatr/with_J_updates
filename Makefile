stun_build: hkdf chacha20 stun request_mgr chacha20 packetdump
	g++ -g -o stun_hkdf.out hkdf.o stun.o chacha20_libgcrypt.o request_mgr.o packetdump.o -lcrypto++ -lgpg-error -lm -lgcrypt -lpthread 

hkdf: hkdf.cpp
	g++ -g -c -o hkdf.o hkdf.cpp 

request_mgr: request_mgr.c
	gcc -g -c -o request_mgr.o request_mgr.c

stun: stun.c
	gcc -g -c -o stun.o stun.c

chacha20: chacha20_libgcrypt.c
	gcc -g -c -o chacha20_libgcrypt.o chacha20_libgcrypt.c
	
packetdump: packetdump.c
	gcc -g -c -o packetdump.o packetdump.c	

.PHONY : clean
clean :
	-rm *.o $(objects) stun_hkdf.out
	
     
