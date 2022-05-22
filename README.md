# stunnel
C language stun tunnel implementation for Linux.

## v1.0
	* base version of stunnel plus chacha20 test module
	* no extra libraries required
	* key and nonce are fixed values from beginning of run
	* variable log verbosity: 0-2, 0 is minimal logs, 2 is maximum
	
## v1.1
	* adds updated nonce for each msg
	* keeps fixed key value
	* unique nonce for both server and client
	* nonce is a 12-byte counter

## v1.2
	* adds libgcrypt C library  
	* libgcrypt has chacha20 functionality
	* nonce is updated for each message
	* key is fixed
	* this version requires Libgcrypt and libgpg-error libraries
		* download Libgcrypt (LTS) from:
			https://github.com/gpg/libgcrypt	
		* version used for integration is: libgcrypt-1.8.9.tar.bz2 
		* once downloaded, build the library
			* ./configure
			* make
		* copy the library files to /usr/local/lib/ or specify the director with -L
	
		* download Libgpg-error from:
			https://github.com/gpg/libgcrypt	
		* version used for integration is: libgpg-error-1.44.tar.bz2
		* once downloaded, build the library		
			* ./configure
			* make
		* copy the library files to /usr/local/lib/ or specify the director with -L 			
	* Build the libgcrypt_test_chacha executable with the script:
			* build_chacha_test.sh
