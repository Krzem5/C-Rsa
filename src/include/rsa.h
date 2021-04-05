#ifndef __RSA_H__
#define __RSA_H__ 1
#include <stdint.h>



typedef struct __RSA_KEYPAIR{
	uint16_t sz;
	uint64_t d;
	uint64_t e;
	uint64_t n;
} rsa_keypair_t;



void rsa_create_keypair(rsa_keypair_t* kp);



void rsa_print_keypair(rsa_keypair_t* kp);



#endif
