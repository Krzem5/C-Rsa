#include <rsa.h>
#include <windows.h>
#include <wincrypt.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#pragma intrinsic(__stosq)



void rsa_create_keypair(rsa_keypair_t* kp){
	HCRYPTPROV ctx;
	CryptAcquireContext(&ctx,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT);
	uint64_t p=61;
	uint64_t q=53;
	kp->n=p*q;
	p--;
	q--;
	uint64_t a=p;
	uint64_t b=q;
	uint64_t t;
	while (b){
		t=b;
		b=a%b;
		a=t;
	}
	uint64_t lcm=p/a*q;
	uint8_t i=0;
	for (;i<64;i++){
		if (!(lcm>>i)){
			break;
		}
	}
	kp->e=0;
	BYTE* bf=(BYTE*)&kp->e;
	uint8_t j=(i+7)>>3;
	i&=7;
	while (1){
		CryptGenRandom(ctx,j,bf);
		bf[j-1]&=i;
		if (kp->e>=lcm){
			continue;
		}
		a=kp->e;
		b=lcm;
		while (b){
			t=b;
			b=a%b;
			a=t;
		}
		if (a==1){
			break;
		}
	}
	CryptReleaseContext(ctx,0);
	a=kp->e;
	b=0;
	int64_t d=1;
	uint64_t m=lcm;
	while (a>1){
		uint64_t q=a/m;
		uint64_t t=m;
		m=a%m;
		a=t;
		int64_t t2=b;
		b=d-q*b;
		d=t2;
	}
	kp->d=d+(d<0?lcm:0);
}



void rsa_print_keypair(rsa_keypair_t* kp){
	printf("RSA Keypair:  \n  Private Key (D): %llu\n  Public  Key (E): %llu\n  Public  Key (N): %llu\n",kp->d,kp->e,kp->n);
}
