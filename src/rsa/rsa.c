#include <rsa.h>
#include <windows.h>
#include <wincrypt.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#pragma intrinsic(__stosq)




uint64_t _mul_mod(uint64_t a,uint64_t b,uint64_t m){
	uint64_t o=0;
	while (a){
		if (a&1){
			o=(o+b)%m;
		}
		a>>=1;
		b=(b<<1)%m;
	}
	return o;
}



void rsa_create_keypair(rsa_keypair_t* kp){
	HCRYPTPROV ctx;
	CryptAcquireContext(&ctx,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT);
	uint64_t p=0;
_gen_p:
	CryptGenRandom(ctx,sizeof(uint64_t),(BYTE*)&p);
	// uint64_t t=p-1;
	// uint64_t c=1;
	// while (t){
	// 	uint64_t s=(t>32?32:t);
	// 	t-=s;
	// 	c=(c<<s)%p;
	// }
	p&=~0x8000000000000000;
	if (p<100){
		goto _gen_p;
	}
	uint64_t pb=2;
	uint64_t pt=p-1;
	uint64_t o=1;
	while (pt){
		if (pt&1){
			o=_mul_mod(o,pb,p);
		}
		pb=_mul_mod(pb,pb,p);
		pt>>=1;
	}
	if (o!=1){
		printf("%llu\n",p);
		goto _gen_p;
	}
	uint64_t q=0;
	while (q<100){
		CryptGenRandom(ctx,sizeof(uint64_t),(BYTE*)&q);
	}
	printf("%llu, %llu\n",p,q);
	/***/p=61;q=53;/***/
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
