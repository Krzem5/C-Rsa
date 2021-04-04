#include <rsa.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>



#define MILLER_RABIN_LOOP_LENGTH 40



uint64_t _mult_mod(uint64_t a,uint64_t b,uint64_t m){
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



uint64_t _pow_mod(uint64_t pb,uint64_t t,uint64_t m){
	uint64_t o=1;
	while (t){
		if (t&1){
			o=_mult_mod(o,pb,m);
		}
		pb=_mult_mod(pb,pb,m);
		t>>=1;
	}
	return o;
}



uint8_t _check_prime(uint64_t n,HCRYPTPROV ctx){
	const static uint64_t LOW_PRIMES[]={3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997};
	if (_pow_mod(2,n-1,n)!=1){
		return 0;
	}
	for (uint16_t i=0;i<sizeof(LOW_PRIMES)/sizeof(uint64_t);i++){
		if (n==LOW_PRIMES[i]){
			return 1;
		}
		if (!(n%LOW_PRIMES[i])){
			return 0;
		}
	}
	uint64_t s=n-1;
	uint64_t t=0;
	while (!(s&1)){
		s>>=1;
		t++;
	}
	uint8_t i=0;
	for (;i<64;i++){
		if (!(n>>i)){
			break;
		}
	}
	uint8_t j=(i+7)>>3;
	i=(uint8_t)((1<<(uint16_t)(i&7?i&7:8))-1);
	uint64_t a;
	BYTE* bf=(BYTE*)&a;
	for (uint8_t k=0;k<MILLER_RABIN_LOOP_LENGTH;k++){
		a=0;
		while (a<2||a>=n){
			CryptGenRandom(ctx,j,bf);
			bf[j-1]&=i;
		}
		uint64_t v=_pow_mod(a,s,n);
		if (v!=1){
			uint8_t l=0;
			while (v!=n-1){
				if (l==t-1){
					return 0;
				}
				l++;
				v=_mult_mod(v,v,n);
			}
		}
	}
	return 1;
}



void rsa_create_keypair(rsa_keypair_t* kp){
	HCRYPTPROV ctx;
	CryptAcquireContext(&ctx,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT);
	uint64_t p=0;
_gen_p:
	CryptGenRandom(ctx,sizeof(uint64_t),(BYTE*)&p);
	p&=~0x8000000000000000;
	p|=1;
	if (p<100){
		goto _gen_p;
	}
	if (!_check_prime(p,ctx)){
		goto _gen_p;
	}
	uint64_t q=0;
_gen_q:
	CryptGenRandom(ctx,sizeof(uint64_t),(BYTE*)&q);
	q&=~0x8000000000000000;
	q|=1;
	if (q<100){
		goto _gen_q;
	}
	if (!_check_prime(q,ctx)){
		goto _gen_q;
	}
	kp->n=p*q;
	p--;
	q--;
	uint64_t a=p;
	uint64_t b=q;
	while (b){
		uint64_t t=b;
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
	i=(uint8_t)((1<<(uint16_t)(i&7?i&7:8))-1);
	while (1){
		CryptGenRandom(ctx,j,bf);
		bf[j-1]&=i;
		if (kp->e>=lcm){
			continue;
		}
		a=kp->e;
		b=lcm;
		while (b){
			uint64_t t=b;
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
