#include <rsa.h>



int main(int argc,const char** argv){
	rsa_keypair_t kp;
	rsa_create_keypair(&kp);
	rsa_print_keypair(&kp);
	return 0;
}
