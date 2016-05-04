/*
openssl genrsa -out alice.priv 2048 && openssl rsa -in alice.priv -outform PEM -pubout -out alice.pub


gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include dhClient.c socks.c -o dhClient -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
./dhClient
*/



#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "socks.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>


#define PUBKEY 1
#define PRIKEY 0
typedef unsigned char byte;
#define UNUSED(x) ((void)x)
const char hn[] = "SHA1";
int sock;
char ip_addr[] = "192.168.220.129";//ip address of server(localhost)
int port_no=54000;//source port no.
char dh_param[500];


char res[200];

struct sec{

	char value[64];
	int length;
};

/* Returns 0 for success, non-0 otherwise */
int make_keys(EVP_PKEY** skey, EVP_PKEY** vkey);

/* Returns 0 for success, non-0 otherwise */
int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey);

/* Returns 0 for success, non-0 otherwise */
int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey);
struct sec performDH(char *pubkeyRec,DH *privkey);
DH *createPubkey();
void print_it(const char* label, const byte* buff, size_t len);
RSA *readkey(char *location,int keytype);
void handleErrors(void);
char *createDataformat(const char *plaintext,char *encrypted,int encrypted_len, char *tokens[]);
void validateResponse(byte *response,EVP_PKEY *vkey,char *tokens[]);
int establishConnection();
void verifySignature(int sock,const byte *msg);

int main(){

	// printf("Testing RSA functions with EVP_DigestSign and EVP_DigestVerify\n");
	char response[1000];

	OpenSSL_add_all_algorithms();

	/* Sign and Verify HMAC keys */
	EVP_PKEY *skey = NULL, *vkey = NULL;
	
	int rc = make_keys(&skey, &vkey);
	assert(rc == 0);
	if(rc != 0)
	exit(1);

	assert(skey != NULL);
	if(skey == NULL)
	exit(1);

	assert(vkey != NULL);
	if(vkey == NULL)
	exit(1);
	DH *privkey=createPubkey();
	//char *dh_param_pub=BN_bn2dec(privkey->pub_key); 
	const byte *msg = BN_bn2dec(privkey->pub_key);//msg contains dh_param_pub
	printf("DH public key Generated:%s \n",msg);
	byte* sig = NULL;
	size_t slen = 0;

	
	
	sock=establishConnection();
	int i=0;
	//int count = split(data1, "$", tokens);
	sendMsg(sock,msg);
	
	 if( recv(sock, response , 6000 , 0) < 0)
	{
	puts("recv failed");
	}
	printf("Recieved Successfully:length of data=%d \n",(int)strlen(response));
	printf("DH public key Recieved:%s \n",response);
	//printf("Sent Successfully: length of data=%d\n",sumSend);
	char *pubkey=response;
	struct sec s=performDH(pubkey,privkey);
	printf("Shared key is:%s\n ",s.value);
	puts("The DH Key is");
	BIO_dump_fp(stdout, s.value, s.length);
	//free(msg);
	verifySignature(sock,msg);
	if(sig)
	OPENSSL_free(sig);

	if(skey)
	EVP_PKEY_free(skey);

	if(vkey)
	EVP_PKEY_free(vkey);
	
	return 0;
}

void verifySignature(int sock,const byte *msg){	
	EVP_PKEY *skey = NULL, *vkey = NULL;
	
	int rc = make_keys(&skey, &vkey);
	assert(rc == 0);
	if(rc != 0)
	exit(1);

	assert(skey != NULL);
	if(skey == NULL)
	exit(1);

	assert(vkey != NULL);
	if(vkey == NULL)
	exit(1);	

	
	byte* sig = NULL;
	size_t slen = 0;
	/* Using the skey or signing key */
	rc = sign_it(msg, sizeof(msg), &sig, &slen, skey);
	assert(rc == 0);
	if(rc == 0) {
	printf("Created signature with length %d\n",(int)slen);
	} else {
	printf("Failed to create signature, return code %d\n", rc);
	exit(1); /* Should cleanup here */
	}
	sendMsg(sock,"SendSignature");
	while(strstr(recvMsg(sock),"SendSignature")==NULL){}
	sendMsg(sock,sig);
	byte* sig2 = NULL;
	sig2=recvMsg(sock);
	rc = verify_it(msg, sizeof(msg), sig2, sizeof(sig2), vkey);
	if(rc == 0) {
	printf("Verified signature. the length of sig is %d\n",(int)slen);
	} else {
	printf("length of recived signature is %d",(int)slen);
	printf("Failed to verify signature, return code %d\n", rc);
	}

}


int establishConnection(){
	sock=createTcpSocket();
	connectToIpv4(sock,ip_addr,port_no);
	
	return sock;
}



char *createDataformat(const char *plaintext,char *encrypted,int encrypted_len, char *tokens[]){
	tokens[0]=plaintext;
	char e[4];
	sprintf(e,"%d",encrypted_len);
	tokens[1]="256";
	tokens[2]=encrypted;
	tokens[3]=NULL;

}
void validateResponse(byte *response,EVP_PKEY *vkey,char *tokens[]){
	char ch4param[1000];
	if (strstr(response,"$$")!=NULL)
	{
	char *token = strtok(ch4param,"$$"); //token=ddh_param
	tokens[0]=token;
	char *token2 ="256";
	tokens[1]=token2;
	//token2=length=256
	
	char *token3 = strtok(NULL,"$$");
	tokens[2]=token3;
	}
	else{
	tokens[0]=response;
	tokens[1]="";
	tokens[2]="";
	tokens[3]="";
	}
}



void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}


int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !pkey) {
        assert(0);
        return -1;
    }
    
    if(*sig)
        OPENSSL_free(*sig);
    
    *sig = NULL;
    *slen = 0;
    
    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        assert(req > 0);
        if(!(req > 0)) {
            printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *sig = OPENSSL_malloc(req);
        assert(*sig != NULL);
        if(*sig == NULL) {
            printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }
        
        assert(req == *slen);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    return !!result;
}

int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    
    if(!msg || !mlen || !sig || !slen || !pkey) {
        assert(0);
        return -1;
    }
    
    EVP_MD_CTX* ctx = NULL;
    
    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        const EVP_MD* md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        int rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        /* Clear any errors for the call below */
        ERR_clear_error();
        
        rc = EVP_DigestVerifyFinal(ctx, sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        result = 0;
        
    } while(0);
    
    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    
    return !!result;

}

void print_it(const char* label, const byte* buff, size_t len)
{
    if(!buff || !len)
        return;
    
    if(label)
        printf("%s: ", label);
    
    for(size_t i=0; i < len; ++i)
        printf("%02X", buff[i]);
    
    printf("\n");
}

int make_keys(EVP_PKEY** skey, EVP_PKEY** vkey)
{
    int result = -1;
    
    if(!skey || !vkey)
        return -1;
    
    if(*skey != NULL) {
        EVP_PKEY_free(*skey);
        *skey = NULL;
    }
    
    if(*vkey != NULL) {
        EVP_PKEY_free(*vkey);
        *vkey = NULL;
    }
    
    RSA* rsa = NULL;
    
    do
    {
        *skey = EVP_PKEY_new();
        assert(*skey != NULL);
        if(*skey == NULL) {
            printf("EVP_PKEY_new failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        *vkey = EVP_PKEY_new();
        assert(*vkey != NULL);
        if(*vkey == NULL) {
            printf("EVP_PKEY_new failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        rsa=readkey("alice.priv",PRIKEY);
        //rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	
       // assert(rsa != NULL);
       // if(rsa == NULL) {
        //    printf("RSA_generate_key failed, error 0x%lx\n", ERR_get_error());
         //   break; /* failed */
        //}
        
        /* Set signing key */
        int rc = EVP_PKEY_assign_RSA(*skey, RSAPrivateKey_dup(rsa));
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_PKEY_assign_RSA (1) failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        /* Sanity check. Verify private exponent is present */
        /* assert(EVP_PKEY_get0_RSA(*skey)->d != NULL); */

        /* Set verifier key */
	 RSA *rsa1=readkey("bob.pub",PUBKEY);
        rc = EVP_PKEY_assign_RSA(*vkey, RSAPublicKey_dup(rsa1));
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_PKEY_assign_RSA (2) failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        
        /* Sanity check. Verify private exponent is missing */
        /* assert(EVP_PKEY_get0_RSA(*vkey)->d == NULL); */
        
        result = 0;
        
    } while(0);
    
    if(rsa) {
        RSA_free(rsa);
        rsa = NULL;
    }
    
    return !!result;
}
struct sec performDH(char *pubkeyRec,DH *privkey){
	
	struct sec s;
	int secret_size;
	/* Send the public key to the peer.
	* How this occurs will be specific to your situation (see main text below) */


	/* Receive the public key from the peer. In this example we're just hard coding a value */
	BIGNUM *pubkey = NULL;
	if(0 == (BN_dec2bn(&pubkey, pubkeyRec))) handleErrors();

	/* Compute the shared secret */
	unsigned char *secret;
	if(NULL == (secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(privkey))))) handleErrors();

	if(0 > (secret_size = DH_compute_key(secret, pubkey, privkey))) handleErrors();

	/* Do something with the shared secret */
	/* Note secret_size may be less than DH_size(privkey) */
	printf("The shared secret is:\n");
	
	strcpy(s.value,secret);
	s.length=secret_size;
	/* Clean up */
	OPENSSL_free(secret);
	BN_free(pubkey);
	DH_free(privkey);

	return s;
}
RSA *readkey(char *location,int keytype){
	
	
	FILE *infile;
	
	
	infile = fopen(location, "r");
	
	
	if (keytype==PUBKEY){
	RSA *key=PEM_read_RSA_PUBKEY(infile,NULL,NULL,NULL);
	return key;}
	else if (keytype==PRIKEY){
	RSA *key= PEM_read_RSAPrivateKey(infile,NULL,NULL,NULL);
	return key;}
	
}

DH *createPubkey(){

	DH *privkey;
	int codes;
	

	/* Generate the parameters to be used */
	if(NULL == (privkey = DH_new())) handleErrors();
	if(1 != DH_generate_parameters_ex(privkey, 512, DH_GENERATOR_2, NULL)) handleErrors();

	if(1 != DH_check(privkey, &codes)) handleErrors();
	if(codes != 0)
	{
	/* Problems have been found with the generated parameters */
	/* Handle these here - we'll just abort for this example */
	printf("DH_check failed\n");
	abort();
	}

	/* Generate the public and private key pair */
	if(1 != DH_generate_key(privkey)) handleErrors();
	return privkey;
	
}
