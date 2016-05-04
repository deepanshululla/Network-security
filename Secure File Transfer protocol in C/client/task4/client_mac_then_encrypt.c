#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "socks.h"
#include <stddef.h>

#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int sock;
char ip_addr[] = "192.168.220.129";//ip address of server
int port_no=54000;//destination port no.
char *message; 
char server_reply[300];
char mdString[20];
unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
/*
gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include client_mac_then_encrypt.c socks.c -o client -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
*/

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);
char *decryptMsg(char *server_reply,int cipher_len);
void handleErrors(void);
int verifyHmac(char *data,char *sig);



int main(int argc , char *argv[])
{
	int ciphertext_len=0;
	char cop[300];
	sock=createTcpSocket();
	connectToIpv4(sock,ip_addr,port_no);
	char decryptedmsg[128];	
	char decryptedmsgHmac[170];		
	message="GET /file2send.txt";
	
	sendMsg(sock,message);
	printf("Sent Successfully: length of data=%d",(int)strlen(message));
	puts(message);
	while (recv(sock, server_reply , 15000 , 0)<0){};
	printf("Recieved Successfully:length of data=%d ",(int)strlen(server_reply));
	puts(server_reply);
	if (strstr(server_reply,"$Incominglength=$")!=NULL)
	{
		strcpy(cop,server_reply);
		char *token = strtok(cop,"$");//Incoming length
		char *token2 = strtok(NULL,"$");// size of cipher
		//token = strtok(NULL,"Message begins:");
		ciphertext_len=atoi(token2);
		char *token3=strtok(NULL,"$");//EncryptedMessage:
		char token4[128];//token 4=encryptedMsg--checked uptil here
		strcpy(token4,strtok(NULL,"$"));
		strcpy(decryptedmsgHmac,decryptMsg(token4,ciphertext_len));
		//while(recv(sock, server_reply, 2000 , 0)){
			//server_reply=recvMsg(sock);
		char *token5=strtok(decryptedmsgHmac,"$");//Message
		char token6[128];//token6=decrypted text
		strcpy(token6,strtok(NULL,"$"));
		//token3=strtok(NULL,"Message begins:");

		strcpy(decryptedmsg,token6);
		puts("The decrypted message is");
		puts(decryptedmsg);
		//printf("The length of decrypted msg is %d\n",decryptedtext_len);
		char *token7=strtok(NULL,"$");//HMac
		char token8[40];
		strcpy(token8,strtok(NULL,"$"));
		if(verifyHmac(decryptedmsg,token8))
			{puts("Hmac verified");}
		//}
		//decryptMsg(server_reply,ciphertext_len);
	}

	return 0;
}
int verifyHmac(char *data,char *sig){
	 // The key to hash
	
	unsigned char *digest1;
	digest1 = HMAC(EVP_sha1(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);   
	

	for(int i = 0; i < 20; i++)
	 {sprintf(&mdString[i*2], "%02x", (unsigned int)digest1[i]);}
	puts("Computing HMAC");
	puts(mdString);
	puts(sig);
	if(strcmp(mdString,sig)==0){
		//puts("Hmac verified");
		return 1;
		
	}
	return 0;
}
char *decryptMsg(char *server_reply,int ciphertext_len){

	
	
	

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)"01234567890123456";
	/* Buffer for ciphertext. Ensure the buffer is long enough for the
	* ciphertext which may be longer than the plaintext, dependant on the
	* algorithm and mode
	*/
	unsigned char ciphertext[256];
	
	/* Buffer for the decrypted text */
	unsigned char decryptedtext[256];
	int decryptedtext_len=0;
	
	
	decryptedtext_len = decrypt(server_reply, ciphertext_len, key, iv,decryptedtext);
	decryptedtext[decryptedtext_len] = '\0';
	//puts("The decrypted message is");
	//puts(decryptedtext);
	//printf("The length of decrypted msg is %d\n",decryptedtext_len);
	return decryptedtext;

}
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len=0;

	int plaintext_len=0;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}
void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}
