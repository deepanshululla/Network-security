
#include <stdio.h>
#include <string.h>    //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include "socks.h"


//char *message; 
//char server_reply[2000];

int createTcpSocket()
{
	int socket_desc;
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
     
	if (socket_desc == -1)
	{
		printf("Could not create socket \n");
	}
	else
	{
		printf("Socket Created \n");
	}
     
	return socket_desc;
	
}

void connectToIpv4(int sock,char ip_addr[],int port_no)
{
	struct sockaddr_in serverAddress;
	
	serverAddress.sin_addr.s_addr = inet_addr(ip_addr);
	serverAddress.sin_family = AF_INET;

	serverAddress.sin_port = htons(port_no);
	if (connect(sock,(struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
	{
		puts("connect error");
		
	}
	else 
	{    
		puts("Connected to server");
	}
}


void sendMsg(int sock,char *message)
{
	
	if( send(sock , message , strlen(message) , 0) < 0)
	{
		puts("Send failed");
		
	}
	else
	{
		puts("message sent");
	}
}

char *recvMsg(int sock)
{
	static char reply[2000];
	if( recv(sock, reply , 2000 , 0) < 0)
	{
		puts("recieve failed \n");
	}
	else
	{
		puts("Reply received\n");
	}	
	return reply;
}
    

void bindToIpv4(int socket_desc,char ip_addr[],int port_no)
{
	struct sockaddr_in serverAddress;
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = inet_addr(ip_addr);
	serverAddress.sin_port = htons(port_no);
     
    //Bind
	if( bind(socket_desc,(struct sockaddr *)&serverAddress , sizeof(serverAddress)) < 0)
	{
	        //print the error message
		perror("bind failed. Error");
        
	}
	else
	{
		puts("bind done");
	}
}


int acceptConnections(int socket_desc)
{
	int c,client_sock;
	struct sockaddr_in clientAddress;
	c = sizeof(struct sockaddr_in);
     
    //accept connection from an incoming client
	client_sock = accept(socket_desc, (struct sockaddr *)&clientAddress, (socklen_t*)&c);
	if (client_sock < 0)
	{
		perror("accept failed");
		return 0;
	}
	else
	{
		puts("Connection accepted");
		return client_sock;
	}    
}


void closeSocket(int sock)
{
	close(sock);
}


void startListening(int server_sock,int max_connections)
{
	listen(server_sock,max_connections);
}
