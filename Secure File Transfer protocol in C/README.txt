TASK 1: Certificate generation for RSA keys
$openssl req -x509 -newkey rsa:2048 -keyout alice.priv -out alice.pub -days 100 -nodes

TASK 2 - Use Diffie-Hellman to generate encryption key and HMAC symmetric keys
Server
$openssl genrsa -out bob.priv 2048 && openssl rsa -in bob.priv -outform PEM -pubout -out bob.pub

$gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include dhServer.c socks.c -o dhServer -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
$./dhServer

Client

$ gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include dhClient.c socks.c -o dhClient -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
$./dhClient

Server

$ gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include dhServer.c socks.c -o dhServer -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
$ ./dhServer

PART 3 - Encryption, encrypt and mac

Client

$ gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include client_encrypt_and_mac.c socks.c -o client -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
$./client

Server

$ gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include server_encrypt_and_mac.c socks.c -o server -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
$ ./server


PART 4 - Encryption - mac then encrypt
Client

$ gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include client_mac_then_encrypt.c socks.c -o client -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
$./client

Server

$ gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include server_mac_then_encrypt.c socks.c -o server -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
$ ./server


Client

$ gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include client_encrypt_then_mac.c socks.c -o client -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
$./client

Server

$ gcc -c socks.c -o socks.o && gcc -std=c99 -g -I/usr/local/openssl/include server_encrypt_then_mac.c socks.c -o server -L/usr/local/openssl/lib -lssl -lcrypto -ldl -fno-stack-protector
$ ./server