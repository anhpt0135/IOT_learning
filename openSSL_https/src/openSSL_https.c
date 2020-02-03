/*
 ============================================================================
 Name        : openSSL_https.c
 Author      : AnhPT
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define MAX_BUFF 1024

void openssl_init(void){
	SSL_library_init();//khoi tao the OpenSSL library
	OpenSSL_add_all_algorithms();// load tat ca cac algorithms san co, co the chi can load nhung thuat toan can thiet thoi
	SSL_load_error_strings();//de de dang doc cac error messages khi gap loi
}

int main(int argc, char *argv[]) {
	const char *server_address = argv[1];//chinh la hostname trong sach
	const char *port = argv[2];
	struct sockaddr_in serv_addr;
	struct addrinfo hints;
	struct addrinfo *peer_address;
	int sock = 0;

	if(getaddrinfo(server_address, port, &hints, &peer_address)){
		printf("getaddinfo() failed\n");
		return -1;
	}

	puts("!!!OpenSSL_https!!!"); /* prints !!!OpenSSL_https!!! */
	printf("OpenSSL version: %s\n", OpenSSL_version(SSLEAY_VERSION));

	memset(&hints, 0, sizeof(hints));
	//1. Initialize OPENSSL
	openssl_init();
	//tao mot SSL context(mot SSL ctx object) de luu cac setting ban dau
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if(!ctx) {
		fprintf(stderr, "SSL_CTX_new() failed.\n");
	}
	//2. Tao mot TCP connection (TCP socket)
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){// Thong tin tu peer_addr co the dem vao day socket(peer_address->ai_family,peer_address->ai_socktype, peer_address->ai_protocol);
		printf("\n Socket creation error\n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(atoi(port));

	if(inet_pton(AF_INET, server_address, &serv_addr.sin_addr) < 0){ // chuyen doi chuoi server_address thanh dia chi ip
		printf("\n Invalid address\n");
		return -1;
	}

	if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 ){
		printf("\n Connection Failed\n");
		return 1;
	}
	//3. Sau khi TCP connection duoc tao ra thanh cong, tien hanh khoi tao mot TLS connection
	SSL *ssl = SSL_new(ctx);
	if(!ctx){
		printf("SSL_new() failed \n");
		return 1;
	}

	if(!SSL_set_tlsext_host_name(ssl, server_address)){
		printf("SSL_set_tlsext_host_name() failed\n");
		return 1;
	}

	SSL_set_fd(ssl, sock);
	if(SSL_connect(ssl) == -1){
		printf("SSL_connect() failed\n");
		return 1;
	}


	return EXIT_SUCCESS;
}
