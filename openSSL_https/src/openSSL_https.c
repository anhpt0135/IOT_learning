/*
 ============================================================================
 Name        : openSSL_https.c
 Author      : AnhPT
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/ssl.h"
int main(void) {
	puts("!!!OpenSSL_https!!!"); /* prints !!!OpenSSL_https!!! */
	printf("OpenSSL version: %s\n", OpenSSL_version(SSLEAY_VERSION));

	return EXIT_SUCCESS;
}
