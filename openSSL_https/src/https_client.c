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

#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#define GETSOCKETERRNO() (errno)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "aes.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"

#define MAX_BUFF 1024
#define MAX_LENGTH_DATA 1024
#define IV "00000000000000000000000000000000"

char *key = "00001111222233334444555566667777";
char *iv = "00000000000000000000000000000000";
char *data = "EEEEFFFFGGGGHHHH";

unsigned char hex_sha512_key[128] = {0};
unsigned char sha512_key[64] = {0};
static unsigned char g_psk[512] = {0};

static int generate_random_number()
{
    int number = 0;
    time_t t;

    srand((unsigned)time(&t));
    number = rand() % (MAX_LENGTH_DATA * 2);

    return number;
}

static int unhexify(unsigned char *obuf, const char *ibuf)
{
    int len = 0;
    unsigned char c, c2;

    /* Warning: The length of the input stream have to be an even number */
    len = (strlen(ibuf) >> 1);

    while(*ibuf != 0)
    {
        c = *ibuf++;
        if(c >= '0' && c <= '9')
            c -= '0';
        else if(c >= 'a' && c <= 'f')
            c -= 'a' - 10;
        else if(c >= 'A' && c <= 'F')
            c -= 'A' - 10;

        c2 = *ibuf++;
        if(c2 >= '0' && c2 <= '9')
            c2 -= '0';
        else if(c2 >= 'a' && c2 <= 'f')
            c2 -= 'a' - 10;
        else if(c2 >= 'A' && c2 <= 'F')
            c2 -= 'A' - 10;

        *obuf++ = (c << 4) | c2;
    }

    return len;
}

static void hexify(unsigned char *obuf, const unsigned char *ibuf, int len)
{
    unsigned char l, h;

    while(len != 0)
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if(h < 10)
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if(l < 10)
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

static int generate_sha512(unsigned char *input, unsigned char *output)
{
    int ret = -1;
    mbedtls_md_context_t sha_ctx;

    if(input == NULL || output == NULL)
    {
        printf("Invalid NULL parameter");
        return -1;
    }

    if(input[0] == 0x00)
    {
        printf("Invalid empty string parameter");
        return -2;
    }

    ret = mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1);
    if(ret != 0)
    {
        printf("  ! mbedtls_md_setup() returned -0x%04x\n", -ret);
        mbedtls_md_free(&sha_ctx);
        return ret;
    }

    mbedtls_md_starts(&sha_ctx);
    mbedtls_md_update(&sha_ctx, input, strlen((char *)input));
    mbedtls_md_finish(&sha_ctx, output);
    mbedtls_md_free(&sha_ctx);

    return 0;
}

static int encrypt_aes128(char *hex_key_string, char *hex_iv_string,
                          unsigned char *src_string, unsigned char *dst_str, int *encrypt_size)
{
    unsigned char key_str[100];
    unsigned char iv_str[100];
    unsigned char size_data[20];

    mbedtls_aes_context ctx;
    int key_len, data_len, cbc_result;

    memset(key_str, 0x00, 100);
    memset(iv_str, 0x00, 100);
    memset(size_data, 0x00, 20);
    mbedtls_aes_init(&ctx);

    key_len = unhexify(key_str, hex_key_string);

    unhexify(iv_str, hex_iv_string);

    data_len = strlen((char *)src_string);

    if(data_len < 1)
    {
        printf("Error: encrypt_aes128() length data (%d)", data_len);
        mbedtls_aes_free(&ctx);
        return -1;
    }

    if(data_len % 16 != 0)
    {
        data_len = ((data_len / 16) + 1) * 16;
    }

    if(data_len > MAX_LENGTH_DATA)
    {
        printf("Error: encrypt_aes128() length data over (%d)", MAX_LENGTH_DATA);
        mbedtls_aes_free(&ctx);
        return -1;
    }

    sprintf((char *)size_data, "SSL%04d%04d", data_len, generate_random_number());

    mbedtls_aes_setkey_enc(&ctx, key_str, key_len * 8);

    cbc_result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, 16, iv_str, size_data, dst_str);
    if(cbc_result != 0)
    {
        printf("Error: encrypt_aes128() length data");
        mbedtls_aes_free(&ctx);
        return -2;
    }

    cbc_result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, data_len, iv_str, src_string, dst_str + 16);
    if(cbc_result != 0)
    {
        printf("Error: encrypt_aes128()");
    }

    mbedtls_aes_free(&ctx);
    *encrypt_size = (data_len + 16);
    return cbc_result;
}

static int decrypt_aes128(char *hex_key_string, char *hex_iv_string,
                          unsigned char *src_string, unsigned char *dst_str)
{
    int random_number;
    int key_len, data_len, cbc_result, ret = 0;
    unsigned char key_str[100];
    unsigned char iv_str[100];
    unsigned char size_data[20];
    mbedtls_aes_context ctx;

    if(strlen((char *)src_string) <= 0)
    {
        printf("Error decrypt_aes128 length data source");
        return -1;
    }

    memset(key_str, 0x00, 100);
    memset(iv_str, 0x00, 100);
    memset(size_data, 0x00, 20);
    mbedtls_aes_init(&ctx);

    key_len = unhexify(key_str, hex_key_string);

    unhexify(iv_str, hex_iv_string);

    mbedtls_aes_setkey_dec(&ctx, key_str, key_len * 8);

    cbc_result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, 16, iv_str, src_string, size_data);
    if(cbc_result != 0)
    {
        printf("Error: decrypt AES 128");
        mbedtls_aes_free(&ctx);
        return -1;
    }

    ret = sscanf((char *)size_data, "SSL%04d%04d", &data_len, &random_number);
    if(ret != 2)
    {
        printf("Error, cannot parse length data");
        mbedtls_aes_free(&ctx);
        return -1;
    }

    if(data_len % 16 != 0)
    {
        data_len = ((data_len / 16) + 1) * 16;
    }

    if(data_len > MAX_LENGTH_DATA)
    {
        printf("Error decrypt_aes128 length data over %d", MAX_LENGTH_DATA);
        mbedtls_aes_free(&ctx);
        return -2;
    }

    cbc_result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, data_len, iv_str, src_string + 16, dst_str);
    if(cbc_result != 0)
    {
        printf("Error decrypt_aes128\n");
    }

    mbedtls_aes_free(&ctx);
    return cbc_result;
}

static void init_psk(char *psk, size_t len, int mode)
{
	printf("inside init_psk()\n");
    char sPSK[64] = {0};
    char sIdentity[64] = {0};
    char response_pskidentity[128] ="saurjal0kkcsoduk864r68nv4m";
    char response_pdkkey[128] = "0C14CB721D6F02D7906AFD641D5BD489";

    if(psk == NULL)
    {
        printf("Error: NULL pointer");
        return;
    }

    memset(psk, 0x00, len);

    strcpy(sIdentity, response_pskidentity+16);
    strcpy(sPSK, response_pdkkey+17);
    printf("Use dynamic Identity & Pre-shared Key\n");
    snprintf(psk, len, "%s%s", sIdentity, sPSK);

    printf("PSK: %s\n", psk);

    return;
}

int main(int argc, char *argv[]) {

#if defined(_WIN32)
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        fprintf(stderr, "Failed to initialize.\n");
        return 1;
    }
#endif

/*    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new() failed.\n");
        return 1;
    }*/

    if (argc < 3) {
        fprintf(stderr, "usage: https_simple hostname port\n");
        return 1;
    }

    char *hostname = argv[1];
    char *port = argv[2];

    init_psk((char*)g_psk, sizeof(g_psk), 1);
    generate_sha512(g_psk, sha512_key);
    hexify(hex_sha512_key, sha512_key, 16);
    printf("[Hex] SHA512 Key:\r\n%s\n", hex_sha512_key);
    printf("Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *peer_address;
    if (getaddrinfo(hostname, port, &hints, &peer_address)) {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }

    printf("Remote address is: ");
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
            address_buffer, sizeof(address_buffer),
            service_buffer, sizeof(service_buffer),
            NI_NUMERICHOST);
    printf("%s %s\n", address_buffer, service_buffer);

    printf("Creating socket...\n");
    SOCKET server;
    server = socket(peer_address->ai_family,
            peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(server)) {
        fprintf(stderr, "socket() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }

    printf("Connecting...\n");
    if (connect(server,
                peer_address->ai_addr, peer_address->ai_addrlen)) {
        fprintf(stderr, "connect() failed. (%d)\n", GETSOCKETERRNO());
        exit(1);
    }
    freeaddrinfo(peer_address);

    printf("Connected.\n");

    char buffer[MAX_LENGTH_DATA]={0};
    unsigned char encrypt_buffer[MAX_LENGTH_DATA] = {0};
    unsigned char decrypt_buffer[MAX_LENGTH_DATA] = {0};
    int encrypt_size;

    sprintf(buffer, "GET /?action=command&command=get_udid HTTP/1.1\r\n");
    sprintf(buffer + strlen(buffer), "Host: %s:%s\r\n", hostname, port);
    //sprintf(buffer + strlen(buffer), "Connection: close\r\n");
    sprintf(buffer + strlen(buffer), "User-Agent: https_simple\r\n");
    sprintf(buffer + strlen(buffer), "\r\n");

    printf("before encrypt !.....");
    encrypt_aes128((char *)hex_sha512_key, IV, (unsigned char*)buffer, encrypt_buffer, &encrypt_size);
    printf("encrypt buffer = %s\n", encrypt_buffer);
    decrypt_aes128((char *)hex_sha512_key, IV, encrypt_buffer, decrypt_buffer);
    printf("decrypt the encrypt buffer : %s\n", decrypt_buffer);
    memset(decrypt_buffer, 0, sizeof(decrypt_buffer));
    printf("encrypt done!.....");
    //decrypt_aes128((char *)hex_sha512_key, IV, encrypt_buffer, decrypt_buffer);
    //SSL_write(ssl, buffer, strlen(buffer));
    int bytes_sent = send(server, buffer, strlen(buffer), 0);
    printf("Sent %d bytes.\n", bytes_sent);

    printf("Sent Headers:\n%s", buffer);

    while(1) {
        //int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    	int bytes_received = recv(server, buffer, MAX_LENGTH_DATA, 0);
            if (bytes_received < 1) {
                printf("\nConnection closed by peer.\n");
                break;
            }
            decrypt_aes128((char *)hex_sha512_key, IV, (unsigned char*)buffer, decrypt_buffer);
            printf("Received (%d bytes): '%.*s'\n",
                                bytes_received, bytes_received, decrypt_buffer);

    } //end while(1)

    printf("\nClosing socket...\n");
    //SSL_shutdown(ssl);
    CLOSESOCKET(server);
    //SSL_free(ssl);
/*    SSL_CTX_free(ctx);*/

#if defined(_WIN32)
    WSACleanup();
#endif

    printf("Finished.\n");
    return 0;
}
