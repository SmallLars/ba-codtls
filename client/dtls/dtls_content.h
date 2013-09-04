/* __DTLS_CONTENT_H__ */
#ifndef __DTLS_CONTENT_H__
#define __DTLS_CONTENT_H__

#include <stddef.h>
#include <netinet/in.h>

typedef enum {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3, 
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    change_cipher_spec = 32,
    alert = 33,
    // max = 63
} __attribute__ ((packed)) ContentType;

void *getContent(void *data, size_t len, ContentType type);

ContentType getContentType(void *data);

size_t getContentLen(void *data);

size_t getContentDataLen(void *data);

void *getContentData(void *data);

size_t makeContent(void *dst, ContentType type, void *data, size_t len);

#endif /* __DTLS_CONTENT_H__ */
