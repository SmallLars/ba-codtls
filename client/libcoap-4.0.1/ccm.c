#include "ccm.h"

#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#define M 8 // Element von {4, 6, 8, 10, 12, 14, 16} -> Länge des Authentication Fields
#define L 7 // Element von {2, 3, 4, 5, 6, 7, 8} -> Länge des Längenfeldes
#define N (15-L) // Es Ergibt sich die Länge der Nonce
#define SETNONCE(a) memcpy(a, "ABCDEFGH", N)

#define min(x,y) ((x)<(y)?(x):(y))

void printBytes(uint8_t *b, size_t c) {
  size_t i;
  for (i = 0; i < c; i++) {
    if (i > 0 && i % 4 == 0) printf(" ");
    printf("%02X", b[i]);
  }
}

void getAuthCode(uint8_t *out, uint8_t *key, const uint8_t *msg, size_t msg_len) {
  // b_0 generieren
  uint8_t b_0[16];
  memset(b_0, 0, 16);
  // Flags
  b_0[0] = (8 * ((M-2)/2)) + (L - 1);
  // Nonce
  SETNONCE(b_0 + 1);
  // Länge der Nachricht
  size_t new_len = htonl(msg_len);
  memcpy(b_0 + 12, &new_len, 4);

  uint8_t cypher[16];
  int32_t cypherLen;

  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), key, NULL);
  EVP_CIPHER_CTX_set_padding(&ctx, 0);

  EVP_EncryptUpdate(&ctx, cypher, &cypherLen, b_0, 16);

  size_t i;
  uint8_t plaintext[16];
  for (i = 0; i < msg_len; i+=16) {
      memset(plaintext, 0, 16);
      memcpy(plaintext, msg + i, min(16, msg_len - i));
      EVP_EncryptUpdate(&ctx, cypher, &cypherLen, plaintext, 16);
  }

  memcpy(out, cypher, M);
  EVP_CIPHER_CTX_cleanup(&ctx);
}

void crypt(CCMData_t *out, unsigned char *key, uint8_t *buf, size_t len) {
    // A_0 generieren
    uint8_t a[16];
    memset(a, 0, 16);
    // Flags
    a[0] = (L - 1);
    // Nonce
    SETNONCE(a + 1);

    uint8_t s[16];
    uint32_t length;

    EVP_CIPHER_CTX aesctx;
    EVP_EncryptInit(&aesctx, EVP_aes_128_ecb(), key, 0);
    EVP_CIPHER_CTX_set_padding(&aesctx, 0);

    size_t i;

    // A-Block verschlüssel und mit dem bereits berechneten MAC X-Oren
    EVP_EncryptUpdate(&aesctx, s, &length, a, 16);
    for (i = 0; i < M; i++) out->ccm_ciphered[len + i] = out->ccm_ciphered[len + i] ^ s[i];

    for (i = 0; i < len; i+=16) {
        // a modifizieren
        length = htonl((i/16)+1);
        memcpy(a + 12, &length, 4);
        EVP_EncryptUpdate(&aesctx, s, &length, a, 16);
        size_t j;
        size_t blocklen = min(16, len - i);
        for (j = 0; j < blocklen; j++) out->ccm_ciphered[i+j] = buf[i+j] ^ s[j];
    }

    EVP_CIPHER_CTX_cleanup(&aesctx);
}

void encrypt(CCMData_t *c, uint8_t *key, uint8_t *buf, size_t len) {
  getAuthCode(c->ccm_ciphered + len, key, buf, len);
  crypt(c, key, buf, len);
}

/*
void crypt(unsigned char *out, unsigned char *key, std::vector<unsigned char *> &blocks);
unsigned char getBlock(unsigned char *&target, unsigned char size);
void putBlocks(std::vector<unsigned char *> *blocks, size_t msg_len);

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Fehler! Erwartete Parameter:\n   myccm -e schlüssel\n   myccm -d schlüssel\n");
        exit(EXIT_FAILURE);
    }

    bool encrypt = (memcmp(argv[1], "-e", 2) == 0 ? true : false);
    bool decrypt = (memcmp(argv[1], "-d", 2) == 0 ? true : false);

    if (!encrypt && !decrypt) {
        fprintf(stderr, "Fehler! Erwartete Parameter:\n   myccm -e schlüssel\n   myccm -d schlüssel\n");
        exit(EXIT_FAILURE);
    }

    unsigned char key[16];
    memset(key, 0, 16);
    size_t keyLen = strlen(argv[2]);
    memcpy(key, argv[2], keyLen > 16 ? 16 : keyLen);

    std::vector<unsigned char *> *blocks = new std::vector<unsigned char *>();

    unsigned int msg_len = 0;
    unsigned char b_len = 1;
    unsigned char *block;
    while ((b_len = getBlock(block, 16)) > 0) {
        blocks->push_back(block);
        msg_len += b_len;
        if (b_len != 16) break;
    }

    if (encrypt) {
        unsigned char t[M];
        getAuthCode(t, key, *blocks, msg_len);

        unsigned char s_0[M];
        crypt(s_0, key, *blocks);

        putBlocks(blocks, msg_len);

        for (size_t i = 0; i < M; i++) putchar(t[i] ^ s_0[i]);
    }
    if (decrypt) {
        char mac[M];
        int move = msg_len % 16;
        if (move > 0) {
            memcpy(mac, (*blocks)[blocks->size()-2] + move, M - move);
            memcpy(mac + M - move, blocks->back(), move);
        } else {
            memcpy(mac, blocks->back(), M);
        }
        delete[] blocks->back();
        blocks->pop_back();
        msg_len -= M;

        unsigned char s_0[M];
        crypt(s_0, key, *blocks);
        memset(blocks->back() + move, 0, M - move);

        putBlocks(blocks, msg_len);

        unsigned char t[M];
        getAuthCode(t, key, *blocks, msg_len);

        char newMac[M];
        for (size_t i = 0; i < M; i++) newMac[i] = t[i] ^ s_0[i];

        if (memcmp(mac, newMac, M) != 0)
            fprintf(stderr, "SICHERHEITSWARNUNG: Der Geheimtext wurde manipuliert oder der Schlüssel ist falsch!\n");
    }

    for (size_t b = 0; b < blocks->size(); b++) delete[] (*blocks)[b];
    delete blocks;

    exit(EXIT_SUCCESS);
}

unsigned char getBlock(unsigned char *&target, unsigned char size) {
    target = new unsigned char[size];
    memset(target, 0, size);

    int c = 0;
    unsigned char pos = 0;
    while (pos < size && (c = getchar()) != EOF) {
        target[pos] = (unsigned char) c;
        pos++;
    }

    if (pos == 0) delete[] target;

    return pos;
}

void putBlocks(std::vector<unsigned char *> *blocks, size_t msg_len) {
    size_t b, i;
    for (b = 0; b < blocks->size() - 1; b++)
        for (i = 0; i < 16; i++)
            putchar((*blocks)[b][i]);

       for (i = 0; i < msg_len % 16; i++)
        putchar((*blocks)[blocks->size()-1][i]);
}
*/
