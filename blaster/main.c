#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <time.h>

// Blöcke
// 0x18000 - 0x18FFF Random Zugriff Block 1.1
// 0x19000 - 0x19FFF Random Zugriff Block 1.2
// 0x1A000 - 0x1AFFF Random Zugriff Block 2.1
// 0x1B000 - 0x1BFFF Random Zugriff Block 2.2
// 0x1C000 - 0x1CFFF Stack ohne Pop-Funktion
// 0x1D000 - 0x1DFFF Fehlermeldungen
// 0x1E000 - 0x1EFFF MAC, UUID, PSK, ECC-Base-Point, Name, Model, Flashzeitpunkt
// 0x1F000 - 0x1FFFF Systemreserviert

#define RES_BLOCK_11     0x18000
#define RES_BLOCK_12     0x19000
#define RES_BLOCK_21     0x1A000
#define RES_BLOCK_22     0x1B000
#define LEN_BLOCK_XX     0x1000
#define LEN_BLOCK        0x01

//Read Only Fehlermeldungen
#define RES_B_ERR_05     0x1D000
#define LEN_B_ERR_05     73
#define RES_B_ERR_04     0x1D080
#define LEN_B_ERR_04     51
#define RES_B_ERR_03     0x1D100
#define LEN_B_ERR_03     52
#define RES_B_ERR_02     0x1D180
#define LEN_B_ERR_02     31
#define RES_B_ERR_01     0x1D200
#define LEN_B_ERR_01     61

//Read Only Vars
#define RES_MAC          0x1E000
#define LEN_MAC          0x08
#define RES_UUID         0x1E008
#define LEN_UUID         0x10
#define RES_PSK          0x1E018
#define LEN_PSK          0x10
#define RES_ECC_BASE_X   0x1E028
#define LEN_ECC_BASE_X   0x20
#define RES_ECC_BASE_Y   0x1E048
#define LEN_ECC_BASE_Y   0x20
#define RES_NAME         0x1E068
#define LEN_NAME         0x0F
#define RES_MODEL        0x1E088
#define LEN_MODEL        0x0E
#define RES_FLASHTIME    0x1E0A8
#define LEN_FLASHTIME    0x04

// ----------------------------------------------------------------------------

int main(int nArgs, char **argv) {
    if (nArgs < 2 || nArgs > 3) {
        fprintf(stderr, "Parameter erforderlich: ./blaster <MAC-Endnummer> [-t]\n");
        fprintf(stderr, "Bei -t wird Standard-PSK 1111111111111111 gesetzt.\n");
        return -1;
    }

    char *end;
    long int m = strtol(argv[1], &end, 16);
    if (*end != '\0' || m < 1 || m > 40) {
        fprintf(stderr, "Es sind nur MAC-Endnummern von 1 bis 28 zulässig.\n");
        return -1;
    }

    if (nArgs == 3 && strcmp(argv[2], "-t") != 0) {
        fprintf(stderr, "Ungültiger 2. Parameter.\n");
        return -1;
    }

    unsigned char output[131072];

    unsigned int c, i;
    for (i = 8; (c = getchar()) != EOF; i++) {
        output[i] = (unsigned char) c;
    }

// Ursprüngliche Länge der Firmware setzen im little Endian Encoding ---------
    unsigned int length = i - 8;
    memcpy(output + 4, (const void *) &length, 4);
    fprintf(stderr, "Länge: %u = 0x%08x\n", length, length);

// Rest zunächst mit 0xFF füllen (gleicher wert wie nach Löschen)
    for (; i < 0x1F000; i++) output[i] = 0xFF;

// Blöcke für Random Zugriff initialisieren -----------------------------------
    output[RES_BLOCK_11] = 1;
    output[RES_BLOCK_21] = 1;

// Fehlermeldungen setzen -----------------------------------------------------
    char *buffer;
    buffer = "Ohne eine korrekte PSK-Uebertragung kann der PSK nicht ausgelesen werden.";
    memcpy(output + RES_B_ERR_05, buffer, LEN_B_ERR_05);
    buffer = "Der PSK wurde schon uebertragen. Eingabe ignoriert.";
    memcpy(output + RES_B_ERR_04, buffer, LEN_B_ERR_04);
    buffer = "Ohne gedrückten Knopf wird der Pin nicht angenommen.";
    memcpy(output + RES_B_ERR_03, buffer, LEN_B_ERR_03);
    buffer = "Der PSK passt nicht zum Geraet.";
    memcpy(output + RES_B_ERR_02, buffer, LEN_B_ERR_02);
    buffer = "Der erste Teil des Handshakes wurde noch nicht durchgefuehrt.";
    memcpy(output + RES_B_ERR_01, buffer, LEN_B_ERR_01);

// Mac setzen -----------------------------------------------------------------
    unsigned char mac[8] = {0x62, 0xB1, 0x60, 0xB1, 0x60, 0xB1, 0x00, (unsigned char) m};
    for (i = 0; i < 8; i++) output[RES_MAC + i] = mac[i];
    fprintf(stderr, "MAC-Adresse: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]);

// UUID setzen ----------------------------------------------------------------
    unsigned char uuid_bin[16];
    uuid_generate(uuid_bin);
    for (i = 0; i < 16; i++) output[RES_UUID + i] = uuid_bin[i];

    char uuid[37];
    uuid_unparse(uuid_bin, uuid);
    fprintf(stderr, "UUID: %s\n", uuid);

// PSK setzen -----------------------------------------------------------------
    unsigned char psk[16] = "1111111111111111";
    if (nArgs == 2) {
        FILE *fd = fopen("/dev/urandom","r");
        if (fd == NULL) {
            perror("Öffnen von /dev/urandom fehlgeschlagen: ");
            return -1;
        }
        char *letter = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-";
        for (i = 0; i < 16; i++) {
            int c;
            while ((c = fgetc(fd)) == EOF);
            psk[i] = letter[((unsigned char) c) % 64];
        }
        if (fclose(fd) == -1) printf("Fehler beim Schließen von /dev/urandom\n");
    }
    for (i = 0; i < 16; i++) {
        output[RES_PSK + i] = psk[i];
    }
    fprintf(stderr, "PSK: %.*s\n", 16, psk);

// ECC Base Points setzen -----------------------------------------------------
    uint32_t *base_x = (uint32_t *) (output + RES_ECC_BASE_X);
    base_x[0] = 0xd898c296;
    base_x[1] = 0xf4a13945;
    base_x[2] = 0x2deb33a0;
    base_x[3] = 0x77037d81;
    base_x[4] = 0x63a440f2;
    base_x[5] = 0xf8bce6e5;
    base_x[6] = 0xe12c4247;
    base_x[7] = 0x6b17d1f2;

    uint32_t *base_y = (uint32_t *) (output + RES_ECC_BASE_Y);
    base_y[0] = 0x37bf51f5;
    base_y[1] = 0xcbb64068;
    base_y[2] = 0x6b315ece;
    base_y[3] = 0x2bce3357;
    base_y[4] = 0x7c0f9e16;
    base_y[5] = 0x8ee7eb4a;
    base_y[6] = 0xfe1a7f9b;
    base_y[7] = 0x4fe342e2;

// Name setzen ----------------------------------------------------------------
    char *name = "DTLS-Testserver";
    memcpy(output + RES_NAME, name, LEN_NAME);
    fprintf(stderr, "Name: %s\n", name);

// Model setzen ---------------------------------------------------------------
    char *model = "LARS-ABCD-1234";
    memcpy(output + RES_MODEL, model, LEN_MODEL);
    fprintf(stderr, "Model: %s\n", model);

// Zeit setzen ----------------------------------------------------------------
    time_t my_time = time(NULL) + 34;
    memcpy(output + RES_FLASHTIME, (void *) &my_time, LEN_FLASHTIME);
    struct tm *timeinfo = localtime(&my_time);
    char b[64];
    memset(b, 0, 64);
    strftime(b, 64, "Erzeugt am %d.%m.%Y um %H:%M:%S", timeinfo);
    fprintf(stderr, "%s\n", b);

// Ausgeben -------------------------------------------------------------------
    for (i = 4; i < 0x1F000; i++) putchar(output[i]);

    return 0;
}
