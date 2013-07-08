#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

// Bloecke
// 0x18000 - 0x18FFF Random Zugriff Block 1.1
// 0x19000 - 0x19FFF Random Zugriff Block 1.2
// 0x1A000 - 0x1AFFF Random Zugriff Block 2.1
// 0x1B000 - 0x1BFFF Random Zugriff Block 2.2
// 0x1C000 - 0x1CFFF Fehlermeldungen
// 0x1D000 - 0x1DFFF Fehlermeldungen
// 0x1E000 - 0x1EFFF MAC, UUID, PIN, Name, Model
// 0x1F000 - 0x1FFFF Systemreserviert

#define RES_BLOCK_11     0x18000
#define RES_BLOCK_12     0x19000
#define RES_BLOCK_21     0x1A000
#define RES_BLOCK_22     0x1B000
#define LEN_BLOCK_XX     0x1000
#define LEN_BLOCK        0x01

//Read Only Vars
#define RES_MAC          0x1E000
#define LEN_MAC          0x08
#define RES_UUID         0x1E008
#define LEN_UUID         0x10
#define RES_PIN          0x1E018
#define LEN_PIN          0x08
#define RES_NAME         0x1E020
#define LEN_NAME         0x0F
#define RES_MODEL        0x1E040
#define LEN_MODEL        0x0E

#define RES_B_ERR_05     0x1C000
#define LEN_B_ERR_05     73
#define RES_B_ERR_04     0x1C080
#define LEN_B_ERR_04     51
#define RES_B_ERR_03     0x1C100
#define LEN_B_ERR_03     52
#define RES_B_ERR_02     0x1C180
#define LEN_B_ERR_02     31
#define RES_B_ERR_01     0x1C200
#define LEN_B_ERR_01     61

int main(int nArgs, char **argv) {
    if (nArgs < 2 || nArgs > 3) {
        fprintf(stderr, "Parameter erforderlich: ./blaster <MAC-Endnummer> [-t]\nBei -t wird Standard-PIN 11111111 gesetzt.\n");
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

// Ursprüngliche Länge der Firmware setzen im little Endian Encoding
    unsigned int length = i - 8;
    memcpy(output + 4, (const void *) &length, 4);
    fprintf(stderr, "Länge: %u = 0x%02x%02x%02x%02x\n", length, output[7], output[6], output[5], output[4]);

    for (; i < 0x1F000; i++) output[i] = 0xFF;

// UUID setzen
    unsigned char uuid_bin[16];
    uuid_generate(uuid_bin);
    for (i = 0; i < 16; i++) output[RES_UUID + i] = uuid_bin[i];

    char uuid[37];
    uuid_unparse(uuid_bin, uuid);
    fprintf(stderr, "UUID: %s\n", uuid);

// Pin setzen
    unsigned char pin[8] = "11111111";
    if (nArgs == 2) {
        FILE *fd = fopen("/dev/urandom","r");
        if (fd == NULL) {
            perror("Öffnen von /dev/urandom fehlgeschlagen: ");
            return -1;
        }
        char *letter = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-";
        for (i = 0; i < 8; i++) {
            int c;
            while ((c = fgetc(fd)) == EOF);
            pin[i] = letter[((unsigned char) c) % 64];
        }
        if (fclose(fd) == -1) printf("Fehler beim Schließen von /dev/urandom\n");
        pin[8] = 0;
    }
    for (i = 0; i < 8; i++) {
        output[RES_PIN + i] = pin[i];
    }
    fprintf(stderr, "PIN: %c%c%c%c%c%c%c%c\n", pin[0], pin[1], pin[2], pin[3], pin[4], pin[5], pin[6], pin[7]);

// Name setzen
    char *name = "DTLS-Testserver";
    memcpy(output + RES_NAME, name, LEN_NAME);
    fprintf(stderr, "Name: %s\n", name);

// Model setzen
    char *model = "LARS-ABCD-1234";
    memcpy(output + RES_MODEL, model, LEN_MODEL);
    fprintf(stderr, "Model: %s\n", model);

// Blöcke für Random Zugriff initialisieren
    output[RES_BLOCK_11] = 1;
    output[RES_BLOCK_21] = 1;

// Mac setzen
    unsigned char mac[8] = {0x62, 0xB1, 0x60, 0xB1, 0x60, 0xB1, 0x00, (unsigned char) m};
    for (i = 0; i < 8; i++) output[RES_MAC + i] = mac[i];
    fprintf(stderr, "MAC-Adresse: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7]);

// Fehlermeldungen setzen
    char *buffer;
    buffer = "Ohne eine korrekte PIN-Uebertragung kann der PIN nicht ausgelesen werden.";
    memcpy(output + RES_B_ERR_05, buffer, LEN_B_ERR_05);
    buffer = "Der PIN wurde schon uebertragen. Eingabe ignoriert.";
    memcpy(output + RES_B_ERR_04, buffer, LEN_B_ERR_04);
    buffer = "Ohne gedrückten Knopf wird der Pin nicht angenommen.";
    memcpy(output + RES_B_ERR_03, buffer, LEN_B_ERR_03);
    buffer = "Der PIN passt nicht zum Geraet.";
    memcpy(output + RES_B_ERR_02, buffer, LEN_B_ERR_02);
    buffer = "Der erste Teil des Handshakes wurde noch nicht durchgefuehrt.";
    memcpy(output + RES_B_ERR_01, buffer, LEN_B_ERR_01);

// Ausgeben
    for (i = 4; i < 0x1F000; i++) putchar(output[i]);

    return 0;
}
