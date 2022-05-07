#define BLOCK_SIZE_IN_BYTES 16
#define KEY_SIZE_IN_BYTES 32
#define ENCRYPTION_MODE "-e"
#define DECRYPTION_MODE "-d"
#define C1 0xA09E667F3BCC908B
#define C2 0xB67AE8584CAA73B2
#define C3 0xC6EF372FE94F82BE
#define C4 0x54FF53A5F1D36F1C
#define C5 0x10E527FADE682D1D
#define C6 0xB05688C2B3E6C1FD

const unsigned char SBOX[256] = {
        0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5,
        0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
        0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21,
        0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
        0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce,
        0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
        0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d,
        0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
        0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d,
        0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
        0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05,
        0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
        0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c,
        0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
        0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91,
        0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
        0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97,
        0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
        0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb,
        0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
        0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33,
        0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
        0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b,
        0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
        0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e,
        0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
        0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba,
        0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
        0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a,
        0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
        0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1,
        0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e};

typedef struct{
    uint64_t kw[4];
    uint64_t ke[6];
    uint64_t k[24];
}subkeys;

uint8_t SBOX1(uint8_t index) {
    return SBOX[index];
}

uint8_t SBOX2(uint8_t index) {
    return (SBOX[index] >> 7 | SBOX[index] << 1);
}

uint8_t SBOX3(uint8_t index) {
    return (SBOX[index] >> 1 | SBOX[index] << 7);
}

uint8_t SBOX4(uint8_t index) {
    return SBOX[(index << 1 | index >> 7) & 0xff];
}

void swap(uint64_t *first, uint64_t *second) {
    uint64_t tmp = *first;
    *first = *second;
    *second = tmp;
}

uint64_t F(uint64_t F_IN, uint64_t KE) {
    uint64_t F_OUT = 0;
    uint8_t t[8], y[8];

    uint64_t x = F_IN ^ KE;

    t[0] = SBOX1(x >> 56);
    t[1] = SBOX2(x >> 48);
    t[2] = SBOX3(x >> 40);
    t[3] = SBOX4(x >> 32);
    t[4] = SBOX2(x >> 24);
    t[5] = SBOX3(x >> 16);
    t[6] = SBOX4(x >> 8);
    t[7] = SBOX1(x);

    y[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
    y[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
    y[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
    y[3] = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
    y[4] = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
    y[5] = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
    y[6] = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
    y[7] = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];

    for(int i = 0; i < 7; i++)
        F_OUT = (F_OUT | y[i]) << 8;
    F_OUT |= y[7];
    return F_OUT;
}

uint64_t FL(uint64_t FL_IN, uint64_t KE) {
    uint64_t FL_OUT = 0;
    uint32_t k1, k2, x1, x2;
    x1 = FL_IN >> 32;
    x2 = FL_IN & 0xffffffff;
    k1 = KE >> 32;
    k2 = KE & 0xffffffff;
    x2 = x2 ^ ((x1 & k1) >> 31 | (x1 & k1) << 1);
    x1 = x1 ^ (x2 | k2);

    FL_OUT = ((FL_OUT | x1) << 32) | x2;
    return FL_OUT;
}

uint64_t FLINV(uint64_t FLINV_IN, uint64_t key) {
    uint64_t FLINV_OUT = 0;
    uint32_t k1, k2, y1, y2;
    y1 = FLINV_IN >> 32;
    y2 = FLINV_IN & 0xffffffff;
    k1 = key >> 32;
    k2 = key & 0xffffffff;
    y1 = y1 ^ (y2 | k2);
    y2 = y2 ^ ((y1 & k1) >> 31 | (y1 & k1) << 1);

    FLINV_OUT = ((FLINV_OUT | y1) << 32) | y2;
    return FLINV_OUT;
}

void swap_keys(subkeys *ptr) {
    for(int i = 0; i < 2; i++)
        swap(&ptr->kw[i], &ptr->kw[i + 2]);
    for(int i = 0; i < 3; i++)
        swap(&ptr->ke[i], &ptr->ke[5 - i]);
    for(int i = 0; i < 12; i++)
        swap(&ptr->k[i], &ptr->k[23 - i]);
}

void keygen(subkeys *ptr, const uint8_t *key, const char *mode) {
    uint64_t KL[2] = {}, KR[2] = {}, KA[2] = {}, KB[2] = {}, D1, D2;

    int i;
    for(i = 0; i < 7; i++) {
        KL[0] = (KL[0] | key[i]) << 8;
        KL[1] = (KL[1] | key[i + 8]) << 8;
        KR[0] = (KR[0] | key[i + 16]) << 8;
        KR[1] = (KR[1] | key[i + 24]) << 8;
    }
    KL[0] |= key[i];
    KL[1] |= key[i + 8];
    KR[0] |= key[i + 16];
    KR[1] |= key[i + 24];

    D1 = KL[0] ^ KR[0];
    D2 = KL[1] ^ KR[1];
    D2 = D2 ^ F(D1, C1);
    D1 = D1 ^ F(D2, C2);
    D1 = D1 ^ KL[0];
    D2 = D2 ^ KL[1];
    D2 = D2 ^ F(D1, C3);
    D1 = D1 ^ F(D2, C4);
    KA[0] = D1;
    KA[1] = D2;
    D1 = KA[0] ^ KR[0];
    D2 = KA[1] ^ KR[1];
    D2 = D2 ^ F(D1, C5);
    D1 = D1 ^ F(D2, C6);
    KB[0] = D1;
    KB[1] = D2;

    ptr->kw[0] = KL[0];
    ptr->kw[1] = KL[1];
    ptr->k[0] = KB[0];
    ptr->k[1] = KB[1];
    ptr->k[2] = KR[0] << 15 | KR[1] >> 49;
    ptr->k[3] = KR[1] << 15 | KR[0] >> 49;
    ptr->k[4] = KA[0] << 15 | KA[1] >> 49;
    ptr->k[5] = KA[1] << 15 | KA[0] >> 49;
    ptr->ke[0] = KR[0] << 30 | KR[1] >> 34;
    ptr->ke[1] = KR[1] << 30 | KR[0] >> 34;
    ptr->k[6] = KB[0] << 30 | KB[1] >> 34;
    ptr->k[7] = KB[1] << 30 | KB[0] >> 34;
    ptr->k[8] = KL[0] << 45 | KL[1] >> 19;
    ptr->k[9] = KL[1] << 45 | KL[0] >> 19;
    ptr->k[10] = KA[0] << 45 | KA[1] >> 19;
    ptr->k[11] = KA[1] << 45 | KA[0] >> 19;
    ptr->ke[2] = KL[0] << 60 | KL[1] >> 4;
    ptr->ke[3] = KL[1] << 60 | KL[0] >> 4;
    ptr->k[12] = KR[0] << 60 | KR[1] >> 4;
    ptr->k[13] = KR[1] << 60 | KR[0] >> 4;
    ptr->k[14] = KB[0] << 60 | KB[1] >> 4;
    ptr->k[15] = KB[1] << 60 | KB[0] >> 4;
    ptr->k[16] = KL[1] << 13 | KL[0] >> 51;
    ptr->k[17] = KL[0] << 13 | KL[1] >> 51;
    ptr->ke[4] = KA[1] << 13 | KA[0] >> 51;
    ptr->ke[5] = KA[0] << 13 | KA[1] >> 51;
    ptr->k[18] = KR[1] << 30 | KR[0] >> 34;
    ptr->k[19] = KR[0] << 30 | KR[1] >> 34;
    ptr->k[20] = KA[1] << 30 | KA[0] >> 34;
    ptr->k[21] = KA[0] << 30 | KA[1] >> 34;
    ptr->k[22] = KL[1] << 47 | KL[0] >> 17;
    ptr->k[23] = KL[0] << 47 | KL[1] >> 17;
    ptr->kw[2] = KB[1] << 47 | KB[0] >> 17;
    ptr->kw[3] = KB[0] << 47 | KB[1] >> 17;

    if(strcmp(mode, DECRYPTION_MODE) == 0)
        swap_keys(ptr);
}

void encryption(const uint8_t *plaintext, uint8_t *ciphertext, subkeys *ptr) {
    uint64_t D1 = 0, D2 = 0;
    for(int i = 0; i < 7; i++) {
        D1 = (D1 | plaintext[i]) << 8;
        D2 = (D2 | plaintext[i + 8]) << 8;
    }
    D1 |= plaintext[7];
    D2 |= plaintext[15];

    D1 = D1 ^ ptr->kw[0];
    D2 = D2 ^ ptr->kw[1];
    for(int i = 0, j = 0; i < 24;) {
        if(i % 6 == 0 && i > 0) {
            D1 = FL(D1, ptr->ke[j++]);
            D2 = FLINV(D2, ptr->ke[j++]);
        }
        D2 = D2 ^ F(D1, ptr->k[i++]);
        D1 = D1 ^ F(D2, ptr->k[i++]);
    }
    D2 = D2 ^ ptr->kw[2];
    D1 = D1 ^ ptr->kw[3];

    for(int i = 0; i < 8; i++) {
        ciphertext[i] = (D2 >> (7 - i) * 8) & 0xff;
        ciphertext[i + 8] = (D1 >> (7 - i) * 8) & 0xff;
    }
}