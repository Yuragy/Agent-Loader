#ifndef OBFUSCATE_H
#define OBFUSCATE_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static inline uint64_t generate_key(uint64_t seed) {
    uint64_t key = seed;
    key ^= (key >> 33);
    key *= 0xff51afd7ed558ccdULL;
    key ^= (key >> 33);
    key *= 0xc4ceb9fe1a85ec53ULL;
    key ^= (key >> 33);
    key |= 0x0101010101010101ULL;
    return key;
}

static inline void cipher(char *data, size_t size, uint64_t key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= (char)((key >> ((i % 8) * 8)) & 0xFF);
    }
}

typedef struct {
    char *data;      
    size_t size;     
    uint64_t key;    
    int encrypted;   
} obfuscated_data_t;

static inline obfuscated_data_t *obfuscate_create(const char *literal, uint64_t key) {
    obfuscated_data_t *obs = (obfuscated_data_t *)malloc(sizeof(obfuscated_data_t));
    if (!obs) return NULL;
    obs->size = 0;
    while (literal[obs->size] != '\0') {
        obs->size++;
    }
    obs->size++;
    obs->data = (char *)malloc(obs->size);
    if (!obs->data) {
        free(obs);
        return NULL;
    }
    for (size_t i = 0; i < obs->size; i++) {
        obs->data[i] = literal[i];
    }
    obs->key = key;
    cipher(obs->data, obs->size, obs->key);
    obs->encrypted = 1;
    return obs;
}

static inline void obfuscate_decrypt(obfuscated_data_t *obs) {
    if (obs && obs->encrypted) {
        cipher(obs->data, obs->size, obs->key);
        obs->encrypted = 0;
    }
}

static inline void obfuscate_encrypt(obfuscated_data_t *obs) {
    if (obs && !obs->encrypted) {
        cipher(obs->data, obs->size, obs->key);
        obs->encrypted = 1;
    }
}

static inline char *obfuscate_get(obfuscated_data_t *obs) {
    if (obs) {
        if (obs->encrypted) {
            obfuscate_decrypt(obs);
        }
        return obs->data;
    }
    return NULL;
}

static inline void obfuscate_free(obfuscated_data_t *obs) {
    if (obs) {
        if (obs->data) {
            for (size_t i = 0; i < obs->size; i++) {
                obs->data[i] = 0;
            }
            free(obs->data);
        }
        free(obs);
    }
}

#ifdef _MSC_VER
#define AY_CAT(X,Y) AY_CAT2(X,Y)
#define AY_CAT2(X,Y) X##Y
#define AY_LINE (int)(AY_CAT(__LINE__,U))
#else
#define AY_LINE __LINE__
#endif

#ifndef AY_OBFUSCATE_DEFAULT_KEY
#define AY_OBFUSCATE_DEFAULT_KEY (generate_key((uint64_t)AY_LINE))
#endif

#define AY_OBFUSCATE(data) obfuscate_create(data, AY_OBFUSCATE_DEFAULT_KEY)

#endif // OBFUSCATE_H
