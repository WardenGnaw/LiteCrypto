/*
 * Header File for LiteCrypto functions
 */
#ifndef LITECRYPTO_H
#define LITECRYPTO_H
#include "tweetnacl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#define IPV4_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define IPV4_AND_UDP_HEADER_SIZE (IPV4_HEADER_SIZE + UDP_HEADER_SIZE)
#define crypto_onetimeauth_key_and_bytes (crypto_onetimeauth_KEYBYTES + crypto_onetimeauth_BYTES)

#define SIGN_KEYBYTES crypto_auth_KEYBYTES  //tweetnacl: 32
#define SIGN_BYTES crypto_auth_BYTES        //tweetnacl: 32
#define KEY_SIZE crypto_hash_BYTES          //tweetnacl: 64

#define KEY_DERIV_ITER 5000
#define SALT_SIZE 16

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;

/*
 * Deterministically derive a 32-byte key from a variable size input_key and salt (random bytes)
 * Expects: 
 *  output_key to have enough space for KEY_SIZE
 *  salt to be of length SALT_SIZE
 */
u64 derive_key(u8 *output_key, u8 *input_key, u64 input_size, u8 *salt);

/*
 * Authenticate IPv4 + UDP packet by HMAC-SHA512-256.
 * Expects:
 *  signed_data to have enough space for (size + SIGN_BYTES), it will fill that size.
 *  key to be SIGN_KEYBYTES long
 *
 * Returns: size of signed_data
 */
u64 packet_sign(u8 *signed_data, u8 *key, u8 *data, u64 size);

/*
 * Verify authentication of a signed packet
 * Expects:
 *  output to have enough space for (signed_size - SIGN_BYTES), it will fill that size.
 *  key to be SIGN_KEYBYTES long
 *
 * Returns:
 *  0 if verified, -1 if not.
 */
u64 packet_verify(u8 *output, u8 *key, u8 *signed_data, u64 signed_size);

/*
 * 
 */
u64 packet_secret_box(u8 **data, u64 size);

/*
 * 
 */
u64 packet_open_secret_box(u8 **data, u64 size);
#endif
