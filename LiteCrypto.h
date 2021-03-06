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

#define SIGN_KEYBYTES crypto_auth_KEYBYTES      //tweetnacl: 32
#define SIGN_BYTES crypto_auth_BYTES            //tweetnacl: 32
#define NONCE_BYTES crypto_stream_NONCEBYTES    //tweetnacl: 24
#define ENCRYPT_KEYBYTES crypto_stream_KEYBYTES //tweetnacl: 32
#define SIGN_AND_NONCE_BYTES (SIGN_BYTES + NONCE_BYTES)

#define KEY_SIZE ENCRYPT_KEYBYTES
#define SALT_SIZE 16

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;

/*
 * Deterministically derive a KEY_SIZE length key from a variable size
 *  input_key and salt (random bytes)
 * Expects: 
 *  output_key to have enough space for KEY_SIZE
 *  salt to be of length SALT_SIZE
 *
 * Returns:
 *  KEY_SIZE on success, -1 on failure
 */
extern i64 derive_key(u8 *output_key, u8 *input_key, i64 input_size, u8 *salt);

/*
 * Authenticate IPv4 + UDP packet by HMAC-SHA512-256.
 * Expects:
 *  signed_data to have enough space for (size + SIGN_BYTES), it will fill that size.
 *  key to be SIGN_KEYBYTES long
 *
 * Returns: size of signed_data
 */
extern i64 packet_sign(u8 *signed_data, u8 *key, u8 *data, i64 size);

/*
 * Verify authentication of a signed IPv4 + UDP packet by HMAC-SHA512-256.
 * Expects:
 *  output to have enough space for (signed_size - SIGN_BYTES), it will fill that size.
 *  key to be SIGN_KEYBYTES long
 *
 * Returns:
 *  size of output if verified, -1 if not.
 */
extern i64 packet_verify(u8 *output, u8 *key, u8 *signed_data, i64 signed_size);

/*
 * Encrypts data of a IPv4 + UDP packet by xsalsa20 stream cipher.
 * Expects:
 *  output to have enough space for (size + NONCE_BYTES), it will fill that size.
 *  key to be ENCRYPT_KEYBYTES long
 *
 * Returns: size of output
 */
extern i64 packet_encrypt(u8 *output, u8 *key, u8 *data, i64 size);

/*
 * Decrypts data of an encrypted IPv4 + UDP packet by xsalsa20 stream cipher.
 * Expects:
 *  output to have enough space for (size - NONCE_BYTES), it will fill that size.
 *  key to be ENCRYPT_KEYBYTES long
 *
 * Returns: size of output
 */
extern i64 packet_decrypt(u8 *output, u8 *key, u8 *data, i64 size);

/*
 * Encrypts data of a IPv4 + UDP packet by xsalsa20 stream cipher and
 * authenticate IPv4 + UDP packet by HMAC-SHA512-256.
 *
 * Expects:
 *  output to have enough space for (size + NONCE_BYTES + SIGN_BYTES), it will fill that size.
 *  key to be ENCRYPT_KEYBYTES long
 *
 * Returns: size of signed_data on success or -1 on failure
 */
extern i64 packet_encrypt_sign(u8 *signed_data, u8 *key, u8 *data, i64 size);

/*
 * Verify IPv4 + UDP packet by HMAC-SHA512-256, if verified then
 *  decrypts data of a IPv4 + UDP packet by xsalsa20 stream cipher.
 *
 * Expects:
 *  output to have enough space for (size - NONCE_BYTES - SIGN_BYTES), it will fill that size.
 *  key to be ENCRYPT_KEYBYTES long
 *
 * Returns: size of output on success or -1 on failure
 */
extern i64 packet_verify_decrypt(u8 *output, u8 *key, u8 *signed_data, i64 signed_size);

#endif
