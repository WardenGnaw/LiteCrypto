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
#define UDP_HEADER_SIZE 4
#define IPV4_AND_UDP_HEADER_SIZE (IPV4_HEADER_SIZE + UDP_HEADER_SIZE)
#define crypto_onetimeauth_key_and_bytes (crypto_onetimeauth_KEYBYTES + crypto_onetimeauth_BYTES)

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;


/*
 * 
 */
u64 packet_sign(u8 *key, u8 **data, u64 size);

/*
 * 
 */
u64 packet_verify(u8 *key, u8 **message, u64 message_length);

/*
 * 
 */
u64 packet_secret_box(u8 **data, u64 size);

/*
 * 
 */
u64 packet_open_secret_box(u8 **data, u64 size);
#endif
