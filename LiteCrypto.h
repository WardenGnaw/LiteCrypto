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
#define IPV4_AND_UDP_HEADER_SIZE 24
#define crypto_onetimeauth_key_and_bytes (crypto_onetimeauth_KEYBYTES + crypto_onetimeauth_BYTES)

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
/*
typedef struct  __attribute__ ((__packed__)) {
   u8 ipv4_header[IPV4_HEADER_SIZE];
   u8 udp_header[UDP_HEADER_SIZE];
   u8 key[crypto_onetimeauth_KEYBYTES]; // defined in tweetnacl.h as 32
   u8 auth[crypto_onetimeauth_BYTES];   // defined in tweetnacl.h as 16
}  __attribute__ ((__packed__)) packet_header_struct;
*/
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
