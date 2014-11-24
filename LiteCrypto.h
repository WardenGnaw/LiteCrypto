/*
 * Header File for LiteCrypto functions
 */
#ifndef LITECRYPTO_H
#define LITECRYPTO_H
#include "tweetnacl.h"
#include <stdint.h>

/*
 * 
 */
uint32_t packet_sign(uint8_t **data, uint32_t size);

/*
 * 
 */
uint32_t packet_verify(uint8_t **data, uint32_t size);

/*
 * 
 */
uint32_t packet_secret_box(uint8_t **data, uint32_t size);

/*
 * 
 */
uint32_t packet_open_secret_box(uint8_t **data, uint32_t size);
#endif
