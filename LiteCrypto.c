#include "LiteCrypto.h"

void randombytes(u8 *output,u64 size) {
   int fd = open("/dev/urandom", O_RDONLY);
   if (fd < 0) {
      return;
   }
   read(fd, output, size);
   close(fd);
}

#define KEY_DERIV_ITER 5000

i64 derive_key(u8 *output_key, u8 *input_key, i64 input_size, u8 *salt) {
   u8 *aux1, *aux2, *block1, *block2;
   u32 count, ndx;
   
   if (!output_key || !input_key || !salt || input_size <= 0) {
      return -1;
   }
   
   //crypto_hash_BYTES > SALT_SIZE, we have no INT(i) since we limit keySize
   //to 32 bytes which is less than 64 byte digest of crypto_hash
   aux1 = malloc(2*(input_size + crypto_hash_BYTES));
   if (!aux1) {
      return -1;
   }
   block1 = aux1 + input_size;
   aux2 = aux1 + input_size + crypto_hash_BYTES;
   block2 = aux2 + input_size;
   
   //initialize
   memcpy(aux1, input_key, input_size);
   memcpy(block1, salt, SALT_SIZE);
   memcpy(aux2, input_key, input_size);
   crypto_hash(block2, aux1, input_size + SALT_SIZE);
   memcpy(output_key, block2, KEY_SIZE);  //copy over U1 to key
   
   for (count = 0; count < KEY_DERIV_ITER; ++count) {
      crypto_hash(block1, aux2, input_size + crypto_hash_BYTES);
      //perform XOR with Ui on current U so far in key
      for (ndx = 0; ndx < KEY_SIZE; ++ndx) {
         output_key[ndx] = output_key[ndx] ^ block1[ndx];
      }
      crypto_hash(block2, aux1, input_size + crypto_hash_BYTES);
      for (ndx = 0; ndx < KEY_SIZE; ++ndx) {
         output_key[ndx] = output_key[ndx] ^ block2[ndx];
      }
   }
   
   memset(aux1, 0, 2*(input_size + crypto_hash_BYTES));  //clear our data
   free(aux1);
   return KEY_SIZE;
}

i64 packet_sign(u8 *signed_data, u8 *key, u8 *data, i64 size) {
   if (!signed_data || !key || !data || size < IPV4_AND_UDP_HEADER_SIZE) {
      return -1;
   }
   crypto_auth(signed_data + IPV4_AND_UDP_HEADER_SIZE, data, size, key);

   //copy original packet into new packet
   memcpy(signed_data, data, IPV4_AND_UDP_HEADER_SIZE);
   memcpy(signed_data + IPV4_AND_UDP_HEADER_SIZE + SIGN_BYTES, 
          data + IPV4_AND_UDP_HEADER_SIZE, 
          size - IPV4_AND_UDP_HEADER_SIZE);  

   return size + SIGN_BYTES;  // Return new size
}

i64 packet_verify(u8 *output, u8 *key, u8 *signed_data, i64 signed_size) {
   u8 authorization[SIGN_BYTES];
   
   if (!output || !key || !signed_data ||
       signed_size < (IPV4_AND_UDP_HEADER_SIZE + SIGN_BYTES)) {
      return -1;
   }
   
   //copy tag from signed packet
   memcpy(authorization, signed_data + IPV4_AND_UDP_HEADER_SIZE, SIGN_BYTES);
   
   //reconstruct original packet without tag
   memcpy(output, signed_data, IPV4_AND_UDP_HEADER_SIZE);
   memcpy(output + IPV4_AND_UDP_HEADER_SIZE,
          signed_data + IPV4_AND_UDP_HEADER_SIZE + SIGN_BYTES,
          signed_size - IPV4_AND_UDP_HEADER_SIZE - SIGN_BYTES);
   
   if(crypto_auth_verify(authorization, output, signed_size - SIGN_BYTES, key)) {
      return -1;
   }
   return signed_size - SIGN_BYTES;
}

i64 packet_encrypt(u8 *output, u8* key, u8 *data, i64 size) {
   u8 nonce[NONCE_BYTES];

   if (!output || !key || !data || size < IPV4_AND_UDP_HEADER_SIZE) {
      return -1;
   }

   randombytes(nonce, NONCE_BYTES);

   crypto_stream_xor(output + NONCE_BYTES + IPV4_AND_UDP_HEADER_SIZE,
                     data + IPV4_AND_UDP_HEADER_SIZE, size - IPV4_AND_UDP_HEADER_SIZE,
                     nonce, key);
   
   
   memcpy(output, data, IPV4_AND_UDP_HEADER_SIZE);
   memcpy(output + IPV4_AND_UDP_HEADER_SIZE, nonce, NONCE_BYTES);
   
   return size + NONCE_BYTES;
}

i64 packet_decrypt(u8 *output, u8* key, u8 *data, i64 size) {
   u8 nonce[NONCE_BYTES];

   if (!output || !key || !data || size < (IPV4_AND_UDP_HEADER_SIZE + NONCE_BYTES)) {
      return -1;
   }

   memcpy(nonce, data + IPV4_AND_UDP_HEADER_SIZE, NONCE_BYTES);

   crypto_stream_xor(output + IPV4_AND_UDP_HEADER_SIZE, 
                     data + NONCE_BYTES + IPV4_AND_UDP_HEADER_SIZE,
                     size - IPV4_AND_UDP_HEADER_SIZE - NONCE_BYTES,
                     nonce, key);
   
   
   memcpy(output, data, IPV4_AND_UDP_HEADER_SIZE);

   return size - NONCE_BYTES;
}

i64 packet_encrypt_sign(u8 *signed_data, u8 *key, u8 *data, i64 size) {
   u8 *aux_data;
   if (signed_data && key && data && size >= IPV4_AND_UDP_HEADER_SIZE) {
      aux_data = malloc(size + NONCE_BYTES);
      if (aux_data) {
         i64 auxSize = packet_encrypt(aux_data, key, data, size);
         i64 rtnSize = packet_sign(signed_data, key, aux_data, auxSize);
         free(aux_data);
         return rtnSize;
      }
   }
   return -1;
}

i64 packet_verify_decrypt(u8 *output, u8 *key, u8 *signed_data, i64 signed_size) {
   u8 *aux_data;
   if (output && key && signed_data &&
       signed_size >= (IPV4_AND_UDP_HEADER_SIZE + SIGN_AND_NONCE_BYTES)) {
      aux_data = malloc(signed_size - NONCE_BYTES);
      i64 rtnSize = -1;
      if (aux_data) {
         i64 auxSize = packet_verify(aux_data, key, signed_data, signed_size);
         if (auxSize > 0) {  //do not decrypt unless verified
            rtnSize = packet_decrypt(output, key, aux_data, auxSize);
         }
         free(aux_data);
      }
      return rtnSize;
   }
   return -1;
}
