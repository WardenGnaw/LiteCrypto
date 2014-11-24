#include "LiteCrypto.h"

void randombytes(u8 *output,u64 size) {
   int fd = open("/dev/urandom", O_RDONLY);
   if (fd < 0) {
      return;
   }
   read(fd, output, size);
   close(fd);
}

u64 derive_key(u8 *output_key, u8 *input_key, u64 input_size, u8 *salt) {
   u8 aux[KEY_SIZE + SALT_SIZE];
   u32 count;
   
   if (!output_key || !input_key || !salt) {
      return -1;
   }
   
   //add salt only to auxilitary array to use output_key (size KEY_SIZE)
   crypto_hash(aux, input_key, input_size);
   for (count = 0; count < KEY_DERIV_ITER; ++count) {
      memcpy(aux + KEY_SIZE, salt, SALT_SIZE);
      crypto_hash(output_key, aux, KEY_SIZE + SALT_SIZE);
      crypto_hash(aux, output_key, KEY_SIZE);
   }
   memcpy(aux + KEY_SIZE, salt, SALT_SIZE);
   crypto_hash(output_key, aux, KEY_SIZE + SALT_SIZE);
   
   return KEY_SIZE;
}

u64 packet_sign(u8 *signed_data, u8 *key, u8 *data, u64 size) {
   if (!signed_data || !key || !data) {
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

u64 packet_verify(u8 *output, u8 *key, u8 *signed_data, u64 signed_size) {
   u8 authorization[SIGN_BYTES];
   
   if (!output || !key || !signed_data) {
      return -1;
   }
   
   //copy tag from signed packet
   memcpy(authorization, signed_data + IPV4_AND_UDP_HEADER_SIZE, SIGN_BYTES);
   
   //reconstruct original packet without tag
   memcpy(output, signed_data, IPV4_AND_UDP_HEADER_SIZE);
   memcpy(output + IPV4_AND_UDP_HEADER_SIZE,
          signed_data + IPV4_AND_UDP_HEADER_SIZE + SIGN_BYTES,
          signed_size - IPV4_AND_UDP_HEADER_SIZE - SIGN_BYTES);
   
   return crypto_auth_verify(authorization, output, signed_size - SIGN_BYTES, key);
}

u64 packet_secret_box(u8 **data, u64 size) {
   
   return 0;
}

u64 packet_open_secret_box(u8 **data, u64 size) {

   return 0;
}
