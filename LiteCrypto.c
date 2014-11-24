#include "LiteCrypto.h"

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
