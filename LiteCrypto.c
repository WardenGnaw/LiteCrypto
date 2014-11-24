#include "LiteCrypto.h"

u64 packet_sign(u8 *secret_key, u8 **message, u64 message_length) {
   int fd = open("/dev/urandom", O_RDONLY);
   u8 random_key[crypto_onetimeauth_KEYBYTES];
   u8 out[crypto_onetimeauth_key_and_bytes];
   u8 *ret = malloc(message_length + crypto_onetimeauth_key_and_bytes); // Allocate space for new signed packet

   if (NULL == ret) {
      perror("Failed to allocate space for new signed packet.\n");
      return -1; // Error failed to allocate space for signed packet.
   }

   if (fd < 0) {
      perror("Failed to open urandom.\n");
      return -2; // Error failed to open urandom.
   }
   
   if (read(fd, random_key, crypto_onetimeauth_KEYBYTES) == -1) {
      perror("Failed to read urandom.\n");
      return -2; // Error failed to open urandom.
   }

   crypto_onetimeauth(out + crypto_onetimeauth_KEYBYTES, *message, message_length, random_key); 

   crypto_secret_box(out, random_key, &message_length /* INSERT NONCE_HERE */, secret_key);

   memcpy(ret, *message, IPV4_AND_UDP_HEADER_SIZE);
   memcpy(ret + IPV4_AND_UDP_HEADER_SIZE, out, crypto_onetimeauth_KEYBYTES);
   memcpy(ret + IPV4_AND_UDP_HEADER_SIZE + crypto_onetimeauth_KEYBYTES, out + crypto_onetimeauth_KEYBYTES, crypto_onetimeauth_BYTES);
   memcpy(ret + IPV4_AND_UDP_HEADER_SIZE + crypto_onetimeauth_key_and_bytes, 
          *message + IPV4_AND_UDP_HEADER_SIZE, 
          message_length - IPV4_AND_UDP_HEADER_SIZE);  

   free(*message);                                           // Get rid of old data
   *message = ret;                                           // Return encrypted data
   memset(random_key, 0, crypto_onetimeauth_KEYBYTES);       // Clear key
   close(fd);                                                // Close urandom
   return message_length + crypto_onetimeauth_key_and_bytes; // Return new size
}

u64 packet_verify(u8 *key, u8 **message, u64 message_length) {
   u8 authorization[crypto_onetimeauth_BYTES]; 
   u8 *ret = malloc(message_length - crypto_onetimeauth_key_and_bytes);
   
   memcpy(ret, *message, IPV4_AND_UDP_HEADER_SIZE);
   memcpy(authorization, *message + IPV4_AND_UDP_HEADER_SIZE, crypto_onetimeauth_BYTES); 
   memcpy(ret + IPV4_AND_UDP_HEADER_SIZE, 
          *message + IPV4_AND_UDP_HEADER_SIZE + crypto_onetimeauth_key_and_bytes, 
          message_length - IPV4_AND_UDP_HEADER_SIZE);  

   
   crypto_onetimeauth_verify(authorization, ret, message_length - crypto_onetimeauth_key_and_bytes, key);
   
   return 0;
}

u64 packet_secret_box(u8 **data, u64 size) {
   
   return 0;
}

u64 packet_open_secret_box(u8 **data, u64 size) {

   return 0;
}
