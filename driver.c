#include "LiteCrypto.h"

void printHex(u8 *data, u64 size) {
   u64 count;
   for (count = 0; count < size; ++count) {
      printf("%02x", (unsigned int) data[count]);
   }
   printf("\n");
}

int main(int argc, char **argv) {
   u8 *passwd = "LETMEIN";
   u8 *salt = "SLOWDAYINTHELIFE";
   u8 key[KEY_SIZE];
   int key_len = derive_key(key, passwd, strlen(passwd), salt);
   printf("key:\n");
   printHex(key, key_len);

   int message_len = 30;
   u8 message[30];
   memset(message, 97, message_len);
   printf("\nMessage:\n");
   printHex(message, message_len);

   u8 newMessage[30+SIGN_BYTES];
   packet_sign(newMessage, key, message, message_len);
   printf("\nNew Message:\n");
   printHex(newMessage, message_len+SIGN_BYTES);

   memset(message, 0, message_len);  //clear before outputting
   if (!packet_verify(message, key, newMessage, message_len+SIGN_BYTES)) {
      printf("\nVerified Message:\n");
      printHex(message, message_len);
   }
   else {
      printf("Failed to verify.");
   }

   return 0;
}
