#include "LiteCrypto.h"

#define MY_MSG_LEN 64

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

   u8 message[MY_MSG_LEN];
   memset(message, 97, MY_MSG_LEN);
   printf("\nMessage:\n");
   printHex(message, MY_MSG_LEN);

   u8 encryptedMessage[MY_MSG_LEN+NONCE_BYTES];
   int encrypted_size = packet_encrypt(encryptedMessage, key, message, MY_MSG_LEN);
   printf("\nEncrypted Message:\n");
   printHex(encryptedMessage, encrypted_size);

   u8 signed_encryptedMessage[MY_MSG_LEN+NONCE_BYTES+SIGN_BYTES];
   int signed_size = packet_sign(signed_encryptedMessage, key, encryptedMessage,
                                 encrypted_size);
   printf("\nSigned Message:\n");
   printHex(signed_encryptedMessage, signed_size);

   memset(message, 0, MY_MSG_LEN);  //clear before outputting
   memset(encryptedMessage, 0, MY_MSG_LEN+NONCE_BYTES);

   encrypted_size = packet_verify(encryptedMessage, key,
                                  signed_encryptedMessage,
                                  signed_size);
   if (encrypted_size > 0) {
      printf("\nVerified Message:\n");
      printHex(encryptedMessage, encrypted_size);

      int decrypted_size = packet_decrypt(message, key, encryptedMessage,
                                          encrypted_size);
      printf("\nDecrypted Message:\n");
      printHex(message, decrypted_size);
   }
   else {
      printf("\nFailed to verify.\n");
   }

   printf("\nTESTING CONVENIENT AUTH_ENC FUNCTIONS\n");

   memset(message, 97, MY_MSG_LEN);
   printf("\nMessage:\n");
   printHex(message, MY_MSG_LEN);

   signed_size = packet_encrypt_sign(signed_encryptedMessage, key, message,
                                         MY_MSG_LEN);
   printf("\nSigned Encrypted Message:\n");
   printHex(signed_encryptedMessage, signed_size);

   memset(signed_encryptedMessage, 0, 1);

   int decrypted_size = packet_verify_decrypt(message, key, signed_encryptedMessage,
                                       signed_size);
   if (decrypted_size > 0) {
      printf("\nVerified Decrypted Message:\n");
      printHex(message, decrypted_size);
   }
   else {
      printf("\nFailed to verify.\n");
   }

   return 0;
}
