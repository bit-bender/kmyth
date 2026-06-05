//
// An implementation of the Needham-Schroeder-Lowe protocol using OpenSSL RSA.
// 

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/engine.h>

#include "defines.h"
#include "memory_util.h"

#define NSL_NONCE_LEN 32
#define NSL_ID_MAX_LEN 128
#define NSL_SESSION_KEY_LEN 32

#define NSL_RX_BUF_LEN 8192

//
// encrypt_with_key_pair()
//
int encrypt_with_key_pair(EVP_PKEY_CTX * ctx,
                          const unsigned char *p,
                          size_t p_len,
                          unsigned char **c,
                          size_t *c_len)
{
  // Initialize the context for encryption.
  int result = EVP_PKEY_encrypt_init(ctx);

  if (result == 0)
  {
    kmyth_log(LOG_ERR, "Failed to initialize the EVP context for encryption.");
    return 1;
  }

  // Determine the length of the ciphertext buffer.
  result = EVP_PKEY_encrypt(ctx, NULL, c_len, p, p_len);
  if (result <= 0)
  {
    kmyth_log(LOG_ERR,
              "Failed to determine the length of the ciphertext buffer.");
    return 1;
  }

  // Allocate the ciphertext buffer.
  *c = (unsigned char *) calloc(*c_len, sizeof(unsigned char));
  if (*c == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the ciphertext buffer.");
    return 1;
  }

  // Encrypt the plaintext.
  result = EVP_PKEY_encrypt(ctx, *c, c_len, p, p_len);
  if (result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the plaintext.");
    return 1;
  }

  return 0;
}

//
// decrypt_with_key_pair()
//
int decrypt_with_key_pair(EVP_PKEY_CTX * ctx,
                          const unsigned char *c,
                          size_t c_len,
                          unsigned char **p,
                          size_t *p_len)
{
  // Initialize the context for decryption.
  int result = EVP_PKEY_decrypt_init(ctx);

  if (result == 0)
  {
    kmyth_log(LOG_ERR, "Failed to initialize the EVP context for decryption.");
    return 1;
  }

  // Determine the length of the plaintext buffer.
  result = EVP_PKEY_decrypt(ctx, NULL, p_len, c, c_len);
  if (result <= 0)
  {
    kmyth_log(LOG_ERR,
              "Failed to determine the length of the plaintext buffer.");
    return 1;
  }

  // Allocate the plaintext buffer.
  *p = calloc(*p_len, sizeof(unsigned char));
  if (*p == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the plaintext buffer.");
    return 1;
  }

  // Decrypt the ciphertext.
  result = EVP_PKEY_decrypt(ctx, *p, p_len, c, c_len);
  if (result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the ciphertext.");
    return 1;
  }

  return 0;
}

//
// build_nonce_request()
// 
int build_nonce_request(EVP_PKEY_CTX * ctx,
                        unsigned char *nonce,
                        size_t nonce_len,
                        unsigned char *id,
                        size_t id_len,
                        unsigned char **request,
                        size_t *request_len)
{
  // Validate nonce and ID lengths provided as parameters.
  if (NSL_NONCE_LEN != nonce_len)
  {
    kmyth_log(LOG_ERR,
              "Invalid nonce length; specified: %zd, expected: %zd",
              nonce_len, NSL_NONCE_LEN);
    return 1;
  }
  if (id_len > NSL_ID_MAX_LEN) {
    kmyth_log(LOG_ERR,
              "Invalid ID length; specified: %zd, maximum: %zd",
              id_len,
              NSL_ID_MAX_LEN);
    return 1;
  }

  // Allocate the unencrypted request buffer.
  unsigned char *message = NULL;
  size_t message_len = id_len + nonce_len + (2 * sizeof(size_t));

  message = calloc(message_len, sizeof(unsigned char));
  if (message == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the message buffer.");
    return 1;
  }

  // Build the nonce request message.
  unsigned char *index = message;

  memcpy(index, &nonce_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, nonce, nonce_len);
  index += nonce_len;
  memcpy(index, &id_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, id, id_len);

  // Encrypt the nonce request and then clean up the unencrypted request.
  int result =
    encrypt_with_key_pair(ctx, message, message_len, request, request_len);

  kmyth_clear_and_free(message, message_len);

  // Handle encryption errors if any occurred.
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the nonce request.");
    return 1;
  }

  return 0;
}

//
// parse_nonce_request()
//
int parse_nonce_request(EVP_PKEY_CTX * ctx,
                        unsigned char *request,
                        size_t request_len,
                        unsigned char **nonce,
                        size_t *nonce_len,
                        unsigned char **id,
                        size_t *id_len)
{
  // Decrypt the nonce request.
  unsigned char *message = NULL;
  size_t message_len = 0;
  int result = decrypt_with_key_pair(ctx,
                                     request,
                                     request_len,
                                     &message,
                                     &message_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the nonce request.");
    return 1;
  }
  unsigned char *index = message;
  size_t bytes_remaining = message_len;
  
  // Parse out and validate the nonce size.
  if (bytes_remaining < sizeof(size_t)) {
    kmyth_log(LOG_ERR, "Nonce request message buffer too small.");
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(nonce_len, index, sizeof(size_t));
  if (NSL_NONCE_LEN != *nonce_len)
  {
    kmyth_log(LOG_ERR,
              "Unexpected nonce size; received %zd, expected: %zd",
              *nonce_len, NSL_NONCE_LEN);
    *nonce_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  index += sizeof(size_t);
  bytes_remaining -= sizeof(size_t);
  
  // Allocate buffer for nonce bytes.
  *nonce = calloc(*nonce_len, sizeof(unsigned char));
  if (*nonce == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate nonce buffer.");
    *nonce_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }

  // Parse nonce bytes
  if (bytes_remaining < *nonce_len) {
    kmyth_log(LOG_ERR, "Nonce request message buffer too small.");
    *nonce_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(*nonce, index, *nonce_len);
  index += *nonce_len;
  bytes_remaining -= *nonce_len;

  // Parse out and validate ID size.
  if (bytes_remaining < sizeof(size_t)) {
    kmyth_log(LOG_ERR, "Nonce request message buffer too small.");
    kmyth_clear_and_free(*nonce, *nonce_len);
    *nonce = NULL;
    *nonce_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(id_len, index, sizeof(size_t));
  if (*id_len > NSL_ID_MAX_LEN) {
    kmyth_log(LOG_ERR,
              "Invalid ID size; received: %zd, maximum: %zd",
              *id_len, NSL_ID_MAX_LEN);
    kmyth_clear_and_free(*nonce, *nonce_len);
    *nonce_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  index += sizeof(size_t);
  bytes_remaining -= sizeof(size_t);
  
  // Allocate buffer for ID bytes
  *id = calloc(*id_len, sizeof(unsigned char));
  if (*id == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate ID buffer.");
    kmyth_clear_and_free(*nonce, *nonce_len);
    *nonce = NULL;
    *nonce_len = 0;
    *id_len = 0;
    kmyth_clear_and_free(message, message_len);

    return 1;
  }

  // Parse ID bytes
  if (bytes_remaining != *id_len) {
    kmyth_log(LOG_ERR, "Nonce request message buffer size mis-match.");
    kmyth_clear_and_free(*nonce, *nonce_len);
    *nonce = NULL;
    *nonce_len = 0;
    kmyth_clear_and_free(*id, *id_len);
    *id = NULL;
    *id_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(*id, index, *id_len);

  kmyth_clear_and_free(message, message_len);

  return 0;
}

//
// build_nonce_response()
//
int build_nonce_response(EVP_PKEY_CTX * ctx,
                         unsigned char *nonce_a,
                         size_t nonce_a_len,
                         unsigned char *nonce_b,
                         size_t nonce_b_len,
                         unsigned char *id,
                         size_t id_len,
                         unsigned char **response,
                         size_t *response_len)
{
  // Validate nonce and ID lengths provided as parameters.
  if (NSL_NONCE_LEN != nonce_a_len)
  {
    kmyth_log(LOG_ERR,
              "Invalid first nonce length; specified: %zd, expected: %zd",
              nonce_a_len, NSL_NONCE_LEN);
    return 1;
  }
  if (NSL_NONCE_LEN != nonce_b_len)
  {
    kmyth_log(LOG_ERR,
              "Invalid second nonce length; specified: %zd, expected: %zd",
              nonce_b_len, NSL_NONCE_LEN);
    return 1;
  }
  if (id_len > NSL_ID_MAX_LEN) {
    kmyth_log(LOG_ERR,
              "Invalid ID length; specified: %zd, maximum: %zd",
              id_len,
              NSL_ID_MAX_LEN);
    return 1;
  }

  // Allocate the unencrypted response buffer.
  unsigned char *message = NULL;
  size_t message_len = id_len +
                       nonce_a_len +
                       nonce_b_len +
                       (3 * sizeof(size_t));
  message = (unsigned char *) calloc(message_len, sizeof(unsigned char));
  if (message == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the message buffer.");
    return 1;
  }

  // Build the nonce response message.
  unsigned char *index = message;

  memcpy(index, &nonce_a_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, nonce_a, nonce_a_len);
  index += nonce_a_len;
  memcpy(index, &nonce_b_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, nonce_b, nonce_b_len);
  index += nonce_b_len;
  memcpy(index, &id_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, id, id_len);

  // Encrypt the nonce response and then clean up the unencrypted response.
  int result = encrypt_with_key_pair(ctx,
                                     message,
                                     message_len,
                                     response,
                                     response_len);

  kmyth_clear_and_free(message, message_len);

  // Handle encryption errors if any occurred.
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the nonce response.");
    return 1;
  }

  return 0;
}

//
// parse_nonce_response()
//
int parse_nonce_response(EVP_PKEY_CTX * ctx,
                         unsigned char *response,
                         size_t response_len,
                         unsigned char **nonce_a,
                         size_t *nonce_a_len,
                         unsigned char **nonce_b,
                         size_t *nonce_b_len,
                         unsigned char **id,
                         size_t *id_len)
{
  // Decrypt the nonce response.
  unsigned char *message = NULL;
  size_t message_len = 0;
  int result = decrypt_with_key_pair(ctx,
                                     response,
                                     response_len,
                                     &message,
                                     &message_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the nonce response.");
    return 1;
  }

  unsigned char *index = message;
  size_t bytes_remaining = message_len;

  // Parse and validate size of first nonce.
  if (bytes_remaining < sizeof(size_t)) {
    kmyth_log(LOG_ERR, "Nonce response message buffer too small.");
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(nonce_a_len, index, sizeof(size_t));
  if (NSL_NONCE_LEN != *nonce_a_len)
  {
    kmyth_log(LOG_ERR,
              "Unexpected length for nonce A; received: %zd bytes, expected: %zd bytes",
              *nonce_a_len, NSL_NONCE_LEN);
    *nonce_a_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  index += sizeof(size_t);
  bytes_remaining -= sizeof(size_t);

  // Allocate buffer for first nonce
  *nonce_a = calloc(*nonce_a_len, sizeof(unsigned char));
  if (*nonce_a == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate buffer for first nonce.");
    *nonce_a_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }

  // Parse first nonce bytes
  if (bytes_remaining < *nonce_a_len) {
    kmyth_log(LOG_ERR, "Nonce response message buffer too small.");
    *nonce_a_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(*nonce_a, index, *nonce_a_len);
  index += *nonce_a_len;
  bytes_remaining -= *nonce_a_len;

  // Parse and validate size of second nonce.
  if (bytes_remaining < sizeof(size_t)) {
    kmyth_log(LOG_ERR, "Nonce response message buffer too small.");
    kmyth_clear_and_free(*nonce_a, *nonce_a_len);
    *nonce_a = NULL;
    *nonce_a_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(nonce_b_len, index, sizeof(size_t));
  if (NSL_NONCE_LEN != *nonce_b_len)
  {
    kmyth_log(LOG_ERR,
              "Unexpected length for nonce B; received: %zd bytes, expected: %zd bytes",
              *nonce_b_len, NSL_NONCE_LEN);
    kmyth_clear_and_free(*nonce_a, *nonce_a_len);
    *nonce_a = NULL;
    *nonce_a_len = 0;
    *nonce_b_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  index += sizeof(size_t);
  bytes_remaining -= sizeof(size_t);
  
  // Allocate buffer for second nonce
  *nonce_b = calloc(*nonce_b_len, sizeof(unsigned char));
  if (*nonce_b == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate buffer for second nonce.");
    kmyth_clear_and_free(*nonce_a, *nonce_a_len);
    *nonce_a = NULL;
    *nonce_a_len = 0;
    *nonce_b_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  
  // Parse second nonce bytes
  if (bytes_remaining < *nonce_b_len) {
    kmyth_log(LOG_ERR, "Nonce response message buffer too small.");
    kmyth_clear_and_free(*nonce_a, *nonce_a_len);
    *nonce_a = NULL;
    *nonce_a_len = 0;
    *nonce_b_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(*nonce_b, index, *nonce_b_len);
  index += *nonce_b_len;
  bytes_remaining -= *nonce_b_len;

  // Parse and validate size of ID.
  if (bytes_remaining < sizeof(size_t)) {
    kmyth_log(LOG_ERR, "Nonce response message buffer too small.");
    kmyth_clear_and_free(*nonce_a, *nonce_a_len);
    *nonce_a = NULL;
    *nonce_a_len = 0;
    kmyth_clear_and_free(*nonce_b, *nonce_b_len);
    *nonce_b = NULL;
    *nonce_b_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(id_len, index, sizeof(size_t));
  if (*id_len > NSL_ID_MAX_LEN) {
    kmyth_log(LOG_ERR,
              "Invalid length for ID; received: %zd bytes, maximum: %zd bytes",
              *id_len, NSL_ID_MAX_LEN);
    kmyth_clear_and_free(*nonce_a, *nonce_a_len);
    *nonce_a = NULL;
    *nonce_a_len = 0;
    kmyth_clear_and_free(*nonce_b, *nonce_b_len);
    *nonce_b = NULL;
    *nonce_b_len = 0;
    *id_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  index += sizeof(size_t);
  bytes_remaining -= sizeof(size_t);

  // Allocate ID buffer
  *id = calloc(*id_len, sizeof(unsigned char));
  if (*id == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate ID buffer.");
    kmyth_clear_and_free(*nonce_a, *nonce_a_len);
    *nonce_a = NULL;
    *nonce_a_len = 0;
    kmyth_clear_and_free(*nonce_b, *nonce_b_len);
    *nonce_b = NULL;
    *nonce_b_len = 0;
    *id_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  
  // Parse ID bytes
  if (bytes_remaining != *id_len) {
    kmyth_log(LOG_ERR, "Nonce response message buffer size mis-match.");
    kmyth_clear_and_free(*nonce_a, *nonce_a_len);
    *nonce_a = NULL;
    *nonce_a_len = 0;
    kmyth_clear_and_free(*nonce_b, *nonce_b_len);
    *nonce_b = NULL;
    *nonce_b_len = 0;
    *id_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(*id, index, *id_len);

  kmyth_clear_and_free(message, message_len);

  return 0;
}

//
// build_nonce_confirmation()
//
int build_nonce_confirmation(EVP_PKEY_CTX * ctx,
                             unsigned char *nonce,
                             size_t nonce_len,
                             unsigned char **confirmation,
                             size_t *confirmation_len)
{
  // Validate nonce length provided as a parameter.
  if (NSL_NONCE_LEN != nonce_len)
  {
    kmyth_log(LOG_ERR,
              "Invalid nonce length; specified: %zd, expected: %zd",
              nonce_len, NSL_NONCE_LEN);
    return 1;
  }

  // Allocate the unencrypted confirmation buffer.
  unsigned char *message = NULL;
  size_t message_len = nonce_len + sizeof(size_t);

  message = calloc(message_len, sizeof(unsigned char));
  if (message == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the message buffer.");
    return 1;
  }

  // Build the nonce confirmation message.
  unsigned char *index = message;

  memcpy(index, &nonce_len, sizeof(size_t));
  index += sizeof(size_t);
  memcpy(index, nonce, nonce_len);

  // Encrypt the nonce confirmation and then clean up the unencrypted
  // confirmation.
  int result = encrypt_with_key_pair(ctx,
                                     message,
                                     message_len,
                                     confirmation,
                                     confirmation_len);

  kmyth_clear_and_free(message, message_len);

  // Handle encryption errors if any occurred.
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to encrypt the nonce confirmation.");
    return 1;
  }

  return 0;
}

//
// parse_nonce_confirmation()
//
int parse_nonce_confirmation(EVP_PKEY_CTX * ctx,
                             unsigned char *confirmation,
                             size_t confirmation_len,
                             unsigned char **nonce,
                             size_t *nonce_len)
{
  // Decrypt the nonce confirmation.
  unsigned char *message = NULL;
  size_t message_len = 0;
  int result = decrypt_with_key_pair(ctx,
                                     confirmation,
                                     confirmation_len,
                                     &message,
                                     &message_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to decrypt the nonce confirmation.");
    return 1;
  }

  // Initialize 'index' and 'bytes_remaining' variables for parsing message
  unsigned char *index = message;
  size_t bytes_remaining = message_len;

  // Parse and validate size of nonce.
  if (bytes_remaining < sizeof(size_t)) {
    kmyth_log(LOG_ERR, "Nonce confirmation message buffer too small.");
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(nonce_len, index, sizeof(size_t));
  if (NSL_NONCE_LEN != *nonce_len)
  {
    kmyth_log(LOG_ERR,
              "Unexpected length for nonce; received: %zd bytes, expected: %zd bytes",
              *nonce_len, NSL_NONCE_LEN);
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  index += sizeof(size_t);
  bytes_remaining -= sizeof(size_t);
  

  // Allocate the nonce buffer
  *nonce = calloc(*nonce_len, sizeof(unsigned char));
  if (*nonce == NULL)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the nonce buffer.");
    *nonce_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  
  // Parse the nonce bytes 
  if (bytes_remaining < *nonce_len) {
    kmyth_log(LOG_ERR, "Nonce confirmation message buffer too small.");
    *nonce_len = 0;
    kmyth_clear_and_free(message, message_len);
    return 1;
  }
  memcpy(*nonce, index, *nonce_len);

  kmyth_clear_and_free(message, message_len);

  return 0;
}

//
// setup_public_evp_context
//
EVP_PKEY_CTX *setup_public_evp_context(const char *filepath)
{
  FILE *f = fopen(filepath, "r");

  if (NULL == f)
  {
    kmyth_log(LOG_ERR, "Failed to open public key file.");
    return NULL;
  }

  EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);

  if (NULL == pkey)
  {
    kmyth_log(LOG_ERR, "Failed to load public key file.");
    if (fclose(f) != 0)
    {
      kmyth_log(LOG_ERR, "Failed to close public key file.");
    }
    return NULL;
  }

  if (fclose(f) != 0)
  {
    kmyth_log(LOG_ERR, "Failed to close public key file.");
    EVP_PKEY_free(pkey);
    return NULL;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

  if (NULL == ctx)
  {
    kmyth_log(LOG_ERR, "Failed to create public key EVP context.");
    EVP_PKEY_free(pkey);
    return NULL;
  }

  EVP_PKEY_free(pkey);

  return ctx;
}

//
// setup_private_evp_context()
//
EVP_PKEY_CTX *setup_private_evp_context(const char *filepath)
{
  FILE *f = fopen(filepath, "r");

  if (NULL == f)
  {
    kmyth_log(LOG_ERR, "Failed to open private key file.");
    return NULL;
  }

  EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);

  if (NULL == pkey)
  {
    kmyth_log(LOG_ERR, "Failed to load private key file.");
    if (fclose(f) != 0)
    {
      kmyth_log(LOG_ERR, "Failed to close private key file.");
    }
    return NULL;
  }

  if (fclose(f) != 0)
  {
    kmyth_log(LOG_ERR, "Failed to close private key file.");
    EVP_PKEY_free(pkey);
    return NULL;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);

  if (NULL == ctx)
  {
    kmyth_log(LOG_ERR, "Failed to create private key EVP context.");
    EVP_PKEY_free(pkey);

    return NULL;
  }

  EVP_PKEY_free(pkey);

  return ctx;
}

//
// generate_session_key()
//
int generate_session_key(unsigned char *nonce_a,
                         size_t nonce_a_len,
                         unsigned char *nonce_b,
                         size_t nonce_b_len,
                         unsigned char **key,
                         size_t *key_len)
{
  // Validate the nonce lengths provided as parameters
  if (NSL_NONCE_LEN != nonce_a_len)
  {
    kmyth_log(LOG_ERR,
              "Invalid first nonce length; specified: %zd, expected: %zd",
              nonce_a_len, NSL_NONCE_LEN);
    return 1;
  }
  if (NSL_NONCE_LEN != nonce_b_len)
  {
    kmyth_log(LOG_ERR,
              "Invalid second nonce length; specifieded: %zd, expected: %zd",
              nonce_b_len, NSL_NONCE_LEN);
    return 1;
  }

  // Build the combined nonce as the base for key generation.

  // Allocate a buffer to hold the concatenated nonces
  size_t nonces_len = nonce_a_len + nonce_b_len;
  unsigned char *nonces = calloc(nonces_len, sizeof(unsigned char));
  if (NULL == nonces)
  {
    kmyth_log(LOG_ERR, "Failed to allocated the nonces buffer.");
    return 1;
  }
  
  // Copy the nonce values into the buffer
  unsigned char *index = nonces;
  memcpy(index, nonce_a, nonce_a_len);
  index += nonce_a_len;
  memcpy(index, nonce_b, nonce_b_len);

  // Setup the message digest context.
  const EVP_MD *type = EVP_shake256();
  if (NULL == type)
  {
    kmyth_log(LOG_ERR, "Failed to obtain the SHAKE-256 MD.");
    kmyth_clear_and_free(nonces, nonces_len);
    return 1;
  }

  // Create new message digest context
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (NULL == ctx)
  {
    kmyth_log(LOG_ERR, "Failed to create the MD context.");
    kmyth_clear_and_free(nonces, nonces_len);
    return 1;
  }

  // Initialize the context and load in nonces
  int result = EVP_DigestInit_ex(ctx, type, NULL);

  if (0 == result)
  {
    kmyth_log(LOG_ERR, "Failed to initialize the MD context.");
    EVP_MD_CTX_free(ctx);
    kmyth_clear_and_free(nonces, nonces_len);
    return 1;
  }

  // Hash loaded value to compute message digest
  result = EVP_DigestUpdate(ctx, nonces, nonces_len);
  if (0 == result)
  {
    kmyth_log(LOG_ERR, "Failed to update the MD context.");
    EVP_MD_CTX_free(ctx);
    kmyth_clear_and_free(nonces, nonces_len);
    return 1;
  }

  // Allocate session key buffer
  // Set session key length to match digest length of hash
  *key_len = (size_t) EVP_MD_get_size(type);
  *key = calloc(*key_len, sizeof(unsigned char));
  if (NULL == key)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the key buffer.");
    EVP_MD_CTX_free(ctx);
    kmyth_clear_and_free(nonces, nonces_len);
    return 1;
  }

  result = EVP_DigestFinalXOF(ctx, *key, (unsigned int) *key_len);
  if (0 == result)
  {
    kmyth_log(LOG_ERR, "Failed to finalize the MD context.");
    EVP_MD_CTX_free(ctx);
    kmyth_clear_and_free(nonces, nonces_len);
    kmyth_clear_and_free(*key, *key_len);
    return 1;
  }

  EVP_MD_CTX_free(ctx);
  kmyth_clear_and_free(nonces, nonces_len);

  if (*key_len != NSL_SESSION_KEY_LEN)
  {
    kmyth_log(LOG_ERR,
              "The generated key length must be %zd bytes, not %zd bytes.",
              NSL_SESSION_KEY_LEN, *key_len);
    kmyth_clear_and_free(*key, *key_len);
    return 1;
  }
  
  char key_str[(2 * *key_len) + 1];
  char *key_str_ptr = key_str;
  for (size_t i = 0; i < *key_len; i++) {
    key_str_ptr += sprintf(key_str_ptr, "%02X", (*key)[i]);
  }
  kmyth_log(LOG_DEBUG,
            "Generated session key (%zd bytes): %s",
            *key_len,
            key_str);

  return 0;
}

//
// generate_nonce()
//
int generate_nonce(size_t desired_nonce_len,
                   unsigned char **nonce,
                   size_t *nonce_len)
{
  int urand_fd = open("/dev/urandom", O_RDONLY);
  if (urand_fd < 0) {
    kmyth_log(LOG_ERR, "Error opening /dev/urandom");
    return 1;
  }

  uint8_t *buffer = calloc(desired_nonce_len, 1);

  if (NULL == buffer)
  {
    kmyth_log(LOG_ERR, "Failed to allocated the nonce buffer.");
    return 1;
  }

  read(urand_fd, buffer, desired_nonce_len);

  *nonce = (unsigned char *) buffer;
  *nonce_len = desired_nonce_len;

  return 0;
}

//
// negotiate_client_session_key()
//
int negotiate_client_session_key(int socket_fd,
                                 EVP_PKEY_CTX * public_key_ctx,
                                 EVP_PKEY_CTX * private_key_ctx,
                                 unsigned char *client_id,
                                 size_t client_id_len,
                                 unsigned char *expected_server_id,
                                 size_t expected_server_id_len,
                                 unsigned char **session_key,
                                 size_t *session_key_len)
{
  // Generate client nonce locally
  unsigned char *client_nonce = NULL;
  size_t client_nonce_len = 0;

  int result = generate_nonce(NSL_NONCE_LEN, &client_nonce, &client_nonce_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to generate local (client) nonce.");
    return 1;
  }

  char client_nonce_str[(2 * client_nonce_len) + 1];
  char *client_nonce_str_ptr = client_nonce_str;
  for (size_t i = 0; i < client_nonce_len; i++) {
    client_nonce_str_ptr += sprintf(client_nonce_str_ptr, "%02X", client_nonce[i]);
  }
  kmyth_log(LOG_DEBUG,
            "Generated local (client) nonce (%zd bytes): %s",
            client_nonce_len,
            client_nonce_str);

  // Conduct NSL to obtain server nonce

  // Client builds and sends nonce request message
  unsigned char *request = NULL;
  size_t request_len = 0;
  result = build_nonce_request(public_key_ctx,
                               client_nonce, client_nonce_len,
                               client_id, client_id_len,
                               &request, &request_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the nonce request.");
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(request, request_len);
    return 1;
  }
  if (write(socket_fd, request, request_len) != request_len)
  {
    kmyth_log(LOG_ERR, "Error sending nonce request to server.");
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(request, request_len);
    return 1;
  }
  kmyth_log(LOG_DEBUG,
            "Sent nonce request message (%d bytes) to server.",
            request_len);
  kmyth_clear_and_free(request, request_len);
  request = NULL;
  request_len = 0;
 

  // Allocate buffer to receive nonce response message from server
  unsigned char *response = calloc(NSL_RX_BUF_LEN, sizeof(unsigned char));
  if (NULL == response)
  {
    kmyth_log(LOG_ERR, "Failed to allocate the response buffer.");
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    return 1;
  }

  // Read in (receive) nonce response message from server
  ssize_t read_result = read(socket_fd, response, NSL_RX_BUF_LEN);
  if (read_result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to read the nonce response message.");
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(response, NSL_RX_BUF_LEN);
    return 1;
  }
  kmyth_log(LOG_DEBUG,
            "Received nonce response message (%zd bytes) from server",
            read_result);

  // Parse received nonce response message
  // ( Note: read_result can safely be cast to a size_t
  //         since already checked that it is not negative)
  unsigned char *server_id = NULL;
  size_t server_id_len = 0;
  unsigned char *server_nonce = NULL;
  size_t server_nonce_len = 0;
  unsigned char *rcvd_client_nonce = NULL;
  size_t rcvd_client_nonce_len = 0;
  result = parse_nonce_response(private_key_ctx,
                                response, (size_t)read_result,
                                &rcvd_client_nonce, &rcvd_client_nonce_len,
                                &server_nonce, &server_nonce_len,
                                &server_id, &server_id_len);
  kmyth_clear_and_free(response, NSL_RX_BUF_LEN);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the nonce response.");
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    return 1;
  }

  char rcvd_client_nonce_str[(2 * rcvd_client_nonce_len) + 1];
  char *rcvd_client_nonce_str_ptr = rcvd_client_nonce_str;
  for (size_t i = 0; i < rcvd_client_nonce_len; i++) {
    rcvd_client_nonce_str_ptr += sprintf(rcvd_client_nonce_str_ptr, "%02X", rcvd_client_nonce[i]);
  }
  kmyth_log(LOG_DEBUG, "Received client nonce (%zd bytes): %s",
                       rcvd_client_nonce_len, rcvd_client_nonce_str);

  char server_nonce_str[(2 * server_nonce_len) + 1];
  char *server_nonce_str_ptr = &server_nonce_str[0];
  for (size_t i = 0; i < server_nonce_len; i++) {
    server_nonce_str_ptr += sprintf(server_nonce_str_ptr, "%02X", server_nonce[i]);
  }
  kmyth_log(LOG_DEBUG, "Received server nonce (%zd bytes): %s",
                       server_nonce_len, server_nonce_str);
  
  kmyth_log(LOG_DEBUG, "Received server ID: %.*s", server_id_len, server_id);

  if (client_nonce_len != rcvd_client_nonce_len)
  {
    kmyth_log(LOG_ERR, "%s; received: %zd, expected: %zd",
                       "Received client nonce length is invalid",
                       rcvd_client_nonce_len,
                       client_nonce_len);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(rcvd_client_nonce, rcvd_client_nonce_len);
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(server_id, server_id_len);
    return 1;
  }
  if (server_nonce_len != client_nonce_len)
  {
    kmyth_log(LOG_ERR, "%s; received: %zd, expected: %zd",
                       "Received server nonce length is invalid",
                       server_nonce_len,
                       client_nonce_len);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(rcvd_client_nonce, rcvd_client_nonce_len);
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(server_id, server_id_len);
    return 1;
  }
  if (strncmp((const char *) client_nonce,
              (const char *) rcvd_client_nonce,
              client_nonce_len) != 0)
  {
    kmyth_log(LOG_ERR, "Received/Generated client nonce mis-match.");
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(rcvd_client_nonce, rcvd_client_nonce_len);
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(server_id, server_id_len);
    return 1;
  }

  kmyth_clear_and_free(rcvd_client_nonce, rcvd_client_nonce_len);

  if (strncmp((const char *) server_id,
              (const char *) expected_server_id,
              expected_server_id_len) != 0)
  { 
    kmyth_log(LOG_ERR,
              "Invalid server ID; received: %s, expected: %s",
              server_id,
              expected_server_id);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(server_id, server_id_len);
    return 1;
  }

  kmyth_clear_and_free(server_id, server_id_len);

  //   - client sends nonce confirmation message
  unsigned char *confirmation = NULL;
  size_t confirmation_len = 0;
  result = build_nonce_confirmation(public_key_ctx,
                                    server_nonce, server_nonce_len,
                                    &confirmation, &confirmation_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the nonce confirmation.");
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    return 1;
  }

  if (write(socket_fd, confirmation, confirmation_len) != confirmation_len)
  {
    kmyth_log(LOG_ERR, "Failed to fully send the nonce confirmation.");
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(confirmation, confirmation_len);
    return 1;
  }

  kmyth_clear_and_free(confirmation, confirmation_len);
  confirmation = NULL;
  confirmation_len = 0;

  // Use nonces to generate shared session key S
  result = generate_session_key(client_nonce, client_nonce_len,
                                server_nonce, server_nonce_len,
                                session_key, session_key_len);
  kmyth_clear_and_free(client_nonce, client_nonce_len);
  kmyth_clear_and_free(server_nonce, server_nonce_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to generate the session key.");
    return 1;
  }

  return 0;
}

//
// negotiate_server_session_key()
//
int negotiate_server_session_key(int socket_fd,
                                 EVP_PKEY_CTX * public_key_ctx,
                                 EVP_PKEY_CTX * private_key_ctx,
                                 unsigned char *server_id,
                                 size_t server_id_len,
                                 unsigned char **session_key,
                                 size_t *session_key_len)
{
  // Generate server nonce
  unsigned char *server_nonce = NULL;
  size_t server_nonce_len = 0;

  int result = generate_nonce(NSL_NONCE_LEN, &server_nonce, &server_nonce_len);

  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to generate local (server) nonce.");
    return 1;
  }

  char server_nonce_str[(2 * server_nonce_len) + 1];
  char *server_nonce_str_ptr = server_nonce_str;
  for (size_t i = 0; i < server_nonce_len; i++) {
    server_nonce_str_ptr += sprintf(server_nonce_str_ptr, "%02X", server_nonce[i]);
  }
  kmyth_log(LOG_DEBUG,
            "Generated local (server) nonce (%zd bytes): %s",
            server_nonce_len,
            server_nonce_str);

  // Conduct NSL to obtain client nonce

  // Allocate buffer for nonce request message received from client
  unsigned char *request = calloc(NSL_RX_BUF_LEN, sizeof(unsigned char));
  if (NULL == request)
  {
    kmyth_log(LOG_ERR, "Failed to allocate receive buffer for nonce request.");
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    return 1;
  }

  // Receive nonce request message from client
  ssize_t read_result = read(socket_fd, request, NSL_RX_BUF_LEN);
  if (read_result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to receive the nonce request from client.");
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(request, NSL_RX_BUF_LEN);
    return 1;
  }

  unsigned char *client_nonce = NULL;
  size_t client_nonce_len = 0;

  unsigned char *client_id = NULL;
  size_t client_id_len = 0;

  // Parse the nonce request message received from the client
  // (Note: read_result can safely be cast to size_t because we've already
  //        checked that it is non-negative)
  result = parse_nonce_request(private_key_ctx,
                               request, (size_t)read_result,
                               &client_nonce, &client_nonce_len,
                               &client_id, &client_id_len);

  char client_nonce_str[(2 * client_nonce_len) + 1];
  char *client_nonce_str_ptr = client_nonce_str;
  for (size_t i = 0; i < client_nonce_len; i++) {
    client_nonce_str_ptr += sprintf(client_nonce_str_ptr,
                                    "%02X", client_nonce[i]);
  }
  kmyth_log(LOG_DEBUG,
            "Received remote (client) nonce (%zd bytes): %s",
            client_nonce_len,
            client_nonce_str);
  kmyth_log(LOG_DEBUG, "Received remote (client) ID: %.*s",
            client_id_len, client_id);
  kmyth_clear_and_free(client_id, client_id_len);
  kmyth_clear_and_free(request, NSL_RX_BUF_LEN);

  // Construct nonce response message
  unsigned char *response = NULL;
  size_t response_len = 0;
  result = build_nonce_response(public_key_ctx,
                                client_nonce, client_nonce_len,
                                server_nonce, server_nonce_len,
                                server_id, server_id_len,
                                &response, &response_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to build the nonce response.");
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(response, response_len);
    response = NULL;
    response_len = 0;
    return 1;
  }

  // Send nonce response message to client
  ssize_t send_result = write(socket_fd, response, response_len);
  if (response_len != send_result)
  {
    kmyth_log(LOG_ERR, "Error sending the nonce response.");
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(response, response_len);
    response = NULL;
    response_len = 0;
    return 1;
  }
  kmyth_log(LOG_DEBUG, "Sent nonce response message to client.");
  kmyth_clear_and_free(response, response_len);
  response = NULL;
  response_len = 0;

  // Allocate receive buffer for nonce confirmation expected from client
  unsigned char *confirmation = calloc(NSL_RX_BUF_LEN, sizeof(unsigned char));
  if (NULL == confirmation)
  {
    kmyth_log(LOG_ERR, "Failed to allocate confirmation message receive buffer.");
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    return 1;
  }
  
  // Receive (read in) the confirmation message from the client
  read_result = read(socket_fd, confirmation, NSL_RX_BUF_LEN);
  if (read_result <= 0)
  {
    kmyth_log(LOG_ERR, "Failed to receive the nonce confirmation.");
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(confirmation, NSL_RX_BUF_LEN);
    confirmation = NULL;
    return 1;
  }

  // Parse the received nonce confirmation message
  // (Note: read_result can safely be cast to a size_t
  //        because already checked that it is not negative)
  unsigned char *rcvd_server_nonce = NULL;
  size_t rcvd_server_nonce_len = 0;
  result = parse_nonce_confirmation(private_key_ctx,
                                    confirmation,
                                    (size_t) read_result,
                                    &rcvd_server_nonce,
                                    &rcvd_server_nonce_len);
  kmyth_clear_and_free(confirmation, NSL_RX_BUF_LEN);
  confirmation = NULL;
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to parse the nonce confirmation message.");
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    return 1;
  }
  if (server_nonce_len != rcvd_server_nonce_len)
  {
    kmyth_log(LOG_ERR, "Server nonce received from client has invalid size.");
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(rcvd_server_nonce, rcvd_server_nonce_len);
    return 1;
  }
  if (strncmp((const char *) server_nonce,
              (const char *) rcvd_server_nonce,
              server_nonce_len) != 0)
  {
    kmyth_log(LOG_ERR, "Invalid server nonce received from client.");
    kmyth_clear_and_free(server_nonce, server_nonce_len);
    kmyth_clear_and_free(client_nonce, client_nonce_len);
    kmyth_clear_and_free(rcvd_server_nonce, rcvd_server_nonce_len);
    return 1;
  }

  char rcvd_server_nonce_str[(2 * rcvd_server_nonce_len) + 1];
  char *rcvd_server_nonce_str_ptr = rcvd_server_nonce_str;
  for (size_t i = 0; i < rcvd_server_nonce_len; i++) {
    rcvd_server_nonce_str_ptr += sprintf(rcvd_server_nonce_str_ptr,
                                    "%02X", rcvd_server_nonce[i]);
  }
  kmyth_log(LOG_DEBUG,
            "Received server nonce (%zd bytes): %s",
            rcvd_server_nonce_len,
            rcvd_server_nonce_str);
  kmyth_clear_and_free(rcvd_server_nonce, rcvd_server_nonce_len);


  // Use nonces to generate shared session key S
  result = generate_session_key(client_nonce,
                                client_nonce_len,
                                server_nonce,
                                server_nonce_len,
                                session_key,
                                session_key_len);
  kmyth_clear_and_free(server_nonce, server_nonce_len);
  kmyth_clear_and_free(client_nonce, client_nonce_len);
  if (result)
  {
    kmyth_log(LOG_ERR, "Failed to generate the session key.");
    return 1;
  }

  return 0;
}
