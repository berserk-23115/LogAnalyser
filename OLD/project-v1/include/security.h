#ifndef SECURITY_H
#define SECURITY_H

#include <stddef.h>

// Authentication functions
int authenticate_user(const char *username, const char *password);
int create_user_credentials(const char *username, const char *password);
int verify_credentials(void);

// File encryption (if OpenSSL available)
#ifdef HAVE_OPENSSL
int encrypt_file(const char *input_file, const char *output_file, const char *key);
int decrypt_file(const char *input_file, const char *output_file, const char *key);
int generate_encryption_key(char *key_buffer, size_t buffer_size);
#endif

// Signature update system
int check_for_updates(const char *update_path);
int load_signatures_from_file(const char *signature_file);
int update_signatures(const char *source_dir);
int verify_signature_file(const char *filename);

// Secure storage
int save_encrypted_config(const char *filename);
int load_encrypted_config(const char *filename);

#endif
