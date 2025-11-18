#include "security.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#endif

// Simple credential storage (for demo - not production secure)
#define CRED_FILE ".loganalyser_creds"

/**
 * Simple authentication (demonstration only)
 * In production, use proper password hashing (bcrypt, argon2, etc.)
 */
int authenticate_user(const char *username, const char *password) {
    if (!username || !password) return 0;
    
    FILE *fp = fopen(CRED_FILE, "r");
    if (!fp) {
        print_warning("No credentials file found. Use --init to create.\n");
        return 0;
    }
    
    char stored_user[128], stored_pass[128];
    int authenticated = 0;
    
    while (fscanf(fp, "%127s %127s", stored_user, stored_pass) == 2) {
        if (strcmp(username, stored_user) == 0 && 
            strcmp(password, stored_pass) == 0) {
            authenticated = 1;
            break;
        }
    }
    
    fclose(fp);
    return authenticated;
}

/**
 * Create user credentials
 */
int create_user_credentials(const char *username, const char *password) {
    if (!username || !password) return -1;
    
    FILE *fp = fopen(CRED_FILE, "a");
    if (!fp) {
        print_threat("Error: Could not create credentials file\n");
        return -1;
    }
    
    fprintf(fp, "%s %s\n", username, password);
    fclose(fp);
    
    // Set file permissions (Unix-like systems only)
#ifndef PLATFORM_WINDOWS
    chmod(CRED_FILE, 0600);
#endif
    
    print_success("User credentials created\n");
    return 0;
}

/**
 * Verify credentials interactively
 */
int verify_credentials(void) {
    char username[128], password[128];
    
    printf("Username: ");
    if (!fgets(username, sizeof(username), stdin)) return 0;
    username[strcspn(username, "\n")] = 0;
    
    printf("Password: ");
    if (!fgets(password, sizeof(password), stdin)) return 0;
    password[strcspn(password, "\n")] = 0;
    
    if (authenticate_user(username, password)) {
        print_success("Authentication successful\n");
        return 1;
    } else {
        print_threat("Authentication failed\n");
        return 0;
    }
}

#ifdef HAVE_OPENSSL
/**
 * Generate encryption key
 */
int generate_encryption_key(char *key_buffer, size_t buffer_size) {
    if (!key_buffer || buffer_size < 32) return -1;
    
    if (!RAND_bytes((unsigned char*)key_buffer, 32)) {
        print_threat("Error: Failed to generate encryption key\n");
        return -1;
    }
    
    return 0;
}

/**
 * Encrypt file using AES-256
 */
int encrypt_file(const char *input_file, const char *output_file, const char *key) {
    if (!input_file || !output_file || !key) return -1;
    
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        print_threat("Error: Could not open input file for encryption\n");
        return -1;
    }
    
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        fclose(in);
        print_threat("Error: Could not create output file for encryption\n");
        return -1;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(in);
        fclose(out);
        return -1;
    }
    
    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv))) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return -1;
    }
    
    // Write IV to output file
    fwrite(iv, 1, sizeof(iv), out);
    
    // Initialize encryption
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                           (unsigned char*)key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return -1;
    }
    
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return -1;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    
    if (!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return -1;
    }
    fwrite(outbuf, 1, outlen, out);
    
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    
    print_success("File encrypted successfully\n");
    return 0;
}

/**
 * Decrypt file using AES-256
 */
int decrypt_file(const char *input_file, const char *output_file, const char *key) {
    if (!input_file || !output_file || !key) return -1;
    
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        print_threat("Error: Could not open input file for decryption\n");
        return -1;
    }
    
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        fclose(in);
        print_threat("Error: Could not create output file for decryption\n");
        return -1;
    }
    
    // Read IV
    unsigned char iv[16];
    if (fread(iv, 1, sizeof(iv), in) != sizeof(iv)) {
        fclose(in);
        fclose(out);
        return -1;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(in);
        fclose(out);
        return -1;
    }
    
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                           (unsigned char*)key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return -1;
    }
    
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return -1;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    
    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        print_threat("Error: Decryption failed - wrong key or corrupted file\n");
        return -1;
    }
    fwrite(outbuf, 1, outlen, out);
    
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    
    print_success("File decrypted successfully\n");
    return 0;
}
#else
// Stub implementations when OpenSSL not available
int encrypt_file(const char *input_file, const char *output_file, const char *key) {
    (void)input_file; (void)output_file; (void)key;
    print_warning("Encryption not available - OpenSSL not found\n");
    return -1;
}

int decrypt_file(const char *input_file, const char *output_file, const char *key) {
    (void)input_file; (void)output_file; (void)key;
    print_warning("Decryption not available - OpenSSL not found\n");
    return -1;
}

int generate_encryption_key(char *key_buffer, size_t buffer_size) {
    (void)key_buffer; (void)buffer_size;
    print_warning("Key generation not available - OpenSSL not found\n");
    return -1;
}
#endif

/**
 * Update signatures from removable media or directory
 */
int update_signatures(const char *source_dir) {
    if (!source_dir) return -1;
    
    print_info("Checking for signature updates in: ");
    printf("%s\n", source_dir);
    
    // Check if directory exists
    struct stat st;
    if (stat(source_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        print_warning("Update directory not found or not accessible\n");
        return -1;
    }
    
    // Look for signature files
    char sig_file[512];
    snprintf(sig_file, sizeof(sig_file), "%s/signatures.txt", source_dir);
    
    if (stat(sig_file, &st) == 0) {
        print_info("Found signature file: ");
        printf("%s\n", sig_file);
        
        // Copy to local signatures directory
        FILE *src = fopen(sig_file, "r");
        if (!src) {
            print_threat("Error: Could not read signature file\n");
            return -1;
        }
        
        FILE *dst = fopen(g_config.signatures_path, "w");
        if (!dst) {
            fclose(src);
            print_threat("Error: Could not write to signatures directory\n");
            return -1;
        }
        
        char buffer[4096];
        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
            fwrite(buffer, 1, bytes, dst);
        }
        
        fclose(src);
        fclose(dst);
        
        print_success("Signatures updated successfully!\n");
        return 0;
    }
    
    print_warning("No signature updates found\n");
    return 1;
}

/**
 * Check for updates
 */
int check_for_updates(const char *update_path) {
    if (!update_path) update_path = UPDATES_DIR;
    
    print_info("Checking for updates...\n");
    
    struct stat st;
    if (stat(update_path, &st) != 0) {
        print_warning("Update path not found: ");
        printf("%s\n", update_path);
        return -1;
    }
    
    return update_signatures(update_path);
}

/**
 * Verify signature file integrity
 */
int verify_signature_file(const char *filename) {
    if (!filename) return -1;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;
    
    // Basic validation - check file format
    char line[1024];
    int valid_lines = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        // Check for expected format (pipe-separated)
        if (strchr(line, '|')) {
            valid_lines++;
        }
    }
    
    fclose(fp);
    
    return (valid_lines > 0) ? 0 : -1;
}
