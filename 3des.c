/*
This is an implementation of the 3DES algorithm.
*/

#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/des.h>
#include <openssl/evp.h>

#define GCRYPT_NO_DEPRECATED
#include <gcrypt.h>

#include <mcrypt.h>

static const char key[] = "a0b1c2d3e4f5g6h7i8j9k0l1";
static const char iv[] = "m2n3o4p5";

static const uint8_t plaintext[] = "Hello World!";
static const uint8_t encrypted[] = { 0x00, 0xb0, 0xc3, 0x98, 0xd6, 0x78, 0x05, 0xb0, 0x0f, 0x50, 0x60, 0x71 };

// decrypt using openssl
void decrypt_3des_openssl(const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext) {
    DES_cblock key1, key2, key3, iv_cblock;
    DES_key_schedule schedule1, schedule2, schedule3;

	// openssl needs the 3 keys seperately and mutable
    memcpy(&key1, key, sizeof(key1));
    memcpy(&key2, &key[8], sizeof(key2));
    memcpy(&key3, &key[16], sizeof(key3));

	// IV should be mutable also
    memcpy(&iv_cblock, iv, sizeof(iv_cblock));

	// openssl needs odd parity enforced
    DES_set_odd_parity(&key1);
    DES_set_odd_parity(&key2);
    DES_set_odd_parity(&key3);

    if (DES_set_key_checked(&key1, &schedule1) < 0) {
        errx(1, "DES_set_key_checked");
    }
    if (DES_set_key_checked(&key2, &schedule2) < 0) {
        errx(1, "DES_set_key_checked");
    }
    if (DES_set_key_checked(&key3, &schedule3) < 0) {
        errx(1, "DES_set_key_checked");
    }

    DES_ede3_cfb_encrypt(ciphertext, plaintext,
            8, ciphertext_length,
            &schedule1, &schedule2, &schedule3,
            &iv_cblock, DES_DECRYPT);
}

// decrypt using mcrypt
void decrypt_3des_mcrypt(const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext) {
	MCRYPT m;

	// mcrypt decrypts in place so we need to make a mutable copy of the
	// ciphertext
	memcpy(plaintext, ciphertext, ciphertext_length);

	m = mcrypt_module_open("tripledes", NULL, "cfb", NULL);
	if (m == MCRYPT_FAILED) {
		errx(1, "mcrypt_module_open");
	}

	int rv;
	rv = mcrypt_generic_init(m, (void *)key, sizeof(key) - 1, (void *)iv);
	if (rv < 0) {
		errx(1, "mcrypt_generic_init");
	}

	rv = mdecrypt_generic(m, plaintext, ciphertext_length);
	if (rv < 0) {
		errx(1, "mcrypt_generic");
	}

	rv = mcrypt_generic_deinit(m);
	if (rv < 0) {
		errx(1, "mcrypt_generic_deinit");
	}

	rv = mcrypt_module_close(m);
	if (rv < 0) {
		errx(1, "mcrypt_module_close");
	}
}

// decrypt using gcrypt
void decrypt_3des_gcrypt(const uint8_t *ciphertext, size_t ciphertext_length, uint8_t *plaintext) {
	gcry_error_t error;

	// init gcrypt library
	gcry_check_version(NULL);
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	gcry_cipher_hd_t handle;
	error = gcry_cipher_open(&handle, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CFB, 0);
	if (gcry_err_code(error) != GPG_ERR_NO_ERROR) {
		errx(1, "gcry_cipher_open: %s", gcry_strerror(error));
	}

	error = gcry_cipher_setkey(handle, key, sizeof(key) - 1);
	if (gcry_err_code(error) != GPG_ERR_NO_ERROR) {
		errx(1, "gcry_cipher_setkey: %s", gcry_strerror(error));
	}

	error = gcry_cipher_setiv(handle, iv, sizeof(iv) - 1);
	if (gcry_err_code(error) != GPG_ERR_NO_ERROR) {
		errx(1, "gcry_cipher_setiv: %s", gcry_strerror(error));
	}

	error = gcry_cipher_decrypt(handle, plaintext, ciphertext_length, ciphertext, ciphertext_length);
	if (gcry_err_code(error) != GPG_ERR_NO_ERROR) {
		errx(1, "gcry_cipher_decrypt: %s", gcry_strerror(error));
	}
	gcry_cipher_close(handle);
}

/*
 * decrypt the same hardcoded message 3 times with different libraries
 */
int main(int argc, char *argv[]) {
	uint8_t decrypted[sizeof(encrypted)];

	// openssl
	decrypt_3des_openssl(encrypted, sizeof(encrypted), decrypted);
	assert(memcmp(plaintext, decrypted, sizeof(encrypted)) == 0);

	// clear out decrypted so we know the next method has worked
	memset(decrypted, 0, sizeof(decrypted));

	// mcrypt
	decrypt_3des_mcrypt(encrypted, sizeof(encrypted), decrypted);
	assert(memcmp(plaintext, decrypted, sizeof(encrypted)) == 0);
	
	// clear out decrypted so we know the next method has worked
	memset(decrypted, 0, sizeof(decrypted));
	
	// gcrypt
	decrypt_3des_gcrypt(encrypted, sizeof(encrypted), decrypted);
	// this assert fails as gcrypt only ever gives us the first character
	// of plaintext...?
	assert(memcmp(plaintext, decrypted, sizeof(encrypted)) == 0);

	return 0;
}
