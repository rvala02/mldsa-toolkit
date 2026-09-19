#include <stdio.h>
#include <stddef.h>
#include <keythi.h>

SECKEYPrivateKey *read_PrivateKey(FILE *fp);

/* import a raw (non-PEM) ML-DSA private key from a byte buffer */
SECKEYPrivateKey *import_raw_PrivateKey(const unsigned char *key_buf,
                                        size_t key_len, int mldsa_level);

SECKEYPrivateKey *import_seed_PrivateKey(const unsigned char *seed_buf,
                                         size_t seed_len,
                                         int mldsa_level);
                                        