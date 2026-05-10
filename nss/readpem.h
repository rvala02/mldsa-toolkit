#include <stdio.h>
#include <stddef.h>
#include <keythi.h>

SECKEYPrivateKey *read_PrivateKey(FILE *fp);

/* import a raw (non-PEM) ML-DSA private key from a byte buffer */
SECKEYPrivateKey *import_raw_PrivateKey(const unsigned char *key_buf,
                                        size_t key_len, int mldsa_level);
