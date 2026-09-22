#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

extern uint64_t gnutls_ml_dsa_last_core_cycles;

static void help(const char *name) {
    fprintf(stderr, "Usage: %s -i file -t file -k file -n num [-o file] [-e file] [-h]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, " -i file    File with concatenated messages to sign\n");
    fprintf(stderr, " -o file    File where to write the signatures (optional)\n");
    fprintf(stderr, " -t file    File where to write timing data\n");
    fprintf(stderr, " -k file    File with concatenated 32-byte ML-DSA key seeds\n");
    fprintf(stderr, " -e file    File with expected deterministic signatures (optional)\n");
    fprintf(stderr, " -n num     Length of individual messages in bytes\n");
    fprintf(stderr, " -s num     ML-DSA parameter set: 44, 65, or 87 (default: 44)\n");
    fprintf(stderr, " -h         This message\n");
}

#define SEED_LEN 32

static int wrap_seed_mldsa_pkcs8(int mldsa_level,
                                const unsigned char *seed,
                                unsigned char **out_der, size_t *out_len)
{
    /* OID 2.16.840.1.101.3.4.3.{17,18,19} */
    static const unsigned char oid44[] = {
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
    };
    static const unsigned char oid65[] = {
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
    };
    static const unsigned char oid87[] = {
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13
    };
    const unsigned char *oid;
    size_t oid_len = sizeof(oid44);
    /* seed CHOICE: 0x80 0x20 || seed[32] */
    static const size_t inner_len = 2 + SEED_LEN; /* 34 */
    size_t algid_len = 2 + oid_len;
    size_t body_len = 3 + algid_len + 2 + inner_len; /* version + algid + OCTET STRING */
    size_t total = 2 + body_len; /* SEQUENCE with short length (< 128) */
    unsigned char *buf;
    size_t off = 0;

    switch (mldsa_level) {
        case 44: oid = oid44; break;
        case 65: oid = oid65; break;
        case 87: oid = oid87; break;
        default: return -1;
    }

    /* body_len is 3+13+2+34 = 52, total 54 — short-form lengths throughout */
    if (body_len >= 0x80)
        return -1;

    buf = malloc(total);
    if (!buf)
        return -1;

    buf[off++] = 0x30;
    buf[off++] = (unsigned char)body_len;

    /* version INTEGER 0 */
    buf[off++] = 0x02;
    buf[off++] = 0x01;
    buf[off++] = 0x00;

    /* AlgorithmIdentifier */
    buf[off++] = 0x30;
    buf[off++] = (unsigned char)oid_len;
    memcpy(buf + off, oid, oid_len);
    off += oid_len;

    /* privateKey OCTET STRING containing seed CHOICE */
    buf[off++] = 0x04;
    buf[off++] = (unsigned char)inner_len;
    buf[off++] = 0x80;
    buf[off++] = 0x20;
    memcpy(buf + off, seed, SEED_LEN);
    off += SEED_LEN;

    if (off != total) {
        free(buf);
        return -1;
    }

    *out_der = buf;
    *out_len = total;
    return 0;
}

static gnutls_privkey_t pkey_from_seed(int mldsa_level,
                                       gnutls_pk_algorithm_t pk_alg,
                                       unsigned char *seed)
{
    gnutls_privkey_t pkey = NULL;
    unsigned char *pkcs8_der = NULL;
    size_t pkcs8_len = 0;
    gnutls_datum_t key_data;
    int r_ret;

    if (wrap_seed_mldsa_pkcs8(mldsa_level, seed, &pkcs8_der, &pkcs8_len) != 0)
        goto err;

    r_ret = gnutls_privkey_init(&pkey);
    if (r_ret < 0)
        goto err;

    key_data.data = pkcs8_der;
    key_data.size = pkcs8_len;

    r_ret = gnutls_privkey_import_x509_raw(
        pkey,
        &key_data,
        GNUTLS_X509_FMT_DER,
        NULL,
        0
    );
    if (r_ret < 0)
        goto err;

    if (gnutls_privkey_get_pk_algorithm(pkey, NULL) != pk_alg)
        goto err;

    free(pkcs8_der);
    return pkey;

err:
    free(pkcs8_der);
    if (pkey)
        gnutls_privkey_deinit(pkey);
    return NULL;
}

int main(int argc, char *argv[]) {
    int result = 1;
    int opt;

    char *msg_file = NULL;
    char *key_file = NULL;
    char *sig_file = NULL;
    char *expected_sig_file = NULL;
    char *time_file = NULL;

    size_t msg_len = 0;
    size_t key_len = 0;
    size_t sig_len = 0;
    size_t sig_cap = 0;
    int mldsa_level = 44;
    int count = 0;
    int r_ret;

    int msg_fd = -1, key_fd = -1, sig_fd = -1, time_fd = -1;
    int expected_sig_fd = -1;

    unsigned char *msg = NULL;
    unsigned char *expected_sig = NULL;
    unsigned char *key_buf = NULL;

    gnutls_privkey_t pkey = NULL;
    gnutls_sign_algorithm_t sig_alg;
    gnutls_pk_algorithm_t pk_alg;
    gnutls_datum_t msg_data = { NULL, 0 };
    gnutls_datum_t sig_data = { NULL, 0 };

    uint64_t time_diff;

    char alg_name[16];

    while ((opt = getopt(argc, argv, "i:k:o:t:e:n:s:h")) != -1) {
        switch (opt) {
            case 'i': msg_file = optarg; break;
            case 'k': key_file = optarg; break;
            case 'o': sig_file = optarg; break;
            case 't': time_file = optarg; break;
            case 'e': expected_sig_file = optarg; break;
            case 'n': sscanf(optarg, "%zu", &msg_len); break;
            case 's': mldsa_level = atoi(optarg); break;
            case 'h': help(argv[0]); return 0;
            default: help(argv[0]); return 1;
        }
    }

    if (!msg_file || !key_file || !time_file || !msg_len) {
        help(argv[0]);
        return 1;
    }

    if (mldsa_level != 44 && mldsa_level != 65 && mldsa_level != 87) {
        fprintf(stderr, "Invalid ML-DSA level: %d\n", mldsa_level);
        return 1;
    }

    key_len = SEED_LEN;

    switch (mldsa_level) {
        case 44:
            sig_cap = 2420;
            sig_alg = GNUTLS_SIGN_MLDSA44;
            pk_alg = GNUTLS_PK_MLDSA44;
            break;
        case 65:
            sig_cap = 3309;
            sig_alg = GNUTLS_SIGN_MLDSA65;
            pk_alg = GNUTLS_PK_MLDSA65;
            break;
        case 87:
            sig_cap = 4627;
            sig_alg = GNUTLS_SIGN_MLDSA87;
            pk_alg = GNUTLS_PK_MLDSA87;
            break;
        default:
            goto err;
    }

    msg_fd = open(msg_file, O_RDONLY);
    key_fd = open(key_file, O_RDONLY);
    time_fd = open(time_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);

    if (sig_file) {
        sig_fd = open(sig_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);
        if (sig_fd < 0) {
            fprintf(stderr, "Error opening signature output file: %s\n", strerror(errno));
            return 1;
        }
    }

    if (msg_fd < 0 || key_fd < 0 || time_fd < 0) {
        fprintf(stderr, "Error opening files: %s\n", strerror(errno));
        return 1;
    }

    if (expected_sig_file) {
        expected_sig_fd = open(expected_sig_file, O_RDONLY);
        if (expected_sig_fd < 0) {
            fprintf(stderr, "Error opening expected signature file: %s\n", strerror(errno));
            return 1;
        }
    }

    r_ret = gnutls_global_init();
    if (r_ret < 0) {
        fprintf(stderr, "gnutls_global_init failed: %s\n",
                gnutls_strerror(r_ret));
        goto err;
    }

    msg = malloc(msg_len);
    key_buf = malloc(key_len);
    if (!msg || !key_buf) {
        goto err;
    }

    snprintf(alg_name, sizeof(alg_name), "ML-DSA-%d", mldsa_level);

    fprintf(stderr, "Using %s\n", alg_name);
    fprintf(stderr, "Message length: %zu bytes\n", msg_len);
    fprintf(stderr, "Key length: %zu bytes\n", key_len);
    fprintf(stderr, "Signing...\n");

    while (1) {
        ssize_t k_ret = read(key_fd, key_buf, key_len);
        if (k_ret <= 0) {
            break;
        }
        if ((size_t)k_ret != key_len) {
            fprintf(stderr, "read less key than expected\n");
            goto err;
        }

        ssize_t m_ret = read(msg_fd, msg, msg_len);
        if (m_ret <= 0) {
            break;
        }
        if ((size_t)m_ret != msg_len) {
            fprintf(stderr, "read less data than expected\n");
            goto err;
        }

        if (pkey) {
            gnutls_privkey_deinit(pkey);
            pkey = NULL;
        }
        pkey = pkey_from_seed(mldsa_level, pk_alg, key_buf);
        if (!pkey) {
            fprintf(stderr, "pkey_from_seed() failed\n");
            goto err;
        }

        if (count == 0) {
            if (expected_sig_fd >= 0) {
                expected_sig = malloc(sig_cap);
                if (!expected_sig)
                    goto err;
            }
            fprintf(stderr, "malloc(sig) - size %zu\n", sig_cap);
        }

        msg_data.data = msg;
        msg_data.size = msg_len;

        sig_data.data = NULL;
        sig_data.size = 0;

        r_ret = gnutls_privkey_sign_data2(
            pkey,
            sig_alg,
            0,
            &msg_data,
            &sig_data
        );
        time_diff = gnutls_ml_dsa_last_core_cycles;

        if (r_ret < 0) {
            fprintf(stderr, "Signing failure: %s\n",
                    gnutls_strerror(r_ret));
            goto err;
        }

        sig_len = sig_data.size;

        if (expected_sig_fd >= 0) {
            ssize_t e_ret = read(expected_sig_fd, expected_sig, sig_cap);
            if (e_ret <= 0) {
                fprintf(stderr, "expected signature file ended early\n");
                goto err;
            }
            if ((size_t)e_ret != sig_cap) {
                fprintf(stderr, "read less expected signature than expected\n");
                goto err;
            }

            if (sig_len != sig_cap || memcmp(sig_data.data, expected_sig, sig_cap) != 0) {
                fprintf(stderr, "signature mismatch at sample %d\n", count);
                goto err;
            }
        }

        if (write(time_fd, &time_diff, sizeof(time_diff)) != (ssize_t)sizeof(time_diff)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (sig_fd >= 0) {
            if (write(sig_fd, sig_data.data, sig_len) != (ssize_t)sig_len) {
                fprintf(stderr, "Write signature error\n");
                goto err;
            }
        }

        gnutls_free(sig_data.data);
        sig_data.data = NULL;
        sig_data.size = 0;

        count++;
        if (count % 1000 == 0) {
            fprintf(stderr, "Processed %d samples...\n", count);
        }
    }

    result = 0;
    fprintf(stderr, "done (%d samples)\n", count);
    goto out;

err:
    fprintf(stderr, "failed!\n");
    result = 1;

out:
    free(msg);
    free(expected_sig);
    free(key_buf);

    if (sig_data.data)
        gnutls_free(sig_data.data);

    if (pkey)
        gnutls_privkey_deinit(pkey);

    if (msg_fd >= 0) close(msg_fd);
    if (key_fd >= 0) close(key_fd);
    if (sig_fd >= 0) close(sig_fd);
    if (expected_sig_fd >= 0) close(expected_sig_fd);
    if (time_fd >= 0) close(time_fd);

    gnutls_global_deinit();

    return result;
}
