#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

extern uint64_t ossl_ml_dsa_last_core_cycles;

static void help(const char *name) {
    fprintf(stderr, "Usage: %s -i file -o file -t file -k file -n num [-h]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, " -i file    File with concatenated messages to sign\n");
    fprintf(stderr, " -o file    File where to write the signatures\n");
    fprintf(stderr, " -t file    File where to write timing data\n");
    fprintf(stderr, " -k file    File with concatenated raw ML-DSA private keys\n");
    fprintf(stderr, " -n num     Length of individual messages in bytes\n");
    fprintf(stderr, " -s num     ML-DSA parameter set: 44, 65, or 87 (default: 44)\n");
    fprintf(stderr, " -h         This message\n");
}

int main(int argc, char *argv[]) {
    int result = 1;
    int opt;

    char *msg_file = NULL;
    char *key_file = NULL;
    char *sig_file = NULL;
    char *time_file = NULL;

    size_t msg_len = 0;
    size_t key_len = 0;
    size_t sig_len = 0;
    size_t sig_cap = 0;
    int mldsa_level = 44;
    int r_ret;
    int count = 0;

    int msg_fd = -1, key_fd = -1, sig_fd = -1, time_fd = -1;

    unsigned char *msg = NULL;
    unsigned char *sig = NULL;
    unsigned char *key_buf = NULL;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;

    OSSL_PROVIDER *prov_default = NULL;

    uint64_t time_before, time_after, time_diff;

    int deterministic = 1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic),
        OSSL_PARAM_END
    };

    while ((opt = getopt(argc, argv, "i:k:o:t:n:s:h")) != -1) {
        switch (opt) {
            case 'i': msg_file = optarg; break;
            case 'k': key_file = optarg; break;
            case 'o': sig_file = optarg; break;
            case 't': time_file = optarg; break;
            case 'n': sscanf(optarg, "%zu", &msg_len); break;
            case 's': mldsa_level = atoi(optarg); break;
            case 'h': help(argv[0]); return 0;
            default: help(argv[0]); return 1;
        }
    }

    if (!msg_file || !key_file || !sig_file || !time_file || !msg_len) {
        help(argv[0]);
        return 1;
    }

    if (mldsa_level != 44 && mldsa_level != 65 && mldsa_level != 87) {
        fprintf(stderr, "Invalid ML-DSA level: %d\n", mldsa_level);
        return 1;
    }

    switch (mldsa_level) {
        case 44: key_len = 2560; break;
        case 65: key_len = 4032; break;
        case 87: key_len = 4896; break;
        default: key_len = 2560; break;
    }

    msg_fd = open(msg_file, O_RDONLY);
    key_fd = open(key_file, O_RDONLY);
    sig_fd = open(sig_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    time_fd = open(time_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);

    if (msg_fd < 0 || key_fd < 0 || sig_fd < 0 || time_fd < 0) {
        fprintf(stderr, "Error opening files: %s\n", strerror(errno));
        return 1;
    }

    prov_default = OSSL_PROVIDER_load(NULL, "default");
    if (!prov_default)
        goto err;

    msg = malloc(msg_len);
    key_buf = malloc(key_len);
    if (!msg || !key_buf) {
        goto err;
    }

    char alg_name[16];
    snprintf(alg_name, sizeof(alg_name), "ML-DSA-%d", mldsa_level);

    sig_alg = EVP_SIGNATURE_fetch(NULL, alg_name, NULL);
    if (!sig_alg) {
        fprintf(stderr, "EVP_SIGNATURE_fetch(%s) failed\n", alg_name);
        goto err;
    }

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

        ssize_t r_ret = read(msg_fd, msg, msg_len);
        if (r_ret <= 0) {
            break;
        }
        if ((ssize_t)r_ret != msg_len) {
            fprintf(stderr, "read less data than expected\n");
            goto err;
        }

        if (pkey) {
            EVP_PKEY_free(pkey);
        }
        pkey = EVP_PKEY_new_raw_private_key_ex(NULL, alg_name, NULL, key_buf, key_len);
        if (!pkey) {
            fprintf(stderr, "EVP_PKEY_new_raw_private_key_ex() failed\n");
            goto err;
        }

        if (sig_cap == 0) {
            sig_cap = EVP_PKEY_get_size(pkey);
            if (sig_cap == 0) {
                fprintf(stderr, "EVP_PKEY_get_size() failed or returned 0\n");
                goto err;
            }
            if (!EVP_PKEY_is_a(pkey, alg_name)) {
                fprintf(stderr,
                        "Private key does not match selected algorithm (%s)\n",
                        alg_name);
                goto err;
            }
            sig = malloc(sig_cap);
            if (!sig)
                goto err;
            fprintf(stderr, "malloc(sig) - size %zu\n", sig_cap);
        }

        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
        if (!ctx)
            goto err;

        if (EVP_PKEY_sign_message_init(ctx, sig_alg, params) <= 0)
            goto err;

        sig_len = sig_cap;

        r_ret = EVP_PKEY_sign(ctx, sig, &sig_len, msg, msg_len);
        time_diff = ossl_ml_dsa_last_core_cycles;

        if (r_ret <= 0) {
            fprintf(stderr, "Signing failure\n");
        }

        if (write(time_fd, &time_diff, sizeof(time_diff)) != (ssize_t)sizeof(time_diff)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (write(sig_fd, sig, sig_len) != (ssize_t)sig_len) {
            fprintf(stderr, "Write signature error\n");
            goto err;
        }

        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;

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
    ERR_print_errors_fp(stderr);
    result = 1;

out:
    free(msg);
    free(sig);
    free(key_buf);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_SIGNATURE_free(sig_alg);
    if (msg_fd >= 0) close(msg_fd);
    if (key_fd >= 0) close(key_fd);
    if (sig_fd >= 0) close(sig_fd);
    if (time_fd >= 0) close(time_fd);
    if (prov_default) OSSL_PROVIDER_unload(prov_default);

    return result;
}
