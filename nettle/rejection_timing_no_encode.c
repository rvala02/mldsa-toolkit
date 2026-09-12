#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <nettle/base64.h>
#include <nettle/ml-dsa.h>

#define SEED_LEN 32

extern uint64_t nettle_ml_dsa_last_core_cycles;

static void help(const char *name) {
    fprintf(stderr, "Usage: %s -i file -t file -k file -n num [-o file] [-e file] [-s num] [-h]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, " -i file    File with concatenated messages to sign\n");
    fprintf(stderr, " -o file    File where to write the signatures (optional)\n");
    fprintf(stderr, " -t file    File where to write timing data\n");
    fprintf(stderr, " -k file    File with concatenated 32-byte ML-DSA key seeds\n");
    fprintf(stderr, " -e file    File with expected deterministic signatures (optional)\n");
    fprintf(stderr, " -n num     Length of individual messages in bytes\n");
    fprintf(stderr, " -s num     ML-DSA parameter set: 65 or 87 (default: 65)\n");
    fprintf(stderr, " -h         This message\n");
}

typedef void keygen_func (uint8_t *pub,
                          uint8_t *key,
                          void *random_ctx,
                          nettle_random_func *random);

typedef void sign_func (const uint8_t *key,
                        size_t msg_len, const uint8_t *msg,
                        size_t ctx_len, const uint8_t *ctx,
                        void *random_ctx, nettle_random_func *random,
                        uint8_t *signature);

static void
random_zero(void *ctx, size_t n, uint8_t *dst)
{
    memset(dst, 0, n);
}

struct seed_random_ctx {
    const uint8_t *seed;
    size_t offset;
};

static void
random_seed(void *ctx, size_t n, uint8_t *dst)
{
    struct seed_random_ctx *seed_ctx = ctx;

    if (seed_ctx->offset + n > SEED_LEN) {
        fprintf(stderr, "seed random requested too many bytes\n");
        abort();
    }

    memcpy(dst, seed_ctx->seed + seed_ctx->offset, n);
    seed_ctx->offset += n;
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
    size_t pub_key_len = 0;
    size_t priv_key_len = 0;
    size_t sig_len = 0;

    int mldsa_level = 65;
    const char *alg_name = NULL;
    keygen_func *keygen = NULL;
    sign_func *sign = NULL;
    int count = 0;

    int msg_fd = -1;
    int key_fd = -1;
    int sig_fd = -1;
    int expected_sig_fd = -1;
    int time_fd = -1;

    unsigned char *msg = NULL;
    unsigned char *sig = NULL;
    unsigned char *expected_sig = NULL;
    unsigned char *seed_buf = NULL;
    unsigned char *pub_buf = NULL;
    unsigned char *key_buf = NULL;

    uint64_t time_diff;

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

    if (mldsa_level != 65 && mldsa_level != 87) {
        fprintf(stderr, "Invalid ML-DSA level: %d\n", mldsa_level);
        return 1;
    }

    switch (mldsa_level) {
    case 65:
        alg_name = "ML-DSA-65";
        keygen = ml_dsa_65_generate_keypair;
        sign = ml_dsa_65_sign;
        pub_key_len = ML_DSA_65_PUBLIC_KEY_SIZE;
        priv_key_len = ML_DSA_65_PRIVATE_KEY_SIZE;
        sig_len = ML_DSA_65_SIGNATURE_SIZE;
        break;
    case 87:
        alg_name = "ML-DSA-87";
        keygen = ml_dsa_87_generate_keypair;
        sign = ml_dsa_87_sign;
        pub_key_len = ML_DSA_87_PUBLIC_KEY_SIZE;
        priv_key_len = ML_DSA_87_PRIVATE_KEY_SIZE;
        sig_len = ML_DSA_87_SIGNATURE_SIZE;
        break;
    default:
        assert(0);
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

    if (expected_sig_file) {
        expected_sig_fd = open(expected_sig_file, O_RDONLY);
        if (expected_sig_fd < 0) {
            fprintf(stderr, "Error opening expected signature file: %s\n", strerror(errno));
            return 1;
        }
    }

    if (msg_fd < 0 || key_fd < 0 || time_fd < 0) {
        fprintf(stderr, "Error opening files: %s\n", strerror(errno));
        return 1;
    }

    msg = malloc(msg_len);
    sig = malloc(sig_len);
    expected_sig = malloc(sig_len);
    seed_buf = malloc(SEED_LEN);
    pub_buf = malloc(pub_key_len);
    key_buf = malloc(priv_key_len);

    if (!msg || !sig || !expected_sig || !seed_buf || !pub_buf || !key_buf) {
        goto err;
    }

    fprintf(stderr, "Using %s\n", alg_name);
    fprintf(stderr, "Message length: %zu bytes\n", msg_len);
    fprintf(stderr, "Seed length: %d bytes\n", SEED_LEN);
    fprintf(stderr, "Private key length: %zu bytes\n", priv_key_len);
    fprintf(stderr, "Signature length: %zu bytes\n", sig_len);
    fprintf(stderr, "Timing: nettle_ml_dsa_last_core_cycles (no_encode)\n");
    fprintf(stderr, "Signing...\n");

    while (1) {
        ssize_t k_ret = read(key_fd, seed_buf, SEED_LEN);
        if (k_ret <= 0) {
            break;
        }
        if ((size_t)k_ret != SEED_LEN) {
            fprintf(stderr, "read less seed than expected\n");
            goto err;
        }

        ssize_t r_ret = read(msg_fd, msg, msg_len);
        if (r_ret <= 0) {
            fprintf(stderr, "more seeds than messages\n");
            goto err;
        }
        if ((size_t)r_ret != msg_len) {
            fprintf(stderr, "read less data than expected\n");
            goto err;
        }

        struct seed_random_ctx seed_ctx = {
            .seed = seed_buf,
            .offset = 0,
        };

        keygen(pub_buf, key_buf, &seed_ctx, random_seed);

        sign(key_buf,
             msg_len, msg,
             0 /*ctx_len*/, NULL /*ctx*/,
             NULL /*random_ctx*/, random_zero /*random*/,
             sig);

        time_diff = nettle_ml_dsa_last_core_cycles;

        if (expected_sig_fd >= 0) {
            ssize_t e_ret = read(expected_sig_fd, expected_sig, sig_len);
            if (e_ret <= 0) {
                fprintf(stderr, "expected signature file ended early\n");
                goto err;
            }
            if ((size_t)e_ret != sig_len) {
                fprintf(stderr, "read less expected signature than expected\n");
                goto err;
            }

            if (memcmp(sig, expected_sig, sig_len) != 0) {
                fprintf(stderr, "signature mismatch at sample %d\n", count);
                goto err;
            }
        }

        if (write(time_fd, &time_diff, sizeof(time_diff)) != (ssize_t)sizeof(time_diff)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (sig_fd >= 0) {
            if (write(sig_fd, sig, sig_len) != (ssize_t)sig_len) {
                fprintf(stderr, "Write signature error\n");
                goto err;
            }
        }

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
    free(sig);
    free(expected_sig);
    free(seed_buf);
    free(pub_buf);
    free(key_buf);

    if (msg_fd >= 0) close(msg_fd);
    if (key_fd >= 0) close(key_fd);
    if (sig_fd >= 0) close(sig_fd);
    if (expected_sig_fd >= 0) close(expected_sig_fd);
    if (time_fd >= 0) close(time_fd);

    return result;
}
