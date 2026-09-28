#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

#include "lc_dilithium.h"

extern volatile uint64_t lc_ml_dsa_last_core_cycles;

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
    size_t sig_cap = 0;
    int mldsa_level = 44;
    int count = 0;

    enum lc_dilithium_type dilithium_type;

    int msg_fd = -1, key_fd = -1, sig_fd = -1, time_fd = -1;
    int expected_sig_fd = -1;

    unsigned char *msg = NULL;
    unsigned char *expected_sig = NULL;
    unsigned char *key_buf = NULL;

    struct lc_dilithium_pk pk;
    struct lc_dilithium_sk sk;
    struct lc_dilithium_sig sig;

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

    switch (mldsa_level) {
        case 44: dilithium_type = LC_DILITHIUM_44; break;
        case 65: dilithium_type = LC_DILITHIUM_65; break;
        case 87: dilithium_type = LC_DILITHIUM_87; break;
        default:
            fprintf(stderr, "Invalid ML-DSA level: %d\n", mldsa_level);
            return 1;
    }

    key_len = SEED_LEN;
    sig_cap = lc_dilithium_sig_size(dilithium_type);
    if (sig_cap == 0) {
        fprintf(stderr, "lc_dilithium_sig_size() returned 0\n");
        return 1;
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

    msg = malloc(msg_len);
    key_buf = malloc(key_len);
    if (!msg || !key_buf) {
        goto err;
    }

    if (expected_sig_fd >= 0) {
        expected_sig = malloc(sig_cap);
        if (!expected_sig)
            goto err;
    }

    fprintf(stderr, "Using ML-DSA-%d\n", mldsa_level);
    fprintf(stderr, "Message length: %zu bytes\n", msg_len);
    fprintf(stderr, "Key length: %zu bytes\n", key_len);
    fprintf(stderr, "malloc(sig) - size %zu\n", sig_cap);
    fprintf(stderr, "Signing...\n");

    while (1) {
        uint8_t *sig_ptr;
        size_t sig_len;
        int r_ret;

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

        if (lc_dilithium_keypair_from_seed(&pk, &sk, key_buf, key_len,
                                           dilithium_type)) {
            fprintf(stderr, "lc_dilithium_keypair_from_seed() failed\n");
            goto err;
        }

        r_ret = lc_dilithium_sign(&sig, msg, msg_len, &sk, NULL);
        time_diff = lc_ml_dsa_last_core_cycles;

        if (r_ret) {
            fprintf(stderr, "Signing failure\n");
            goto err;
        }

        if (lc_dilithium_sig_ptr(&sig_ptr, &sig_len, &sig)) {
            fprintf(stderr, "failed to obtain signature pointer\n");
            goto err;
        }

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

            if (sig_len != sig_cap || memcmp(sig_ptr, expected_sig, sig_cap) != 0) {
                fprintf(stderr, "signature mismatch at sample %d\n", count);
                goto err;
            }
        }

        if (write(time_fd, &time_diff, sizeof(time_diff)) != (ssize_t)sizeof(time_diff)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (sig_fd >= 0) {
            if (write(sig_fd, sig_ptr, sig_len) != (ssize_t)sig_len) {
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
    free(expected_sig);
    free(key_buf);
    if (msg_fd >= 0) close(msg_fd);
    if (key_fd >= 0) close(key_fd);
    if (sig_fd >= 0) close(sig_fd);
    if (expected_sig_fd >= 0) close(expected_sig_fd);
    if (time_fd >= 0) close(time_fd);

    return result;
}
