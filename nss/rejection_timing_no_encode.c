#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

#include <prerror.h>
#include <secerr.h>
#include <seccomon.h>
#include <pk11pub.h>
#include <keyhi.h>
#include <keythi.h>
#include <nss.h>

#include "readpem.h"

#define SEED_LEN 32

extern uint64_t nss_ml_dsa_last_core_cycles;

static void help(const char *name) {
    fprintf(stderr, "Usage: %s -i file -t file -k file -n num [-o file] [-e file] [-s num] [-h]\n", name);
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

static size_t get_signature_len(int mldsa_level)
{
    switch (mldsa_level) {
        case 44: return ML_DSA_44_SIGNATURE_LEN;
        case 65: return ML_DSA_65_SIGNATURE_LEN;
        case 87: return ML_DSA_87_SIGNATURE_LEN;
        default: return 0;
    }
}

int main(int argc, char *argv[])
{
    int result = 1;
    int opt;

    char *msg_file = NULL;
    char *key_file = NULL;
    char *sig_file = NULL;
    char *expected_sig_file = NULL;
    char *time_file = NULL;

    size_t msg_len = 0;
    size_t sig_len = 0;
    int mldsa_level = 44;
    int count = 0;

    int msg_fd = -1;
    int key_fd = -1;
    int sig_fd = -1;
    int expected_sig_fd = -1;
    int time_fd = -1;

    unsigned char *msg = NULL;
    unsigned char *seed_buf = NULL;
    unsigned char *sig_buf = NULL;
    unsigned char *expected_sig_buf = NULL;

    SECKEYPrivateKey *pkey = NULL;

    CK_SIGN_ADDITIONAL_CONTEXT sign_params;
    SECItem mech_param;

    uint64_t cycles;

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

    sig_len = get_signature_len(mldsa_level);

    if (sig_len == 0) {
        fprintf(stderr, "Invalid signature length\n");
        return 1;
    }

    msg_fd = open(msg_file, O_RDONLY);
    key_fd = open(key_file, O_RDONLY);
    time_fd = open(time_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);

    if (sig_file) {
        sig_fd = open(sig_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (sig_fd < 0) {
            fprintf(stderr, "Error opening signature output file: %s\n", strerror(errno));
            goto err;
        }
    }

    if (expected_sig_file) {
        expected_sig_fd = open(expected_sig_file, O_RDONLY);
        if (expected_sig_fd < 0) {
            fprintf(stderr, "Error opening expected signature file: %s\n", strerror(errno));
            goto err;
        }
    }

    if (msg_fd < 0 || key_fd < 0 || time_fd < 0) {
        fprintf(stderr, "Error opening files: %s\n", strerror(errno));
        goto err;
    }

    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS init failed\n");
        goto err;
    }

    msg = malloc(msg_len);
    seed_buf = malloc(SEED_LEN);
    sig_buf = malloc(sig_len);
    expected_sig_buf = malloc(sig_len);

    if (!msg || !seed_buf || !sig_buf || !expected_sig_buf)
        goto err;

    memset(&sign_params, 0, sizeof(sign_params));
    sign_params.hedgeVariant = CKH_DETERMINISTIC_REQUIRED;
    sign_params.pContext = NULL;
    sign_params.ulContextLen = 0;

    mech_param.type = siBuffer;
    mech_param.data = (unsigned char *)&sign_params;
    mech_param.len = sizeof(sign_params);

    fprintf(stderr, "Using ML-DSA-%d (rejection seeds, no_encode counter)\n", mldsa_level);
    fprintf(stderr, "Message length: %zu bytes\n", msg_len);
    fprintf(stderr, "Seed length: %d bytes\n", SEED_LEN);
    fprintf(stderr, "Signature length: %zu bytes\n", sig_len);
    fprintf(stderr, "Signing...\n");

    while (1) {
        ssize_t k_ret = read(key_fd, seed_buf, SEED_LEN);
        if (k_ret <= 0)
            break;
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

        if (pkey) {
            SECKEY_DestroyPrivateKey(pkey);
            pkey = NULL;
        }

        pkey = import_seed_PrivateKey(seed_buf, SEED_LEN, mldsa_level);

        if (!pkey) {
            fprintf(stderr, "import_seed_PrivateKey() failed\n");
            int errcode = PORT_GetError();
            if (errcode)
                fprintf(stderr, "%s (%d)\n", PORT_ErrorToString(errcode), errcode);
            goto err;
        }

        SECItem data = { siBuffer, msg, (unsigned int)msg_len };
        SECItem sig = { siBuffer, sig_buf, (unsigned int)sig_len };

        SECStatus rv = PK11_SignWithMechanism(
                pkey,
                CKM_ML_DSA,
                &mech_param,
                &sig,
                &data);

        if (rv != SECSuccess) {
            fprintf(stderr, "Signing failed\n");
            goto err;
        }

        cycles = nss_ml_dsa_last_core_cycles;

        if (expected_sig_fd >= 0) {
            ssize_t e_ret = read(expected_sig_fd, expected_sig_buf, sig_len);
            if (e_ret <= 0) {
                fprintf(stderr, "expected signature file ended early\n");
                goto err;
            }
            if ((size_t)e_ret != sig_len) {
                fprintf(stderr, "read less expected signature than expected\n");
                goto err;
            }

            if (sig.len != sig_len || memcmp(sig.data, expected_sig_buf, sig_len) != 0) {
                fprintf(stderr, "signature mismatch at sample %d\n", count);
                goto err;
            }
        }

        if (write(time_fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (sig_fd >= 0) {
            if (write(sig_fd, sig.data, sig.len) != (ssize_t)sig.len) {
                fprintf(stderr, "Write signature error\n");
                goto err;
            }
        }

        count++;
        if (count % 1000 == 0)
            fprintf(stderr, "Processed %d samples...\n", count);
    }

    result = 0;
    fprintf(stderr, "done (%d samples)\n", count);
    goto out;

err:
    fprintf(stderr, "failed!\n");
    {
        int errcode = PORT_GetError();
        if (errcode)
            fprintf(stderr, "%s (%d)\n", PORT_ErrorToString(errcode), errcode);
        else
            perror("libc");
    }

out:
    free(msg);
    free(seed_buf);
    free(sig_buf);
    free(expected_sig_buf);

    if (pkey)
        SECKEY_DestroyPrivateKey(pkey);
    if (msg_fd >= 0)
        close(msg_fd);
    if (key_fd >= 0)
        close(key_fd);
    if (sig_fd >= 0)
        close(sig_fd);
    if (expected_sig_fd >= 0)
        close(expected_sig_fd);
    if (time_fd >= 0)
        close(time_fd);

    NSS_Shutdown();

    return result;
}
