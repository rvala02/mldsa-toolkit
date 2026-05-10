/*
 * After each successful sign, reads nss_ml_dsa_last_core_cycles (uint64_t) from
 * libfreebl: get_time_after() - get_time_before(), where time_before is taken at
 * the very start of the sign call (sign API entry), and time_after immediately
 * before signature encoding (pack_sig).
 *
 */

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

extern uint64_t nss_ml_dsa_last_core_cycles;

static void
help(const char *name)
{
    fprintf(stderr, "Usage: %s -i file -o file -t file -k file -n num [-s num] [-h]\n", name);  
    fprintf(stderr, "\n");
    fprintf(stderr, " -i file    File with concatenated messages to sign\n");
    fprintf(stderr, " -o file    File where to write the signatures\n");
    fprintf(stderr, " -t file    File where to write timing data\n");
    fprintf(stderr, " -k file    File with the ML-DSA private key in PEM format\n");
    fprintf(stderr, " -n num     Length of individual messages in bytes\n");
    fprintf(stderr, " -s num     ML-DSA parameter set: 44, 65, or 87 (default: 44)\n");
    fprintf(stderr, " -h         This message\n");
}

int
main(int argc, char *argv[])
{
    int result = 1, r_ret;
    size_t msg_len = 0;
    int mldsa_level = 44;

    char *in_file = NULL;
    char *out_file = NULL;
    char *time_file = NULL;
    char *key_file = NULL;

    int in_fd = -1, out_fd = -1, time_fd = -1;

    unsigned char *msg = NULL;
    unsigned char *sig_buf = NULL;

    SECKEYPrivateKey *pkey = NULL;
    FILE *fp = NULL;

    SECStatus rv;
    int opt;

    while ((opt = getopt(argc, argv, "i:o:t:k:n:s:h")) != -1) {
        switch (opt) {
        case 'i':
            in_file = optarg;
            break;
        case 'o':
            out_file = optarg;
            break;
        case 't':
            time_file = optarg;
            break;
        case 'k':
            key_file = optarg;
            break;
        case 'n':
            sscanf(optarg, "%zu", &msg_len);
            break;
        case 's':
            mldsa_level = atoi(optarg);
            break;
        case 'h':
            help(argv[0]);
            return 0;
        default:
            help(argv[0]);
            return 1;
        }
    }

    if (!in_file || !out_file || !time_file || !key_file || !msg_len) {
        fprintf(stderr, "Missing parameters!\n");
        help(argv[0]);
        return 1;
    }

    if (mldsa_level != 44 && mldsa_level != 65 && mldsa_level != 87) {
        fprintf(stderr,
                "Invalid ML-DSA parameter set: %d (use 44, 65, or 87)\n",
                mldsa_level);
        return 1;
    }

    in_fd = open(in_file, O_RDONLY);
    if (in_fd == -1) {
        fprintf(stderr, "can't open input file %s: %s\n", in_file,
                strerror(errno));
        goto err;
    }

    out_fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out_fd == -1) {
        fprintf(stderr, "can't open output file %s: %s\n", out_file,
                strerror(errno));
        goto err;
    }

    time_fd = open(time_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (time_fd == -1) {
        fprintf(stderr, "can't open timing file %s: %s\n", time_file,
                strerror(errno));
        goto err;
    }

    msg = malloc(msg_len);
    if (!msg)
        goto err;

    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS init failed\n");
        goto err;
    }

    fp = fopen(key_file, "r");
    if (!fp) {
        fprintf(stderr, "can't open key file %s: %s\n", key_file,
                strerror(errno));
        goto err;
    }

    pkey = read_PrivateKey(fp);
    if (fclose(fp) != 0)
        goto err;
    fp = NULL;

    if (!pkey) {
        fprintf(stderr, "Failed to load private key\n");
        goto err;
    }

    int sig_len = PK11_SignatureLen(pkey);
    if (sig_len <= 0) {
        fprintf(stderr, "Invalid signature length\n");
        goto err;
    }

    {
        int expected_sig_len = (mldsa_level == 44) ? ML_DSA_44_SIGNATURE_LEN :
                               (mldsa_level == 65) ? ML_DSA_65_SIGNATURE_LEN :
                                                    ML_DSA_87_SIGNATURE_LEN;
        if (sig_len != expected_sig_len) {
            fprintf(stderr,
                    "Private key does not match selected algorithm (ML-DSA-%d)\n",
                    mldsa_level);
            goto err;
        }
    }

    sig_buf = malloc(sig_len);
    if (!sig_buf)
        goto err;

    CK_SIGN_ADDITIONAL_CONTEXT sign_params;
    SECItem mech_param;

    memset(&sign_params, 0, sizeof(sign_params));
    sign_params.hedgeVariant = CKH_DETERMINISTIC_REQUIRED;
    sign_params.pContext = NULL;
    sign_params.ulContextLen = 0;

    mech_param.type = siBuffer;
    mech_param.data = (unsigned char *)&sign_params;
    mech_param.len = sizeof(sign_params);

    fprintf(stderr, "Using ML-DSA-%d (PK11 path, no_encode counter)\n",
            mldsa_level);
    fprintf(stderr, "Signing messages...\n");

    while ((r_ret = read(in_fd, msg, msg_len)) > 0) {

        if ((size_t)r_ret != msg_len) {
            fprintf(stderr, "read less data than expected\n");
            goto err;
        }

        SECItem data = { siBuffer, msg, (unsigned int)msg_len };
        SECItem sig = { siBuffer, sig_buf, (unsigned int)sig_len };

        rv = PK11_SignWithMechanism(pkey, CKM_ML_DSA, &mech_param, &sig,
                                    &data);

        if (rv != SECSuccess) {
            fprintf(stderr, "Signing failed\n");
            goto err;
        }

        uint64_t cycles = nss_ml_dsa_last_core_cycles;

        if (write(time_fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (write(out_fd, sig.data, sig.len) != (ssize_t)sig.len) {
            fprintf(stderr, "Write signature error\n");
            goto err;
        }
    }

    result = 0;
    fprintf(stderr, "finished\n");
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
    free(sig_buf);
    if (pkey) SECKEY_DestroyPrivateKey(pkey);
    if (in_fd >= 0) close(in_fd);
    if (out_fd >= 0) close(out_fd);
    if (time_fd >= 0) close(time_fd);
    if (fp) fclose(fp);
    NSS_Shutdown();

    return result;
}
