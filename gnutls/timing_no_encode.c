/*
 * After each sign call, reads gnutls_ml_dsa_last_core_cycles from libgnutls:
 * get_time_after() - get_time_before(), where time_before is taken at
 * gnutls_privkey_sign_data2() entry and time_after immediately before
 * signature encoding (pack_sig).
 */

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

extern uint64_t gnutls_ml_dsa_last_core_cycles;

static void help(const char *name) {
    fprintf(stderr, "Usage: %s -i file -o file -t file -k file -n num [-h]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, " -i file    File with concatenated messages to sign\n");
    fprintf(stderr, " -o file    File where to write the signatures\n");
    fprintf(stderr, " -t file    File where to write timing data\n");
    fprintf(stderr, " -k file    File with the ML-DSA private key in PEM format\n");
    fprintf(stderr, " -n num     Length of individual messages in bytes\n");
    fprintf(stderr, " -s num     ML-DSA parameter set: 44, 65, or 87 (default: 44)\n");
    fprintf(stderr, " -h         This message\n");
}

int main(int argc, char *argv[]) {
    int result = 1;
    int r_ret;

    gnutls_privkey_t pkey = NULL;
    gnutls_sign_algorithm_t sig_alg;
    gnutls_pk_algorithm_t pk_alg;
    gnutls_datum_t key_data = { NULL, 0 };
    gnutls_datum_t msg_data = { NULL, 0 };
    gnutls_datum_t sig_data = { NULL, 0 };

    size_t msg_len = 0;
    size_t sig_len = 0;

    int mldsa_level = 44; /* default: ML-DSA-44 */

    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL, *time_file_name = NULL;
    int in_fd = -1, out_fd = -1, time_fd = -1;

    unsigned char *msg = NULL;

    int opt;
    uint64_t time_diff;

    char alg_name[16];

    while ((opt=getopt(argc, argv, "i:o:t:k:n:s:h")) != -1) {
        switch (opt) {
            case 'i': in_file_name = optarg; break;
            case 'o': out_file_name = optarg; break;
            case 't': time_file_name = optarg; break;
            case 'k': key_file_name = optarg; break;
            case 'n': sscanf(optarg, "%zu", &msg_len); break;
            case 's': mldsa_level = atoi(optarg); break;
            case 'h': help(argv[0]); return 0;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                help(argv[0]);
                return 1;
        }
    }

    if (!in_file_name || !out_file_name || !time_file_name || !key_file_name || !msg_len) {
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

    /* Open files */
    in_fd = open(in_file_name, O_RDONLY);
    if (in_fd == -1) {
        fprintf(stderr, "can't open input file %s: %s\n", in_file_name, strerror(errno));
        goto err;
    }

    out_fd = open(out_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (out_fd == -1){
        fprintf(stderr, "can't open output file %s: %s\n", out_file_name, strerror(errno));
        goto err;
    }

    time_fd = open(time_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (time_fd == -1){
        fprintf(stderr, "can't open timing file %s: %s\n", time_file_name, strerror(errno));
        goto err;
    }

    r_ret = gnutls_global_init();
    if (r_ret < 0) {
        fprintf(stderr, "gnutls_global_init failed: %s\n",
                gnutls_strerror(r_ret));
        goto err;
    }

    /* Allocate message buffer */
    fprintf(stderr, "malloc(msg) - size %zu\n", msg_len);
    msg = malloc(msg_len);
    if (!msg)
        goto err;

    /* Load key (PEM format) */
    r_ret = gnutls_load_file(key_file_name, &key_data);
    if (r_ret < 0) {
        fprintf(stderr, "can't open key file %s: %s\n",
                key_file_name, gnutls_strerror(r_ret));
        goto err;
    }

    r_ret = gnutls_privkey_init(&pkey);
    if (r_ret < 0) {
        fprintf(stderr, "gnutls_privkey_init failed: %s\n",
                gnutls_strerror(r_ret));
        goto err;
    }

    r_ret = gnutls_privkey_import_x509_raw(
        pkey,
        &key_data,
        GNUTLS_X509_FMT_PEM,
        NULL,
        0
    );
    if (r_ret < 0) {
        fprintf(stderr, "gnutls_privkey_import_x509_raw failed: %s\n",
                gnutls_strerror(r_ret));
        goto err;
    }

    /* Signature algorithm */
    snprintf(alg_name, sizeof(alg_name), "ML-DSA-%d", mldsa_level);

    switch (mldsa_level) {
        case 44:
            sig_alg = GNUTLS_SIGN_MLDSA44;
            pk_alg = GNUTLS_PK_MLDSA44;
            break;
        case 65:
            sig_alg = GNUTLS_SIGN_MLDSA65;
            pk_alg = GNUTLS_PK_MLDSA65;
            break;
        case 87:
            sig_alg = GNUTLS_SIGN_MLDSA87;
            pk_alg = GNUTLS_PK_MLDSA87;
            break;
        default:
            goto err;
    }

    if (gnutls_privkey_get_pk_algorithm(pkey, NULL) != pk_alg) {
        fprintf(stderr,
                "Private key does not match selected algorithm (%s)\n",
                alg_name);
        goto err;
    }

    fprintf(stderr, "Using %s\n", alg_name);
    fprintf(stderr, "Signing messages...\n");

    while((r_ret = read(in_fd, msg, msg_len)) > 0) {
        if ((size_t)r_ret != msg_len) {
            fprintf(stderr, "read less data than expected\n");
            goto err;
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

        if (write(time_fd, &time_diff, sizeof(time_diff)) != (ssize_t)sizeof(time_diff)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (write(out_fd, sig_data.data, sig_len) != (ssize_t)sig_len) {
            fprintf(stderr, "Write signature error\n");
            goto err;
        }

        gnutls_free(sig_data.data);
        sig_data.data = NULL;
        sig_data.size = 0;
    }

    result = 0;
    fprintf(stderr, "finished\n");
    goto out;

err:
    fprintf(stderr, "failed!\n");
    result = 1;

out:
    free(msg);

    if (sig_data.data)
        gnutls_free(sig_data.data);

    if (key_data.data)
        gnutls_free(key_data.data);

    if (pkey)
        gnutls_privkey_deinit(pkey);

    if (in_fd >=0) close(in_fd);
    if (out_fd >=0) close(out_fd);
    if (time_fd >=0) close(time_fd);

    gnutls_global_deinit();

    return result;
}
