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

/* ================= timing ================= */

uint64_t get_time_before() {
    uint64_t time_before = 0;
#if defined( __s390x__ )
    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    time_before = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    asm volatile (
        "mftb    %0": "=r" (time_before) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_before) :: "memory", "cc");
#elif defined( __x86_64__ )
    uint32_t time_before_high = 0, time_before_low = 0;
    asm volatile (
        "CPUID\n\t"
        "RDTSC\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t" : "=r" (time_before_high),
        "=r" (time_before_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_before = (uint64_t)time_before_high<<32 | time_before_low;
#else
#error Unsupported architecture
#endif
    return time_before;
}

uint64_t get_time_after() {
    uint64_t time_after = 0;
#if defined( __s390x__ )
    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    time_after = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    asm volatile (
        "mftb    %0": "=r" (time_after) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_after) :: "memory", "cc");
#elif defined( __x86_64__ )
    uint32_t time_after_high = 0, time_after_low = 0;
    asm volatile (
        "RDTSCP\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t": "=r" (time_after_high),
        "=r" (time_after_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_after = (uint64_t)time_after_high<<32 | time_after_low;
#else
#error Unsupported architecture
#endif
    return time_after;
}

/* ================= CLI ================= */

static void help(const char *name) {
    fprintf(stderr, "Usage: %s -i file -o file -t file -k file -n num [-s num] [-h]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, " -i file    File with concatenated messages to sign\n");
    fprintf(stderr, " -o file    File where to write the signatures\n");
    fprintf(stderr, " -t file    File where to write timing data\n");
    fprintf(stderr, " -k file    File with concatenated raw ML-DSA private keys\n");
    fprintf(stderr, " -n num     Length of individual messages in bytes\n");
    fprintf(stderr, " -s num     ML-DSA parameter set: 44, 65, or 87 (default: 44)\n");
    fprintf(stderr, " -h         This message\n");
}

/* ================= main ================= */

int main(int argc, char *argv[]) {
    int result = 1;
    int opt;

    char *msg_file = NULL;
    char *key_file = NULL;
    char *sig_file = NULL;
    char *time_file = NULL;

    size_t msg_len = 0;
    size_t key_len = 0;
    int sig_len = 0;
    int mldsa_level = 44;
    int count = 0;

    int msg_fd = -1, key_fd = -1, sig_fd = -1, time_fd = -1;

    unsigned char *msg = NULL;
    unsigned char *sig_buf = NULL;
    unsigned char *key_buf = NULL;

    SECKEYPrivateKey *pkey = NULL;

    CK_SIGN_ADDITIONAL_CONTEXT sign_params;
    SECItem mech_param;

    uint64_t time_before, time_after, time_diff;

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
        case 44: key_len = ML_DSA_44_PRIVATEKEY_LEN; break;
        case 65: key_len = ML_DSA_65_PRIVATEKEY_LEN; break;
        case 87: key_len = ML_DSA_87_PRIVATEKEY_LEN; break;
    }

    msg_fd = open(msg_file, O_RDONLY);
    key_fd = open(key_file, O_RDONLY);
    sig_fd = open(sig_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    time_fd = open(time_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);

    if (msg_fd < 0 || key_fd < 0 || sig_fd < 0 || time_fd < 0) {
        fprintf(stderr, "Error opening files: %s\n", strerror(errno));
        goto err;
    }

    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS init failed\n");
        goto err;
    }

    msg = malloc(msg_len);
    key_buf = malloc(key_len);
    if (!msg || !key_buf)
        goto err;

    memset(&sign_params, 0, sizeof(sign_params));
    sign_params.hedgeVariant = CKH_DETERMINISTIC_REQUIRED;
    sign_params.pContext = NULL;
    sign_params.ulContextLen = 0;

    mech_param.type = siBuffer;
    mech_param.data = (unsigned char *)&sign_params;
    mech_param.len = sizeof(sign_params);

    fprintf(stderr, "Using ML-DSA-%d\n", mldsa_level);
    fprintf(stderr, "Message length: %zu bytes\n", msg_len);
    fprintf(stderr, "Key length: %zu bytes\n", key_len);
    fprintf(stderr, "Signing...\n");

    while (1) {
        ssize_t k_ret = read(key_fd, key_buf, key_len);
        if (k_ret <= 0)
            break;
        if ((size_t)k_ret != key_len) {
            fprintf(stderr, "read less key than expected\n");
            goto err;
        }

        ssize_t r_ret = read(msg_fd, msg, msg_len);
        if (r_ret <= 0)
            break;
        if ((size_t)r_ret != msg_len) {
            fprintf(stderr, "read less data than expected\n");
            goto err;
        }

        if (pkey) {
            SECKEY_DestroyPrivateKey(pkey);
            pkey = NULL;
        }

        pkey = import_raw_PrivateKey(key_buf, key_len, mldsa_level);
        if (!pkey) {
            fprintf(stderr, "import_raw_PrivateKey() failed\n");
            int errcode = PORT_GetError();
            if (errcode)
                fprintf(stderr, "%s (%d)\n", PORT_ErrorToString(errcode), errcode);
            goto err;
        }

        if (sig_len == 0) {
            sig_len = PK11_SignatureLen(pkey);
            if (sig_len <= 0) {
                fprintf(stderr, "PK11_SignatureLen() failed\n");
                goto err;
            }
            sig_buf = malloc(sig_len);
            if (!sig_buf)
                goto err;
            fprintf(stderr, "Signature length: %d bytes\n", sig_len);
        }

        SECItem data = { siBuffer, msg,     (unsigned int)msg_len };
        SECItem sig  = { siBuffer, sig_buf, (unsigned int)sig_len };

        time_before = get_time_before();

        SECStatus rv = PK11_SignWithMechanism(
                pkey,
                CKM_ML_DSA,
                &mech_param,
                &sig,
                &data);

        time_after = get_time_after();

        if (rv != SECSuccess) {
            fprintf(stderr, "Signing failed\n");
            goto err;
        }

        time_diff = time_after - time_before;

        if (write(time_fd, &time_diff, sizeof(time_diff)) != (ssize_t)sizeof(time_diff)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (write(sig_fd, sig.data, sig.len) != (ssize_t)sig.len) {
            fprintf(stderr, "Write signature error\n");
            goto err;
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
    int errcode = PORT_GetError();
    if (errcode)
        fprintf(stderr, "%s (%d)\n", PORT_ErrorToString(errcode), errcode);
    else
        perror("libc");

out:
    free(msg);
    free(sig_buf);
    free(key_buf);
    if (pkey) SECKEY_DestroyPrivateKey(pkey);
    if (msg_fd >= 0) close(msg_fd);
    if (key_fd >= 0) close(key_fd);
    if (sig_fd >= 0) close(sig_fd);
    if (time_fd >= 0) close(time_fd);
    NSS_Shutdown();

    return result;
}
