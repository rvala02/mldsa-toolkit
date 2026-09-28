#include <memory.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

#include "lc_dilithium.h"

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

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool pem_read_privkey(FILE *fp, uint8_t **data, size_t size)
{
    uint8_t *buffer;
    char *p;
    /* Generous upper bound for the concatenated base64 text. */
    size_t cap = size * 2 + 4096;

    buffer = malloc(cap);
    if (!buffer)
        return false;
    p = (char *)buffer;

    for (;;) {
        char line[256], *nl;

        if (fgets(line, sizeof(line), fp) == NULL)
            break;
        if (strspn(line, " \t\n") == strlen(line) ||
            strstr(line, "-----BEGIN ") || strstr(line, "-----END "))
            continue;

        nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        p = stpcpy(p, line);
    }

    {
        uint8_t *in = buffer, *out = buffer;
        uint32_t acc = 0;
        int bits = 0;
        size_t decoded;

        for (; *in && *in != '='; in++) {
            int v = b64_val((char)*in);

            if (v < 0)
                continue;
            acc = (acc << 6) | (uint32_t)v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                *out++ = (uint8_t)(acc >> bits);
            }
        }

        decoded = (size_t)(out - buffer);
        if (decoded < size) {
            free(buffer);
            return false;
        }

        memmove(buffer, out - size, size);
    }

    *data = buffer;
    return true;
}

int main(int argc, char *argv[]) {
    int result = 1;
    int r_ret;

    struct lc_dilithium_sk sk;
    struct lc_dilithium_sig sig;

    size_t key_len = 0;
    size_t msg_len = 0;

    int mldsa_level = 44; /* default: ML-DSA-44 */
    enum lc_dilithium_type dilithium_type;

    FILE *fp = NULL;

    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL, *time_file_name = NULL;
    int in_fd = -1, out_fd = -1, time_fd = -1;

    unsigned char *key = NULL;
    unsigned char *msg = NULL;

    int opt;
    uint64_t time_before, time_after, time_diff;

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

    switch (mldsa_level) {
        case 44: dilithium_type = LC_DILITHIUM_44; break;
        case 65: dilithium_type = LC_DILITHIUM_65; break;
        case 87: dilithium_type = LC_DILITHIUM_87; break;
        default:
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

    /* Allocate message buffer */
    fprintf(stderr, "malloc(msg) - size %zu\n", msg_len);
    msg = malloc(msg_len);
    if (!msg)
        goto err;

    /* Load key (PEM format) */
    key_len = lc_dilithium_sk_size(dilithium_type);

    fp = fopen(key_file_name, "r");
    if (!fp) {
        fprintf(stderr, "can't open key file %s\n", key_file_name);
        goto err;
    }

    if (!pem_read_privkey(fp, &key, key_len)) {
        fprintf(stderr, "can't read key file %s\n", key_file_name);
        goto err;
    }

    if (fclose(fp) != 0)
        goto err;
    fp = NULL;

    if (lc_dilithium_sk_load(&sk, key, key_len)) {
        fprintf(stderr, "lc_dilithium_sk_load failed (bad key file?)\n");
        goto err;
    }

    fprintf(stderr, "Using ML-DSA-%d\n", mldsa_level);
    fprintf(stderr, "Signing messages...\n");

    while((r_ret = read(in_fd, msg, msg_len)) > 0) {
        uint8_t *sig_ptr;
        size_t sig_len;

        if ((size_t)r_ret != msg_len) {
            fprintf(stderr, "read less data than expected\n");
            goto err;
        }

        time_before = get_time_before();
        r_ret = lc_dilithium_sign(&sig, msg, msg_len, &sk, NULL);
        time_after = get_time_after();

        if (r_ret) {
            fprintf(stderr, "Signing failure\n");
            goto err;
        }

        if (lc_dilithium_sig_ptr(&sig_ptr, &sig_len, &sig)) {
            fprintf(stderr, "failed to obtain signature pointer\n");
            goto err;
        }

        time_diff = time_after - time_before;

        if (write(time_fd, &time_diff, sizeof(time_diff)) != (ssize_t)sizeof(time_diff)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (write(out_fd, sig_ptr, sig_len) != (ssize_t)sig_len) {
            fprintf(stderr, "Write signature error\n");
            goto err;
        }
    }

    result = 0;
    fprintf(stderr, "finished\n");
    goto out;

err:
    fprintf(stderr, "failed!\n");
    result = 1;

out:
    free(key);
    free(msg);
    if (in_fd >=0) close(in_fd);
    if (out_fd >=0) close(out_fd);
    if (time_fd >=0) close(time_fd);
    if (fp) fclose(fp);

    return result;
}
