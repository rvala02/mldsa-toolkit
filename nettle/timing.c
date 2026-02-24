#include <memory.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <nettle/base64.h>
#include <nettle/ml-dsa.h>

#define DER_HEADER_SIZE 66

static void help(const char *name) {
    fprintf(stderr, "Usage: %s -i file -o file -t file -k file -n num [-h]\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, " -i file    File with concatenated messages to sign\n");
    fprintf(stderr, " -o file    File where to write the signatures\n");
    fprintf(stderr, " -t file    File where to write timing data\n");
    fprintf(stderr, " -k file    File with the ML-DSA private key in PEM format\n");
    fprintf(stderr, " -n num     Length of individual messages in bytes\n");
    fprintf(stderr, " -s num     ML-DSA parameter set: 65 or 87 (default: 65)\n");
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

static bool pem_read_privkey(FILE *fp, uint8_t **data, size_t size)
{
    uint8_t *buffer;
    char *p;
    size_t cap = ((DER_HEADER_SIZE + size) / 3) * 4 + 1 /*NUL*/;

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

    struct base64_decode_ctx decode;
    size_t done;
    base64_decode_init(&decode);
    base64_decode_update(&decode, &done, buffer,
                         strlen((char *)buffer), (const char *)buffer);
    base64_decode_final(&decode);
    if (done != DER_HEADER_SIZE + size) {
        free(buffer);
        return false;
    }

    memmove(buffer, buffer + (done - size), size);
    *data = buffer;
    return true;
}

int main(int argc, char *argv[]) {
    int result = 1;
    int r_ret;

    size_t key_len = 0;
    size_t msg_len = 0;
    size_t sig_len = 0;

    int mldsa_level = 65; /* default: ML-DSA-65 */
    const char *alg_name;
    sign_func *sign;

    FILE *fp = NULL;

    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL, *time_file_name = NULL;
    int in_fd = -1, out_fd = -1, time_fd = -1;

    unsigned char *key = NULL;
    unsigned char *msg = NULL;
    unsigned char *sig = NULL;

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

    if (mldsa_level != 65 && mldsa_level != 87) {
        fprintf(stderr,
                "Invalid ML-DSA parameter set: %d (use 65 or 87)\n",
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

    /* Signature algorithm */
    switch (mldsa_level) {
    case 65:
        alg_name = "ML-DSA-65";
        sign = ml_dsa_65_sign;
        key_len = ML_DSA_65_PRIVATE_KEY_SIZE;
        sig_len = ML_DSA_65_SIGNATURE_SIZE;
        break;
    case 87:
        alg_name = "ML-DSA-87";
        sign = ml_dsa_87_sign;
        key_len = ML_DSA_87_PRIVATE_KEY_SIZE;
        sig_len = ML_DSA_87_SIGNATURE_SIZE;
        break;
    default:
        assert(0);
        goto err;
    }

    /* Load key (PEM format) */
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

    fprintf(stderr, "Using %s\n", alg_name);
    fprintf(stderr, "Signing messages...\n");

    fprintf(stderr, "malloc(sig) - size %zu\n", sig_len);
    sig = malloc(sig_len);
    if (!sig)
        goto err;

    while((r_ret = read(in_fd, msg, msg_len)) > 0) {
        if ((size_t)r_ret != msg_len) {
            fprintf(stderr, "read less data than expected\n");
            goto err;
        }

        time_before = get_time_before();
        sign(key,
             msg_len, msg,
             0 /*ctx_len*/, NULL /*ctx*/,
             NULL /*random_ctx*/, random_zero /*random*/,
             sig);
        time_after = get_time_after();

        time_diff = time_after - time_before;

        if (write(time_fd, &time_diff, sizeof(time_diff)) != (ssize_t)sizeof(time_diff)) {
            fprintf(stderr, "Write timing error\n");
            goto err;
        }

        if (write(out_fd, sig, sig_len) != (ssize_t)sig_len) {
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
    free(sig);
    if (in_fd >=0) close(in_fd);
    if (out_fd >=0) close(out_fd);
    if (time_fd >=0) close(time_fd);
    if (fp) fclose(fp);

    return result;
}
