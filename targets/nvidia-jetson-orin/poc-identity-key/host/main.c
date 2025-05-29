#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>
#include <ta_indentity_key_poc.h>

#include <openssl/ecdsa.h>
#include <openssl/bn.h>

static void pri_buf_hex_format(const char *title,
                               const unsigned char *buf,
                               size_t buf_len)
{
    int rowLen = 0, rowMaxLen = 16, i = 0;
    char hexstr[rowMaxLen*4+1];
    char hex[4];

    if (buf == NULL) {
        printf("pri_buf_hex_format: NULL");
        return;
    }

    memset(hexstr, 0, rowMaxLen);

    if (title != NULL) {
        printf("%s [%lu]\n", title, buf_len);
    }

    for (i = 0; i < buf_len; ++i) {
        sprintf(hex, "%02X ", buf[i]);
        strncat(hexstr, hex, 4);
        rowLen++;
        if (rowLen == rowMaxLen) {
            strcat(hexstr, "\n");
            printf("%s", hexstr);
            memset(hexstr, 0, rowMaxLen);
            rowLen = 0;
        }
    }

    if ((buf_len % rowMaxLen) != 0) {
        strncat(hexstr, "\n", 2);
        printf("%s", hexstr);
    }
}

static int conv_sig_raw2der(uint8_t *sig, size_t sig_len,
                            uint8_t **der_sig, size_t *der_sig_len)
{
    ECDSA_SIG *sign_obj = NULL;
    BIGNUM *r = NULL, *s = NULL;
    unsigned char *openssl_sig_der_buf = NULL;
    size_t openssl_sig_der_buf_len = 0;
    int rv = 1;

    if (sig_len != 96) {
        printf("Function hardcoded\n");
        goto out;
    }

    sign_obj = ECDSA_SIG_new();
    if (sign_obj == NULL) {
        printf("ECDSA_SIG_new NULL\n");
        goto out;
    }

    r = BN_bin2bn(sig, 48, NULL);
    s = BN_bin2bn((sig+48), 48, NULL);
    if (s == NULL || r == NULL) {
        printf("BN_bin2bn failed: s[%p]; r[%p]\n", s, r);
        goto out;
    }

    // NOTE: ECDSA_SIG_set0 returns failure only if r or s NULL!
    // Also ECDSA_SIG_set0 function takes ownership of r and s
    if (ECDSA_SIG_set0(sign_obj, r, s) == 0) {
        printf("ECDSA_SIG_set0 failed\n");
        goto out;
    }

    s = NULL;
    r = NULL;

    openssl_sig_der_buf_len = i2d_ECDSA_SIG(sign_obj, &openssl_sig_der_buf);
    if (openssl_sig_der_buf_len < 0) {
        printf("i2d_ECDSA_SIG failed\n");
        goto out;
    }

    *der_sig = malloc(openssl_sig_der_buf_len);
    if (*der_sig == NULL) {
        printf("Malloc failed\n");
        goto out;
    }

    memcpy(*der_sig, openssl_sig_der_buf, openssl_sig_der_buf_len);
    *der_sig_len = openssl_sig_der_buf_len;
    rv = 0; // SUCCESS

out:
    BN_free(s);
    BN_free(r);
    ECDSA_SIG_free(sign_obj);
    OPENSSL_free(openssl_sig_der_buf);
    return rv;
}

static int read_bin_file(char *name, uint8_t **buffer, size_t *buffer_len)
{
    FILE *fptr = NULL;
    size_t frv = 0;
    long ftell_rv = 0;
    int rv = 1;

    printf("\nReading file [%s]\n", name);

    fptr = fopen(name, "rb");
    if (fptr == NULL) {
        printf("fopen failed: name[%s]\n", name);
        goto out;
    }

    if (fseek(fptr, 0L, SEEK_END) != 0) {
        printf("fseek SEEL_END failed\n");
        goto out;
    }

    ftell_rv = ftell(fptr);
    if (ftell_rv == -1L) {
        printf("ftell failed\n");
    } else {
        *buffer_len = ftell(fptr);
    }

    if (fseek(fptr, 0L, SEEK_SET) != 0) {
        printf("fseek SEEL_SET failed\n");
        goto out;
    }

    *buffer = malloc(*buffer_len);
    if (*buffer == NULL) {
        printf("Malloc failed\n");
        goto out;
    }

    frv = fread(*buffer, *buffer_len, 1, fptr);
    if (frv != 1) {
        printf("fwrite failed\n");
        goto out;
    }
    rv = 0;
out:
    if (fptr)
        fclose(fptr); //No error checks :/
    return rv;
}

static int write_bin_file(char *name, uint8_t *buffer, size_t buffer_len)
{
    FILE *fptr = NULL;
    size_t fwrite_rv = 0;
    int rv = 1;

    fptr = fopen(name, "wb");
    if (fptr == NULL) {
        printf("fopen failed: name[%s]\n", name);
        goto out;
    }

    fwrite_rv = fwrite(buffer, buffer_len, 1, fptr);
    if (fwrite_rv != 1) {
        printf("fwrite failed\n");
        goto out;
    }
    rv = 0;
out:
    if (fptr)
        fclose(fptr); //No error checks :/
    return rv;
}

int main(int argc, char *argv[])
{
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Result tee_rv;
    TEEC_UUID uuid = TA_IDENTITY_KEY_POC_UUID;
	TEEC_Operation operation = {0};
    TEEC_SharedMemory in_mem = {0};
	TEEC_SharedMemory out_mem = {0};
    uint8_t *in_data = NULL;
    size_t in_data_len = 0;
    char *in_data_file_name = "data";
    uint8_t sig[128] = {0};
    uint8_t *der_sig = NULL;
    size_t der_sig_len = 0;
    char *der_file_name = "signature.der";

    if (read_bin_file(in_data_file_name, &in_data, &in_data_len)) {
        goto end_1;
    }

    printf("\n..Connecting TEE and creating signature..\n\n");

    tee_rv = TEEC_InitializeContext(NULL, &context);
    if (tee_rv != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
        goto end_1;
    }

    tee_rv = TEEC_OpenSession(&context, &session,
                              &uuid, TEEC_LOGIN_PUBLIC,
                              NULL, NULL, NULL);
    if (tee_rv != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
        goto end_2;
    }

    in_mem.buffer = in_data;
    in_mem.size = in_data_len;
    in_mem.flags = TEEC_MEM_INPUT;

    tee_rv = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (tee_rv != TEEC_SUCCESS) {
        printf("TEEC_RegisterSharedMemory failed (IN memory): 0x%x\n", tee_rv);
        goto end_3;
    }

    out_mem.buffer = sig;
    out_mem.size = 128;
    out_mem.flags = TEEC_MEM_OUTPUT;

    tee_rv = TEEC_RegisterSharedMemory(&context, &out_mem);
    if (tee_rv != TEEC_SUCCESS) {
        printf("TEEC_RegisterSharedMemory failed (OUT memory): 0x%x\n", tee_rv);
        goto end_3;
    }

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
                                            TEEC_NONE, TEEC_NONE);

    operation.params[0].memref.parent = &in_mem;
    operation.params[1].memref.parent = &out_mem;
    tee_rv = TEEC_InvokeCommand(&session, TA_INDENTITY_CMD_SIGN_NONCE, &operation, NULL);
    if (tee_rv != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
        goto end_4;
    }

    pri_buf_hex_format("Raw signature", sig, operation.params[1].memref.size);

    if (conv_sig_raw2der(sig, operation.params[1].memref.size, &der_sig, &der_sig_len)) {
        goto end_4;
    } else {
        pri_buf_hex_format("Der signature", der_sig, der_sig_len);
    }

    if (write_bin_file(der_file_name, der_sig, der_sig_len)) {
        goto end_4;
    } else {
        printf("\nSignature written to file: %s\n",der_file_name);
    }
/*
 * End: Close/release resources
 */
end_4:
    TEEC_ReleaseSharedMemory(&out_mem);
end_3:
    TEEC_ReleaseSharedMemory(&in_mem);
    TEEC_CloseSession(&session);
end_2:
    TEEC_FinalizeContext(&context);
end_1:
    free(der_sig);
    free(in_data);
    exit(tee_rv);
}
