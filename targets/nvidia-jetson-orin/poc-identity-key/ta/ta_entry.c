#include <tee_internal_api.h>
#include <ta_indentity_key_poc.h>
#include <pta_jetson_user_key.h>
#include <string.h>

#define JETSON_USER_KEY_TA_UUID \
                { 0xe9e156e8, 0xe161, 0x4c8a, \
                        {0x91, 0xa9, 0x0b, 0xba, 0x5e, 0x24, 0x7e, 0xe8} }
#define JETSON_USER_KEY_CMD_POC_GEN_AND_GET_IDENTITY_KEY 10

static TEE_OperationHandle ident_sign_op_g = NULL;

static TEE_Result fetch_populate_identity_key_obj(TEE_ObjectHandle ident_key_obj,
                                                  uint32_t ident_key_size_bit,
                                                  uint32_t ident_curve)
{
    TEE_Result rv = TEE_ERROR_GENERIC;
    TEE_TASessionHandle sess = TEE_HANDLE_NULL;
    uint32_t rv_org = 0, ident_key_size_byte = 0;
    uint32_t ta2ta_params_type = 0;
    TEE_Param ta2ta_params[TEE_NUM_PARAMS] = {0};
    void *d_ptr = NULL, *x_ptr = NULL, *y_ptr = NULL;
    size_t d_size = 0, x_size = 0, y_size = 0;
    TEE_Attribute identity_key_attr[4] = { };

    ident_key_size_byte = ident_key_size_bit/8;

    // For the sake of sanity only supporting:
    // * TEE_ECC_CURVE_NIST_P384
    // * 384 bit size key
    // Could be generalised to all keys!
    if (ident_key_size_byte != 48) {
        // TODO: POC prints nice error message. Remove for production.
        EMSG("Only supported identity key size is 384bit (48byte)");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if (ident_curve != TEE_ECC_CURVE_NIST_P384) {
        // TODO: POC prints nice error message. Remove for production.
        EMSG("Only supported identity key curve is TEE_ECC_CURVE_NIST_P384");
        return TEE_ERROR_NOT_SUPPORTED;
    }

        // All EC key are same size, but for clarity all has own variable
    d_size = ident_key_size_byte;
    x_size = ident_key_size_byte;
    y_size = ident_key_size_byte;

    d_ptr = TEE_Malloc(d_size, TEE_MALLOC_FILL_ZERO);
    x_ptr = TEE_Malloc(x_size, TEE_MALLOC_FILL_ZERO);
    y_ptr = TEE_Malloc(y_size, TEE_MALLOC_FILL_ZERO);
    if (d_ptr == NULL || x_ptr == NULL || y_ptr == NULL) {
        // Out of memory and below might not get printed
        EMSG("Out of memory d_ptr[%p]; x_ptr[%p]; y_ptr[%p];", d_ptr, x_ptr, y_ptr);
        rv = TEE_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    TEE_InitValueAttribute(&identity_key_attr[0], TEE_ATTR_ECC_CURVE, ident_curve, 0);
    TEE_InitRefAttribute(&identity_key_attr[1], TEE_ATTR_ECC_PRIVATE_VALUE, d_ptr, d_size);
    TEE_InitRefAttribute(&identity_key_attr[2], TEE_ATTR_ECC_PUBLIC_VALUE_X, x_ptr, x_size);
    TEE_InitRefAttribute(&identity_key_attr[3], TEE_ATTR_ECC_PUBLIC_VALUE_Y, y_ptr, y_size);

    rv = TEE_OpenTASession(&(const TEE_UUID)JETSON_USER_KEY_TA_UUID,
                            TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
                            &rv_org);
    if (rv) {
        EMSG("TEE_OpenTASession failed rv[0x%08x]; rv_org[%u]\n", rv, rv_org);
                goto out;
    }

    ta2ta_params_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE);
    ta2ta_params[0].memref.buffer = d_ptr;
    ta2ta_params[0].memref.size = d_size;
    ta2ta_params[1].memref.buffer = x_ptr;
    ta2ta_params[1].memref.size = x_size;
    ta2ta_params[2].memref.buffer = y_ptr;
    ta2ta_params[2].memref.size = y_size;
    rv = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
                             JETSON_USER_KEY_CMD_POC_GEN_AND_GET_IDENTITY_KEY,
                             ta2ta_params_type, ta2ta_params, &rv_org);
    if (rv) {
        EMSG("TEE_InvokeTACommand failed rv[0x%08x]; rv_org[%u]\n", rv, rv_org);
        goto out;
    }

    rv = TEE_PopulateTransientObject(ident_key_obj, identity_key_attr, 4);
    if (rv) {
        EMSG("TEE_PopulateTransientObject failed rv[0x%08x]; rv_org[%u]\n", rv, rv_org);
        goto out;
    }

out:
    if (d_ptr)
        TEE_MemFill(d_ptr, 0, d_size);
    TEE_Free(d_ptr);
    TEE_Free(x_ptr);
    TEE_Free(y_ptr);
    TEE_CloseTASession(sess);
    return rv;
}

static void free_ident_sign_op(void)
{
    TEE_FreeOperation(ident_sign_op_g);
    ident_sign_op_g = NULL;
}

static TEE_Result calc_sha384(void *chunk, size_t chunk_len,
                              void *hash, size_t *hash_len)
{
    TEE_OperationHandle sha384_op = NULL;
    TEE_Result rv = TEE_ERROR_GENERIC;

    rv = TEE_AllocateOperation(&sha384_op, TEE_ALG_SHA384, TEE_MODE_DIGEST, 0);
    if (rv != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation failed (TEE_ALG_SHA384,TEE_MODE_DIGEST,,0): 0x%08x", rv);
        goto err;
    }

    rv = TEE_DigestDoFinal(sha384_op, chunk, chunk_len, hash, hash_len);
    if (rv != TEE_SUCCESS) {
        EMSG("TEE_DigestDoFinal failed: 0x%08x", rv);
        goto err;
    }

err:
    TEE_FreeOperation(sha384_op);
    return rv;
}

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_ObjectHandle ident_key_obj = NULL;
    TEE_Result rv = TEE_ERROR_GENERIC;
    uint32_t ident_key_size = 384; // in BITS

    rv = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, ident_key_size, &ident_key_obj);
    if (rv != TEE_SUCCESS) {
        EMSG("TEE_AllocateTransientObject failed rv[0x%08x]", rv);
        goto out;
    }

    rv = fetch_populate_identity_key_obj(ident_key_obj, ident_key_size, TEE_ECC_CURVE_NIST_P384);
    if (rv != TEE_SUCCESS) {
        EMSG("Failed to fetch identity key");
        goto out;
    }

    rv = TEE_AllocateOperation(&ident_sign_op_g, TEE_ALG_ECDSA_SHA384, TEE_MODE_SIGN, ident_key_size);
    if (rv != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation failed (TEE_ALG_ECDSA_SHA256,TEE_MODE_SIGN,ident_key_size): 0x%08x", rv);
        goto out;
    }

    rv = TEE_SetOperationKey(ident_sign_op_g, ident_key_obj);
    if (rv != TEE_SUCCESS) {
        EMSG("TEE_SetOperationKey failed: 0x%08x", rv);
        goto out;
    }

out:
    if (rv != TEE_SUCCESS)
        free_ident_sign_op();
    TEE_FreeTransientObject(ident_key_obj);
    return rv;
}

void TA_DestroyEntryPoint(void)
{
    free_ident_sign_op();
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t ptype __unused,
                                    TEE_Param param[4] __unused,
                                    void **session_id_ptr)
{
    TEE_Result rv = TEE_ERROR_GENERIC;
    TEE_OperationHandle sha256_op = NULL;

    // Sanity check
    if (ident_sign_op_g == NULL) {
        EMSG("Identity key operation not set");
        rv = TEE_ERROR_GENERIC;
        goto err;
    }

    rv = TEE_AllocateOperation(&sha256_op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (rv != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation failed (TEE_ALG_SHA256,TEE_MODE_DIGEST,,0): 0x%08x", rv);
        goto err;
    }
err:
    *session_id_ptr = sha256_op;
    return rv;
}

void TA_CloseSessionEntryPoint(void *sess_ptr __unused)
{
    EMSG("POC-identity-key: TA_CloseSessionEntryPoint");
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_id __unused,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4])
{
    TEE_Result rv = TEE_ERROR_GENERIC;
    uint32_t expeted_parms_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                                  TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                                  TEE_PARAM_TYPE_NONE,
                                                  TEE_PARAM_TYPE_NONE);
    uint8_t nonce_hash[48] = {};
    size_t nonce_hash_len = 48;

    if (command_id != TA_INDENTITY_CMD_SIGN_NONCE) {
        EMSG("Command not supported: command_id[%u]", command_id);
        rv = TEE_ERROR_NOT_SUPPORTED;
        goto out;
    }

    if (expeted_parms_type != parameters_type) {
        EMSG("Bad parameters type: expected[%u]; provided[%u]", expeted_parms_type, parameters_type);
        rv = TEE_ERROR_BAD_PARAMETERS;
        goto out;
    }

    rv = calc_sha384(parameters[0].memref.buffer, parameters[0].memref.size, nonce_hash, &nonce_hash_len);
    if (rv != TEE_SUCCESS) {
        goto out;
    }


    rv = TEE_AsymmetricSignDigest(ident_sign_op_g, NULL, 0,
                                  nonce_hash, nonce_hash_len,
                                  parameters[1].memref.buffer, &parameters[1].memref.size);
    if (rv != TEE_SUCCESS) {
        EMSG("TEE_AsymmetricSignDigest failed: 0x%08x", rv);
        goto out;
    }

out:
    return rv;
}
