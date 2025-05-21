#include <tee_internal_api.h>
#include <ta_indentity_key_poc.h>
#include <pta_jetson_user_key.h>
#include <string.h>

#define JETSON_USER_KEY_TA_UUID \
                { 0xe9e156e8, 0xe161, 0x4c8a, \
                        {0x91, 0xa9, 0x0b, 0xba, 0x5e, 0x24, 0x7e, 0xe8} }

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t ptype,
                                    TEE_Param param[4],
                                    void **session_id_ptr)
{
    ptype = ptype;
    param = param;
    session_id_ptr = session_id_ptr;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ptr)
{
    sess_ptr = sess_ptr;

    EMSG("POC-identity-key: TA_CloseSessionEntryPoint");
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4])
{
    TEE_Result rv = TEE_ERROR_GENERIC;
    TEE_TASessionHandle sess = TEE_HANDLE_NULL;
    uint32_t rv_org = 0;
    uint32_t ta2ta_params_type = 0;
    TEE_Param ta2ta_params[TEE_NUM_PARAMS] = {0};
    uint8_t indentity_key[64] = {0};
    uint8_t *tmpptr = NULL;
    size_t i = 0;

    session_id = session_id;
    command_id = command_id;
    parameters = parameters;
    parameters_type = parameters_type;

    rv = TEE_OpenTASession(&(const TEE_UUID)JETSON_USER_KEY_TA_UUID,
                           TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
                           &rv_org);
    if (rv) {
        EMSG("POC-identity-key: TEE_OpenTASession failed rv[0x%08x]; rv_org[%u]\n", rv, rv_org);
        return rv;
    }

    ta2ta_params_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE);
    ta2ta_params[0].memref.buffer = indentity_key;
    ta2ta_params[0].memref.size = 64;

    rv = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
                             JETSON_USER_KEY_CMD_POC_GEN_AND_GET_IDENTITY_KEY,
                             ta2ta_params_type, ta2ta_params, &rv_org);
    if (rv) {
        EMSG("POC-identity-key: TEE_InvokeTACommand failed rv[0x%08x]; rv_org[%u]\n", rv, rv_org);
    } else {
        tmpptr = indentity_key;
        for (i = 0; i < ta2ta_params[0].memref.size; i++)
        {
            EMSG("POC-identity-key: key[%02x]", indentity_key[i]);
        }
    }

    TEE_CloseTASession(sess);

    return rv;
}
