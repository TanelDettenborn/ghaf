#include <tee_internal_api.h>
#include <ta_ekbpoc.h>
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

    EMSG("#!# ekb-poc: TA_CloseSessionEntryPoint");
}

TEE_Result invoke_poc_ekb(TEE_TASessionHandle *sess)
{
    TEE_Result rv = TEE_ERROR_GENERIC;
    uint32_t rv_org = 0;
    uint32_t params_type = 0;
    TEE_Param params[TEE_NUM_PARAMS] = {0};
    uint8_t my_secret[128] = {0};


    // NOTE: Not a good idea, because secret should not leave from PTA
    // This is done for the POC.
    params_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                  TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE);
    params[0].value.a = 123123;
    params[1].memref.buffer = my_secret;
    params[1].memref.size = 128;
    rv = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
                              JETSON_USER_KEY_CMD_GET_MY_SECRET,
                              params_type, params, &rv_org);
    if (rv) {
        EMSG("ekb-poc: TEE_InvokeTACommand failed rv[0x%08x]; rv_org[%u]\n", rv, rv_org);
    } else {
        // Print fetched buffer in HEX
        for (int i = 0; i < params[1].memref.size; i++)
        {
            EMSG("%02X", my_secret[i]);
        }
    }

    return rv;
}

TEE_Result invoke_poc_idenity_key(TEE_TASessionHandle *sess)
{
    TEE_Result rv = TEE_ERROR_GENERIC;
    uint32_t rv_org = 0;
    uint32_t params_type = 0;

    params_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE);

    rv = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
                              JETSON_USER_KEY_CMD_POC_GEN_IDENTITY_KEY,
                              params_type, NULL, &rv_org);
    if (rv) {
        EMSG("ekb-poc: TEE_InvokeTACommand failed rv[0x%08x]; rv_org[%u]\n", rv, rv_org);
    }

    return rv;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
                                      uint32_t command_id,
                                      uint32_t parameters_type,
                                      TEE_Param parameters[4])
{
    TEE_Result rv = TEE_ERROR_GENERIC;
    TEE_TASessionHandle sess = TEE_HANDLE_NULL;
    uint32_t rv_org = 0;
    // Unused
    session_id = session_id;
    command_id = command_id;
    parameters = parameters;
    parameters_type = parameters_type;

    rv = TEE_OpenTASession(&(const TEE_UUID)JETSON_USER_KEY_TA_UUID,
                            TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
                            &rv_org);
    if (rv) {
        EMSG("ekb-poc: TEE_OpenTASession failed rv[0x%08x]; rv_org[%u]\n", rv, rv_org);
        return rv;
    }
    // rv = invoke_poc_ekb(sess);
    rv = invoke_poc_idenity_key(sess);

    TEE_CloseTASession(sess);

    return rv;
}
