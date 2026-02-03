#include <tee_internal_api.h>
#include <ta_hello_example.h>

TEE_Result TA_CreateEntryPoint(void)
{
    // Nothing

    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    // Nothing
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t ptype __unused,
                                    TEE_Param param[4] __unused,
                                    void **session_id_ptr __unused)
{
    // Nothing

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ptr __unused)
{
    // Nothing
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_id __unused,
                                      uint32_t command_id,
                                      uint32_t parameters_type __unused,
                                      TEE_Param parameters[4] __unused)
{
    TEE_Result rv = TEE_ERROR_NOT_SUPPORTED;
    
    if (command_id == PRINT_HELLO_MSG) {
        EMSG("Hello from example TA!");
        rv = TEE_SUCCESS;
    }
    
    return rv;
}
