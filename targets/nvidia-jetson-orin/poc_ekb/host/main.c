#include <stdio.h>
#include <stdlib.h>

#include <tee_client_api.h>
#include <ta_ekbpoc.h>

int main(int argc, char *argv[])
{
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Result tee_rv;
    TEEC_UUID uuid = TA_EKBPOC_UUID;


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

    tee_rv = TEEC_InvokeCommand(&session, 0, NULL, NULL);
    if (tee_rv != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
    }

/*
 * End: Close/release resources
 */
    TEEC_CloseSession(&session);
end_2:
    TEEC_FinalizeContext(&context);
end_1:
    exit(tee_rv);
}
