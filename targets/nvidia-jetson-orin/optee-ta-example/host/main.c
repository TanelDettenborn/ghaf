#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>
#include <ta_hello_example.h>

int main(int argc, char *argv[])
{
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Result tee_rv;
    TEEC_UUID uuid = TA_HELLO_EXAMPLE_UUID;
	
    printf("\nExample start\n\nConnecting TEE..\n");

    tee_rv = TEEC_InitializeContext(NULL, &context);
    if (tee_rv != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
        goto end_1;
    }

    printf("Opening session towards TA..n");
    
    tee_rv = TEEC_OpenSession(&context, &session,
                              &uuid, TEEC_LOGIN_PUBLIC,
                              NULL, NULL, NULL);
    if (tee_rv != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
        goto end_2;
    }

    printf("Invoking TA command..\n");
    
    tee_rv = TEEC_InvokeCommand(&session, PRINT_HELLO_MSG, NULL, NULL);
    if (tee_rv != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
        goto end_3;
    }

    printf("TA has printed Hello Worlds message\n\n");

    printf("Closing session and connections....\n\n");
/*
 * End: Close/release resources
 */
end_3:
    TEEC_CloseSession(&session);
end_2:
    TEEC_FinalizeContext(&context);
end_1:
    printf("\nExample exit\n");
    exit(tee_rv);
}
