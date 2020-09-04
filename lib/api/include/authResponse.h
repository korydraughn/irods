#ifndef AUTH_RESPONSE_H__
#define AUTH_RESPONSE_H__

struct RcComm;

typedef struct AuthResponseInput {
    char *response;
    char *username;
} authResponseInp_t;
#define authResponseInp_PI "bin *response(RESPONSE_LEN); str *username;"

#ifdef __cplusplus
extern "C"
#endif
int rcAuthResponse( struct RcComm *conn, authResponseInp_t *authResponseInp );

#endif
