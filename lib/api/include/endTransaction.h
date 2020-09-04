#ifndef END_TRANSACTION_H__
#define END_TRANSACTION_H__

struct RcComm;

typedef struct EndTransactionInput {
    char *arg0;
    char *arg1;
} endTransactionInp_t;
#define endTransactionInp_PI "str *arg0; str *arg1;"

#ifdef __cplusplus
extern "C"
#endif
int rcEndTransaction( struct RcComm *conn, endTransactionInp_t *endTransactionInp );

#endif
