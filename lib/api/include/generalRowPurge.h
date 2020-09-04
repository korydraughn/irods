#ifndef GENERAL_ROW_PURGE_H__
#define GENERAL_ROW_PURGE_H__

struct RcComm;

typedef struct GeneralRowPurgeInput {
    char *tableName;
    char *secondsAgo;
} generalRowPurgeInp_t;
#define generalRowPurgeInp_PI "str *tableName; str *secondsAgo;"

#ifdef __cplusplus
extern "C"
#endif
int rcGeneralRowPurge( struct RcComm *conn, generalRowPurgeInp_t *generalRowPurgeInp );

#endif
