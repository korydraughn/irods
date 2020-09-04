#ifndef FILE_CLOSEDIR_H__
#define FILE_CLOSEDIR_H__

struct RcComm;

typedef struct FileCloseInput {
    int fileInx;
} fileClosedirInp_t;
#define fileClosedirInp_PI "int fileInx;"

#ifdef __cplusplus
extern "C"
#endif
int rcFileClosedir( struct RcComm *conn, fileClosedirInp_t *fileClosedirInp );

#endif
