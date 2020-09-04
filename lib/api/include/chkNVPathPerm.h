#ifndef CHK_NV_PATH_PERM_H__
#define CHK_NV_PATH_PERM_H__

#include "fileOpen.h"
#include "rodsConnect.h"

struct RcComm;

#ifdef __cplusplus
extern "C"
#endif
int rcChkNVPathPerm( struct RcComm *conn, fileOpenInp_t *chkNVPathPermInp );

#endif
