#ifndef FILE_SYNC_TO_ARCH_H__
#define FILE_SYNC_TO_ARCH_H__

#include "fileStageToCache.h"

struct RcComm;

#ifdef __cplusplus
extern "C"
#endif
int rcFileSyncToArch( struct RcComm *conn, fileStageSyncInp_t *fileSyncToArchInp, fileSyncOut_t** );

#endif
