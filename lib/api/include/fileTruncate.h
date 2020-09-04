#ifndef FILE_TRUNCATE_H__
#define FILE_TRUNCATE_H__

#include "fileOpen.h"

struct RcComm;

#ifdef __cplusplus
extern "C"
#endif
int rcFileTruncate( struct RcComm *conn, fileOpenInp_t *fileTruncateInp );

#endif
