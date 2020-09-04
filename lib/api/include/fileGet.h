#ifndef FILE_GET_H__
#define FILE_GET_H__

#include "rodsDef.h"
#include "fileOpen.h"

struct RcComm;

#ifdef __cplusplus
extern "C"
#endif
int rcFileGet( struct RcComm *conn, fileOpenInp_t *fileGetInp, bytesBuf_t *fileGetOutBBuf );

#endif
