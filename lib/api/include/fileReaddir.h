#ifndef FILE_READDIR_H__
#define FILE_READDIR_H__

#include "rodsType.h"

struct RcComm;

typedef struct FileReadDirectoryInput {
    int fileInx;
} fileReaddirInp_t;
#define fileReaddirInp_PI "int fileInx;"


#ifdef __cplusplus
extern "C"
#endif
int rcFileReaddir( struct RcComm *conn, fileReaddirInp_t *fileReaddirInp, rodsDirent_t **fileReaddirOut );

#endif
