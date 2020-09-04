#ifndef COLL_REPL_H__
#define COLL_REPL_H__

#include "objInfo.h"
#include "dataObjInpOut.h"

struct RcComm;

#ifdef __cplusplus
extern "C"
#endif
int rcCollRepl( struct RcComm *conn, collInp_t *collReplInp, int vFlag );
int _rcCollRepl( struct RcComm *conn, collInp_t *collReplInp, collOprStat_t **collOprStat );

#endif
