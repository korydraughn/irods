#ifndef DATA_GET_H__
#define DATA_GET_H__

#include "dataObjInpOut.h"

struct RcComm;

int rcDataGet( struct RcComm *conn, dataOprInp_t *dataGetInp, portalOprOut_t **portalOprOut );

#endif
