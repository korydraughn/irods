#ifndef DATA_PUT_H__
#define DATA_PUT_H__

#include "dataObjInpOut.h"

struct RcComm;

#ifdef __cplusplus
extern "C"
#endif
int rcDataPut( struct RcComm *conn, dataOprInp_t *dataPutInp, portalOprOut_t **portalOprOut );

#endif
