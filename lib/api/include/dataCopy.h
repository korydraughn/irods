#ifndef DATA_COPY_H__
#define DATA_COPY_H__

#include "dataObjInpOut.h"

struct RcComm;

typedef struct DataCopyInp {
    dataOprInp_t dataOprInp;
    portalOprOut_t portalOprOut;
} dataCopyInp_t;

#define DataCopyInp_PI "struct DataOprInp_PI; struct PortalOprOut_PI;"


int rcDataCopy( struct RcComm *conn, dataCopyInp_t *dataCopyInp );

#endif
