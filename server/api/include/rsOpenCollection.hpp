#ifndef RS_OPEN_COLLECTION_HPP
#define RS_OPEN_COLLECTION_HPP

#include "rodsConnect.h"
#include "dataObjInpOut.h"

struct RsComm;

int rsOpenCollection( RsComm *rsComm, collInp_t *openCollInp );

#endif
