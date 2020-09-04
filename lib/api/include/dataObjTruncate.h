#ifndef DATA_OBJ_TRUNCATE_H__
#define DATA_OBJ_TRUNCATE_H__

#include "dataObjInpOut.h"
#include "objInfo.h"

struct RcComm;

/* rcDataObjTruncate - Truncate a iRODS data object.
 * Input -
 *   RcComm *conn - The client connection handle.
 *   dataObjInp_t *dataObjInp - generic dataObj input. Relevant items are:
 *      objPath - the path of the data object.
 *      dataSize - the size to truncate to
 *
 * OutPut -
 *   return value - The status of the operation.
 */

#ifdef __cplusplus
extern "C"
#endif
int rcDataObjTruncate( struct RcComm *conn, dataObjInp_t *dataObjInp );

#endif
