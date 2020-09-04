#ifndef CLOSE_COLLECTION_H__
#define CLOSE_COLLECTION_H__

#include "objInfo.h"
#include "dataObjInpOut.h"

struct RcComm;

/* rcCloseCollection - Close a iRODS collection.
 * Input -
 *   RcComm *conn - The client connection handle.
 *   int handleInxInp - the handleInx (collection handle index) to close.
 *
 * Output -
 *   int status - status of the operation.
 */
#ifdef __cplusplus
extern "C"
#endif
int rcCloseCollection( struct RcComm *conn, int handleInxInp );

#endif
