#ifndef CLIENT_HINTS_H__
#define CLIENT_HINTS_H__

#include "rodsDef.h"

struct RcComm;

#ifdef __cplusplus
extern "C"
#endif
int rcClientHints(RcComm* server_comm_ptr, bytesBuf_t** json_response);

#endif
