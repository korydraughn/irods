#ifndef RS_AUTH_CHECK_HPP
#define RS_AUTH_CHECK_HPP

#include "authCheck.h"

struct RsComm;

int rsAuthCheck( struct RsComm *rsComm, authCheckInp_t *authCheckInp, authCheckOut_t **authCheckOut );

#endif
