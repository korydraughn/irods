#ifndef PROC_LOG_H
#define PROC_LOG_H

#include "rodsConnect.h"

struct RsComm;

int
initAndClearProcLog();
int
initProcLog();
int
logAgentProc( RsComm* );
int
readProcLog( int pid, procLog_t *procLog );
int
rmProcLog( int pid );

#endif //PROC_LOG_H
