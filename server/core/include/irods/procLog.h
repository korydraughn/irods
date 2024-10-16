#ifndef PROC_LOG_H
#define PROC_LOG_H

#include "irods/rodsConnect.h"

int readProcLog(int pid, procLog_t* procLog);

#endif //PROC_LOG_H
