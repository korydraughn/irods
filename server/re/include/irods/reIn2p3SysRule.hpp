#ifndef IRODS_RE_IN2P3_SYS_RULE_HPP
#define IRODS_RE_IN2P3_SYS_RULE_HPP

#include "irods/msParam.h"
#include "irods/rods.h"
#include "irods/rsGlobalExtern.hpp"   // server global
#include "irods/rcGlobalExtern.h"     // client global
#include "irods/rodsLog.h"
#include "irods/sockComm.h"
#include "irods/getRodsEnv.h"
#include "irods/rcConnect.h"
#include "irods/generalRowInsert.h"
#include "irods/generalRowPurge.h"
#include "irods/generalAdmin.h"

#include <string>

#define NFIELDS                 4       // number of fields in HostControlAccess file: <user> <group> <IP address> <subnet mask>
#define MAXLEN                  100
#define MAXSTR                  30
#define MAXLIST                 40      // max number of entries in the access list tab.

#define MAX_VALUE               512                                 // for array definition.
#define MAX_MESSAGE_SIZE        2000
#define MAX_NSERVERS            512                                 // max number of servers that can be monitored (load balancing).
#define TIMEOUT                 20                                  // number of seconds after which the request (the thread taking care of it) for server load is canceled.
#define LEN_SECONDS             4                                   // length in bytes for the encoding of number of seconds.

int checkHostAccessControl(const std::string& _user_name,
                           const std::string& _client_host,
                           const std::string& _groups_name);

int msiCheckHostAccessControl(ruleExecInfo_t* rei);

#endif // IRODS_RE_IN2P3_SYS_RULE_HPP
