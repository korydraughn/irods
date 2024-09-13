#ifndef IRODS_GET_ACTIVE_AGENTS_H
#define IRODS_GET_ACTIVE_AGENTS_H

/// \file

#include "irods/objInfo.h"

struct RcComm;

/// TODO
///
/// \since 5.0.0
typedef struct GetActiveAgentsInput
{
    char hostname[65]; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
    char zone[250]; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
    struct KeyValPair condInput;
} getActiveAgentsInp_t;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define GetActiveAgentsInput_PI "str hostname[65]; str zone[250]; struct KeyValPair_PI;"

#ifdef __cplusplus
extern "C" {
#endif

/// TODO
///
/// \param[in] _comm  A pointer to a RcComm.
/// \param[in] _input 
/// \param[in,out] _info 
///
/// \return An integer.
/// \retval 0        On success.
/// \retval non-zero On failure.
///
/// \since 5.0.0
int rc_get_active_agents(struct RcComm* _comm, struct GetActiveAgentsInput* _input, char** _info);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_GET_ACTIVE_AGENTS_H
