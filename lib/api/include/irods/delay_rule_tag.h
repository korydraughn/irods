#ifndef IRODS_DELAY_RULE_TAG_H
#define IRODS_DELAY_RULE_TAG_H

/// \file

#include "irods/objInfo.h"

struct RcComm;

/// TODO
///
/// \since 5.0.0
typedef struct DelayRuleTagInput
{
    char rule_id[32]; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
    char tag[32]; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
    struct KeyValPair condInput;
} delayRuleTagInp_t;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DelayRuleTagInput_PI "str rule_id[32]; str tag[32]; struct KeyValPair_PI;"

#ifdef __cplusplus
extern "C" {
#endif

/// TODO
///
/// \param[in] _comm  A pointer to a RcComm.
/// \param[in] _input 
///
/// \return An integer.
/// \retval 0        On success.
/// \retval non-zero On failure.
///
/// \since 5.0.0
int rc_delay_rule_tag(struct RcComm* _comm, struct DelayRuleTagInput* _input);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_DELAY_RULE_TAG_H
