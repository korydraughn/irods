#ifndef IRODS_DELAY_RULE_TAG_CLEAR_H
#define IRODS_DELAY_RULE_TAG_CLEAR_H

/// \file

#include "irods/objInfo.h"

struct RcComm;

/// TODO
///
/// \since 5.0.0
typedef struct DelayRuleTagClearInput
{
    char rule_id[32]; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
    struct KeyValPair condInput;
} delayRuleTagClearInp_t;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DelayRuleTagClearInput_PI "str rule_id[32]; str tag[32]; struct KeyValPair_PI;"

#ifdef __cplusplus
extern "C" {
#endif

/// TODO
///
/// \param[in]  _comm  A pointer to a RcComm.
/// \param[in]  _input 
///
/// \return An integer.
/// \retval 0        On success.
/// \retval non-zero On failure.
///
/// \since 5.0.0
int rc_delay_rule_tag_clear(struct RcComm* _comm, struct DelayRuleTagClearInput* _input);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_DELAY_RULE_TAG_CLEAR_H
