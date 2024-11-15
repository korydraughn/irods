#ifndef IRODS_DELAY_RULE_UNLOCK_H
#define IRODS_DELAY_RULE_UNLOCK_H

/// \file

#include "irods/objInfo.h"

struct RcComm;

/// The input data type used to invoke #rc_delay_rule_unlock.
///
/// \since 5.0.0
typedef struct DelayRuleUnlockInput
{
    /// The catalog ID of the delay rule to unlock.
    ///
    /// Must be a non-empty string.
    ///
    /// \since 5.0.0
    char rule_id[32]; // NOLINT(cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)

    /// The set of key-value pair strings used to influence the behavior of the API
    /// operation.
    ///
    /// \since 5.0.0
    struct KeyValPair cond_input;
} delayRuleUnlockInp_t;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DelayRuleUnlockInput_PI "str rule_id[32]; struct KeyValPair_PI;"

#ifdef __cplusplus
extern "C" {
#endif

/// Removes the delay server lock information from a delay rule if it exists.
///
/// Requires \p rodsadmin level privileges.
///
/// On success, the following information will be removed from the target delay rule's catalog
/// entry:
/// - The host identifying the delay server
/// - The PID of the delay server
/// - The time the entry was locked
///
/// \param[in] _comm  A pointer to a RcComm.
/// \param[in] _input A pointer to a DelayRuleUnlockInput.
///
/// \return An integer.
/// \retval 0  On success.
/// \retval <0 On failure.
///
/// \b Example
/// \code{.cpp}
/// RcComm* comm = // Our iRODS connection representing a rodsadmin user.
///
/// // Configure the input object for the API call.
/// struct DelayRuleUnlockInput input;
/// memset(&input, 0, sizeof(struct DelayRuleUnlockInput));
///
/// strncpy(input.rule_id, "12345", sizeof(DelayRuleUnlockInput::rule_id) - 1);
///
/// const int ec = rc_delay_rule_unlock(comm, &input);
///
/// if (ec < 0) {
///     // Handle error.
/// }
/// \endcode
///
/// \since 5.0.0
int rc_delay_rule_unlock(struct RcComm* _comm, struct DelayRuleUnlockInput* _input);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_DELAY_RULE_UNLOCK_H
