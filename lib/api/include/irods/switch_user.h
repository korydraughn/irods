#ifndef IRODS_SWITCH_USER_HPP
#define IRODS_SWITCH_USER_HPP

/// \file

#include "irods/plugins/api/switch_user_types.h"

struct RcComm;

#ifdef __cplusplus
extern "C" {
#endif

// NOLINTBEGIN(modernize-use-trailing-return-type)

/// Switches the identity of the user associated with the connection.
///
/// Requires that the proxy user be a \p rodsadmin.
///
/// On success, the following things will be true:
/// - All API operations invoked via the \p RcComm will be carried out as the user that was just switched to.
/// - Server-to-server connections will be updated or disconnected based on the remote server's version.
///
/// On failure, the RcComm should be closed to avoid potential issues.
///
/// \param[in] _comm  A pointer to a RcComm.
/// \param[in] _input \parblock A pointer to a SwitchUserInput.
///
/// SwitchUserInput member variables:
/// - \p username: The part of the iRODS username preceding the pound sign. The following requirements must be satified:
///     - The length must not exceed sizeof(UserInfo::userName) - 1 bytes
///     - It must be null-terminated
///     - It must be non-empty
///     - It must not include the zone
/// - \p zone: The part of the iRODS username following the pound sign. The following requirements must be satisfied:
///     - The length must not exceed sizeof(UserInfo::rodsZone) - 1 bytes
///     - It must be null-terminated
///     - It must be non-empty
/// - \p update_proxy_user: If set to 1, the proxy user is updated as well. This option will result in losing the
///                         ability to invoke rc_switch_user if this option is set to 1 and the user to switch to is
///                         not a \p rodsadmin. This option does not affect server-to-server connections.
/// - \p close_svr_to_svr_connections: If set to 1, all connections created through redirection will be closed.
/// \endparblock
///
/// \return An integer.
/// \retval 0        On success.
/// \retval non-zero On failure.
///
/// \since 4.3.1
int rc_switch_user(struct RcComm* _comm, const struct SwitchUserInput* _input);

// NOLINTEND(modernize-use-trailing-return-type)

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_SWITCH_USER_HPP
