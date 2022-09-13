#ifndef IRODS_SWITCH_USER_HPP
#define IRODS_SWITCH_USER_HPP

/// \file

struct RcComm;

#ifdef __cplusplus
extern "C" {
#endif

// NOLINTBEGIN(modernize-use-trailing-return-type)

/// Switches the identity of the user associated with the connection.
///
/// Requires that the proxy user be a \p rodsadmin.
///
/// \param[in] _comm     A pointer to a RcComm.
/// \param[in] _username The name of the iRODS user to become.
/// \param[in] _zone     The zone of the iRODS user to become. Passing an empty string is
///                      equivalent to setting this parameter to the name of the connected
///                      zone.
///
/// \return An integer.
/// \retval 0        On success.
/// \retval non-zero On failure.
///
/// \since 4.3.1
int rc_switch_user(struct RcComm* _comm, const char* _username, const char* _zone);

// NOLINTEND(modernize-use-trailing-return-type)

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_SWITCH_USER_HPP

