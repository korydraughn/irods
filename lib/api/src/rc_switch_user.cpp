#include "irods/switch_user.h"

#include "irods/plugins/api/switch_user_types.h"
#include "irods/plugins/api/api_plugin_number.h"
#include "irods/procApiRequest.h"
#include "irods/rodsErrorTable.h"

#include <cstdlib>
#include <cstring>

auto rc_switch_user(RcComm* _comm, const char* _username, const char* _zone) -> int
{
    // NOLINTNEXTLINE(readability-implicit-bool-conversion)
    if (!_comm || !_username || !_zone) {
        return SYS_INVALID_INPUT_PARAM;
    }

    // Accepting empty strings for either parameter is not allowed.
    // This is especially true for the "_zone" parameter because the implementation of this
    // function copies the string represented by "_zone" into the RcComm. Copying an empty
    // string into the RcComm's rodsZone member variables makes the RcComm invalid.
    if (std::strlen(_username) == 0 || std::strlen(_zone) == 0) {
        return SYS_INVALID_INPUT_PARAM;
    }

    auto& client = _comm->clientUser;

    // clang-format off
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    //
    // Return immediately if the RcComm object already represents the target user.
    //
    // This is allowed because the RcComm only cares about the username and zone. If the RcComm
    // considered the user's type or authentication level (i.e. LOCAL_PRIV_USER_AUTH), then this
    // optimization would not be possible.
    //
    // The substraction of 1 on the final argument helps to ensure there is a null byte. The
    // server assumes the strings passed to the API are null-terminated strings.
    if (std::strncmp(_username, client.userName, sizeof(UserInfo::userName) - 1) == 0 &&
        std::strncmp(_zone, client.rodsZone, sizeof(UserInfo::rodsZone) - 1) == 0)
    {
        return 0;
    }
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    // clang-format on

    try {
        SwitchUserInput input{};
        std::strncpy(static_cast<char*>(input.username), _username, sizeof(SwitchUserInput::username));
        std::strncpy(static_cast<char*>(input.zone), _zone, sizeof(SwitchUserInput::zone));

        const int ec = procApiRequest(_comm, SWITCH_USER_APN, &input, nullptr, nullptr, nullptr);

        // NOLINTNEXTLINE(readability-implicit-bool-conversion)
        if (ec == 0) {
            // On success, we always assume that the output pointer is valid.
            // If the server-side implementation is solid, then we shouldn't need to check the pointer.

            // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
            std::strncpy(client.userName, _username, sizeof(UserInfo::userName));
            std::strncpy(client.rodsZone, _zone, sizeof(UserInfo::rodsZone));
            // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
        }

        return ec;
    }
    catch (const std::exception&) {
        return SYS_LIBRARY_ERROR;
    }
    catch (...) {
        return SYS_UNKNOWN_ERROR;
    }
} // rc_switch_user

