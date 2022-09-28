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

    auto& client = _comm->clientUser;

    if (std::strcmp(_username, client.userName) == 0 && std::strcmp(_zone, client.rodsZone) == 0) {
        return 0;
    }

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

