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
    if (!_username || !_zone) {
        return SYS_INVALID_INPUT_PARAM;
    }

    auto& client = _comm->clientUser;

    // Attempting to verify that the user is already the target user cannot be done without
    // going over the wire. That's because the client cannot determine the user type of the
    // target user. For that reason, this implementation always results in a network request.

    try {
        SwitchUserInput input{};
        std::strncpy(static_cast<char*>(input.username), _username, sizeof(SwitchUserInput::username));
        std::strncpy(static_cast<char*>(input.zone), _zone, sizeof(SwitchUserInput::zone));

        SwitchUserOutput* output{};
        void** out_ptr = reinterpret_cast<void**>(&output); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

        const int ec = procApiRequest(_comm, SWITCH_USER_APN, &input, nullptr, out_ptr, nullptr);

        // NOLINTNEXTLINE(readability-implicit-bool-conversion)
        if (ec == 0) {
            // On success, we always assume that the output pointer is valid.
            // If the server-side implementation is solid, then we shouldn't need to check the pointer.

            // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
            std::strncpy(client.userName, _username, sizeof(UserInfo::userName));
            std::strncpy(client.rodsZone, _zone, sizeof(UserInfo::rodsZone));
            std::strncpy(client.userType, output->user_type, sizeof(UserInfo::userType));
            // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)

            _comm->clientUser.authInfo.authFlag = output->privilege_level;

            std::free(output); // NOLINT(cppcoreguidelines-owning-memory, cppcoreguidelines-no-malloc)
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

