#include "irods/plugins/api/api_plugin_number.h"
#include "irods/plugins/api/switch_user_types.h"
#include "irods/rodsDef.h"
#include "irods/rcConnect.h"
#include "irods/rodsPackInstruct.h"
#include "irods/rcMisc.h"
#include "irods/client_api_allowlist.hpp"

#include "irods/apiHandler.hpp"

#include <functional>

#ifdef RODS_SERVER

//
// Server-side Implementation
//

#  include "irods/irods_rs_comm_query.hpp"
#  include "irods/rodsErrorTable.h"
#  include "irods/irods_logger.hpp"
#  include "irods/server_utilities.hpp"

#  define IRODS_USER_ADMINISTRATION_ENABLE_SERVER_SIDE_API
#  include "irods/user_administration.hpp"

#  include <cstring>
#  include <string>
#  include <string_view>

namespace
{
    //
    // Function Prototypes
    //

    auto call_switch_user(irods::api_entry*, RsComm*, SwitchUserInput*, SwitchUserOutput**) -> int;
    auto rs_switch_user(RsComm*, SwitchUserInput*, SwitchUserOutput**) -> int;

    //
    // Function Implementations
    //

    auto call_switch_user(irods::api_entry* _api, RsComm* _comm, SwitchUserInput* _input, SwitchUserOutput** _output)
        -> int
    {
        return _api->call_handler<SwitchUserInput*, SwitchUserOutput**>(_comm, _input, _output);
    } // call_switch_user

    auto rs_switch_user(RsComm* _comm, SwitchUserInput* _input, SwitchUserOutput** _output) -> int
    {
        using log_api = irods::experimental::log::api;

        // Clear the output pointer in case the client handed us bad input.
        *_output = nullptr;

        // Only administrators are allowed to invoke this API.
        // We check the proxy user because it covers clients and server-to-server redirects.
        // Remember, the client and proxy user information is identical until there's a redirect.
        if (!irods::is_privileged_proxy(*_comm)) {
            log_api::error(
                "Proxy user [{}] does not have permission to switch client user.", _comm->proxyUser.userName);
            return SYS_PROXYUSER_NO_PRIV;
        }

        if (!_input) {
            log_api::error("Invalid input argument: Received a null pointer");
            return SYS_INVALID_INPUT_PARAM;
        }

        const auto* local_zone = getLocalZoneName();

        if (!local_zone) {
            log_api::error("Could not get name of local zone.");
            return SYS_INTERNAL_ERR;
        }

        const auto* username = _input->username;
        const auto* zone = _input->zone;
        bool is_local_zone = false;

        // Passing an empty string as the zone argument is equivalent to explicitly setting
        // the zone parameter to the local zone.
        if (const std::string_view z{_input->zone}; z.empty() || z == local_zone) {
            zone = local_zone;
            is_local_zone = true;
        }

        namespace adm = irods::experimental::administration;

        // This call covers the existence check too.
        const auto user_type = adm::server::type(*_comm, adm::user{username, zone});

        if (!user_type) {
            log_api::error("[{}#{}] is not a user in the local zone.", username, zone);
            return SYS_INVALID_INPUT_PARAM;
        }

        const auto* user_type_string = adm::to_c_str(*user_type);
        auto& client = _comm->clientUser;

        // Update the user identity associated with the RsComm.
        std::strncpy(client.userName, username, sizeof(UserInfo::userName));
        std::strncpy(client.rodsZone, zone, sizeof(UserInfo::rodsZone));
        std::strncpy(client.userType, user_type_string, sizeof(UserInfo::userType));

        // Set the appropriate privilege level based on whether the user is local or remote
        // relative to the local zone.
        if (is_local_zone) {
            client.authInfo.authFlag =
                (*user_type == adm::user_type::rodsadmin) ? LOCAL_PRIV_USER_AUTH : LOCAL_USER_AUTH;
        }
        else {
            client.authInfo.authFlag =
                (*user_type == adm::user_type::rodsadmin) ? REMOTE_PRIV_USER_AUTH : REMOTE_USER_AUTH;
        }

        // Populate the response object with information that helps the client avoid
        // additional API calls.
        auto* output = static_cast<SwitchUserOutput*>(std::malloc(sizeof(SwitchUserOutput)));
        std::memset(output, 0, sizeof(SwitchUserOutput));
        std::strncpy(output->user_type, user_type_string, sizeof(SwitchUserOutput::user_type));
        output->privilege_level = client.authInfo.authFlag;

        *_output = output;

        return 0;
    } // rs_switch_user

    using operation = std::function<int(RsComm*, SwitchUserInput*, SwitchUserOutput**)>;
    const operation op = rs_switch_user;
#  define CALL_SWITCH_USER call_switch_user
} // anonymous namespace

#else // RODS_SERVER

//
// Client-side Implementation
//

namespace
{
    using operation = std::function<int(RsComm*, SwitchUserInput*, SwitchUserOutput**)>;
    const operation op{};
#  define CALL_SWITCH_USER nullptr // NOLINT(cppcoreguidelines-macro-usage)
} // anonymous namespace

#endif // RODS_SERVER

// The plugin factory function must always be defined.
extern "C" auto plugin_factory(
    const std::string& _instance_name, // NOLINT(bugprone-easily-swappable-parameters)
    const std::string& _context) -> irods::api_entry*
{
    static_cast<void>(_instance_name);
    static_cast<void>(_context);

#ifdef RODS_SERVER
    irods::client_api_allowlist::instance().add(SWITCH_USER_APN);
#endif // RODS_SERVER

    // clang-format off
    irods::apidef_t def{SWITCH_USER_APN,            // API number
                        RODS_API_VERSION,           // API version
                        NO_USER_AUTH,               // Client auth
                        NO_USER_AUTH,               // Proxy auth
                        "SwitchUserInp_PI", 0,      // In PI / bs flag
                        "SwitchUserOut_PI", 0,      // Out PI / bs flag
                        op,                         // Operation
                        "api_switch_user",          // Operation name
                        nullptr,                    // Null clear function
                        (funcPtr) CALL_SWITCH_USER};
    // clang-format on

    auto* api = new irods::api_entry{def}; // NOLINT(cppcoreguidelines-owning-memory)

    api->in_pack_key = "SwitchUserInp_PI";
    api->in_pack_value = SwitchUserInp_PI;

    api->out_pack_key = "SwitchUserOut_PI";
    api->out_pack_value = SwitchUserOut_PI;

    return api;
} // plugin_factory

