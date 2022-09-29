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

// clang-format off
#include "irods/switch_user.h"
#include "irods/irods_rs_comm_query.hpp"
#include "irods/rodsErrorTable.h"
#include "irods/irods_logger.hpp"
#include "irods/server_utilities.hpp"
#include "irods/version.hpp"

#define IRODS_USER_ADMINISTRATION_ENABLE_SERVER_SIDE_API
#include "irods/user_administration.hpp"

#include <cstring>
#include <string>
#include <string_view>
// clang-format on

// This global variable is required so that the API plugin can access RcComm connections
// created as a result of previous API calls (i.e. connections created due to redirection).
extern zoneInfo* ZoneInfoHead;

namespace
{
    //
    // Namespace and Type aliases
    //

    using log_api = irods::experimental::log::api;

    //
    // Function Prototypes
    //

    auto call_switch_user(irods::api_entry*, RsComm*, SwitchUserInput*) -> int;
    auto rs_switch_user(RsComm*, SwitchUserInput*) -> int;
    auto check_input(const SwitchUserInput*) -> int;
    auto update_server_to_server_connections(RsComm&) -> void;

    //
    // Function Implementations
    //

    auto call_switch_user(irods::api_entry* _api, RsComm* _comm, SwitchUserInput* _input) -> int
    {
        return _api->call_handler<SwitchUserInput*>(_comm, _input);
    } // call_switch_user

    auto check_input(const SwitchUserInput* _input) -> int
    {
        if (!_input) {
            log_api::error("Invalid input argument: received a null pointer");
            return SYS_INVALID_INPUT_PARAM;
        }

        if (std::strnlen(_input->username) == 0) {
            log_api::error("Invalid username argument: empty string");
            return SYS_INVALID_INPUT_PARAM;
        }

        if (std::strlen(_input->zone) == 0) {
            log_api::error("Invalid zone argument: empty string");
            return SYS_INVALID_INPUT_PARAM;
        }

        return 0;
    } // check_input

    auto update_server_to_server_connections(RsComm& _comm) -> void
    {
        const auto switch_user_or_disconnect = [&client = _comm.clientUser](rodsServerHost& _host) {
            if (!_host.conn) {
                log_api::warn("No connection to remote host [{}].", _host.hostName->name);
                return;
            }

            // Disconnect if the remote server's version is older than 4.3.1.
            // Remember, only iRODS 4.3.1 and later support the switch user API plugin.
            if (*irods::to_version(_host.conn->svrVersion->relVersion) < irods::version{4, 3, 1}) {
                rcDisconnect(_host.conn);
                return;
            }

            // At this point, we know the remote server supports this API plugin.
            if (const auto ec = rc_switch_user(_host.conn, client.userName, client.rodsZone); ec != 0) {
                log_api::error(
                    "rc_switch_user failed on remote host [{}] with error_code [{}]. Disconnecting from remote host.",
                    _host.hostName->name,
                    ec);
                rcDisconnect(_host.conn);
            }
        };

        for (auto* zone_ptr = ZoneInfoHead; zone_ptr; zone_ptr = zone_ptr->next) {
            for (auto* host_ptr = zone_ptr->primaryServerHost; host_ptr; host_ptr = host_ptr->next) {
                switch_user_or_disconnect(*host_ptr);
            }

            for (auto* host_ptr = zone_ptr->secondaryServerHost; host_ptr; host_ptr = host_ptr->next) {
                switch_user_or_disconnect(*host_ptr);
            }
        }
    } // update_server_to_server_connections

    auto rs_switch_user(RsComm* _comm, SwitchUserInput* _input) -> int
    {
        try {
            // Only administrators are allowed to invoke this API.
            // We check the proxy user because it covers clients and server-to-server redirects.
            // Remember, the client and proxy user information is identical until there's a redirect.
            if (!irods::is_privileged_proxy(*_comm)) {
                log_api::error(
                    "Proxy user [{}] does not have permission to switch client user.", _comm->proxyUser.userName);
                return SYS_PROXYUSER_NO_PRIV;
            }

            // Return immediately if the client did not provide non-empty strings for the
            // username and zone.
            if (const auto ec = check_input(_input); ec != 0) {
                return ec;
            }

            const auto* local_zone = getLocalZoneName();

            if (!local_zone) {
                log_api::error("Could not get name of local zone.");
                return SYS_INTERNAL_ERR;
            }

            namespace adm = irods::experimental::administration;

            // This call covers the existence check too.
            const auto user_type = adm::server::type(*_comm, adm::user{_input->username, _input->zone});

            if (!user_type) {
                log_api::error(
                    "[{}#{}] is not a user in the local zone [{}].", _input->username, _input->zone, local_zone);
                return CAT_INVALID_USER;
            }

            const auto* user_type_string = adm::to_c_str(*user_type);
            auto& client = _comm->clientUser;

            // Update the user identity associated with the RsComm.
            std::strncpy(client.userName, _input->username, sizeof(UserInfo::userName));
            std::strncpy(client.rodsZone, _input->zone, sizeof(UserInfo::rodsZone));
            std::strncpy(client.userType, user_type_string, sizeof(UserInfo::userType));

            // Set the appropriate privilege level based on whether the user is local or remote
            // to this zone.
            if (std::strncmp(_input->zone, local_zone, sizeof(SwitchUserInput::zone)) == 0) {
                client.authInfo.authFlag =
                    (*user_type == adm::user_type::rodsadmin) ? LOCAL_PRIV_USER_AUTH : LOCAL_USER_AUTH;
            }
            else {
                client.authInfo.authFlag =
                    (*user_type == adm::user_type::rodsadmin) ? REMOTE_PRIV_USER_AUTH : REMOTE_USER_AUTH;
            }

            // iRODS agents do not disconnect from other nodes following a redirect. For long running agents,
            // this means the API plugin must invoke rc_switch_user() on each connection.
            update_server_to_server_connections(*_comm);

            return 0;
        }
        catch (const irods::exception& e) {
            log_api::error(e.what());
            return e.code();
        }
        catch (const std::exception& e) {
            log_api::error(e.what());
            return SYS_LIBRARY_ERROR;
        }
        catch (...) {
            log_api::error("An unknown error occurred while processing the request.");
            return SYS_UNKNOWN_ERROR;
        }
    } // rs_switch_user

    using operation = std::function<int(RsComm*, SwitchUserInput*)>;
    const operation op = rs_switch_user;

// clang-format off
#define CALL_SWITCH_USER call_switch_user
// clang-format on
} // anonymous namespace

#else // RODS_SERVER

//
// Client-side Implementation
//

namespace
{
    using operation = std::function<int(RsComm*, SwitchUserInput*)>;
    const operation op{};

// clang-format off
#define CALL_SWITCH_USER nullptr // NOLINT(cppcoreguidelines-macro-usage)
// clang-format on
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
                        nullptr, 0,                 // Out PI / bs flag
                        op,                         // Operation
                        "api_switch_user",          // Operation name
                        nullptr,                    // Null clear function
                        (funcPtr) CALL_SWITCH_USER};
    // clang-format on

    auto* api = new irods::api_entry{def}; // NOLINT(cppcoreguidelines-owning-memory)

    api->in_pack_key = "SwitchUserInp_PI";
    api->in_pack_value = SwitchUserInp_PI;

    return api;
} // plugin_factory

