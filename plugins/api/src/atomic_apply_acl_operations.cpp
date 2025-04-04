#include "irods/plugins/api/api_plugin_number.h"
#include "irods/irods_configuration_keywords.hpp"
#include "irods/rcMisc.h"
#include "irods/rodsDef.h"
#include "irods/rcConnect.h"
#include "irods/rodsErrorTable.h"
#include "irods/rodsPackInstruct.h"
#include "irods/client_api_allowlist.hpp"

#include "irods/apiHandler.hpp"

#include <functional>
#include <stdexcept>

#ifdef RODS_SERVER

//
// Server-side Implementation
//

#include "irods/atomic_apply_acl_operations.h"

#include "irods/catalog.hpp"
#include "irods/catalog_utilities.hpp"
#include "irods/escape_utilities.hpp"
#include "irods/irods_get_full_path_for_config_file.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_re_serialization.hpp"
#include "irods/irods_rs_comm_query.hpp"
#include "irods/irods_server_api_call.hpp"
#include "irods/irods_stacktrace.hpp"
#include "irods/miscServerFunct.hpp"
#include "irods/objDesc.hpp"
#include "irods/rodsConnect.h"
#include "irods/rodsLog.h"
#include "irods/server_utilities.hpp"

#define IRODS_QUERY_ENABLE_SERVER_SIDE_API
#include "irods/irods_query.hpp"

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include "irods/filesystem.hpp"

#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <nanodbc/nanodbc.h>

#include <cstdlib>
#include <string>
#include <string_view>
#include <tuple>
#include <chrono>
#include <system_error>

namespace
{
    // clang-format off
    namespace fs    = irods::experimental::filesystem;
    namespace ic    = irods::experimental::catalog;
    namespace log   = irods::experimental::log;

    using json      = nlohmann::json;
    using operation = std::function<int(rsComm_t*, bytesBuf_t*, bytesBuf_t**)>;
    using id_type   = std::int64_t;
    // clang-format on

    const std::unordered_map<std::string_view, int> acl_to_id{{"null", 1000},
                                                              {"read_metadata", 1040},
                                                              {"read", 1050},
                                                              {"read_object", 1050},
                                                              {"create_metadata", 1070},
                                                              {"modify_metadata", 1080},
                                                              {"delete_metadata", 1090},
                                                              {"create_object", 1110},
                                                              {"write", 1120},
                                                              {"modify_object", 1120},
                                                              {"delete_object", 1130},
                                                              {"own", 1200}};

    //
    // Function Prototypes
    //

    auto call_atomic_apply_acl_operations(irods::api_entry*, rsComm_t*, bytesBuf_t*, bytesBuf_t**) -> int;

    auto is_input_valid(const bytesBuf_t*) -> std::tuple<bool, std::string>;

    auto get_file_descriptor(const bytesBuf_t& _buf) -> int;

    auto make_error_object(const json& _op, int _op_index, const std::string& _error_msg) -> json;

    auto get_object_id(rsComm_t& _comm, std::string_view _logical_path) -> id_type;

    auto throw_if_invalid_acl(std::string_view _acl) -> void;

    auto throw_if_invalid_entity_id(id_type _entity_id) -> void;

    auto to_access_type_id(std::string_view _acl) -> int;

    auto get_entity_id(nanodbc::connection& _db_conn, std::string_view _entity_name, std::string_view _entity_zone)
        -> id_type;

    auto entity_has_acls_set_on_object(nanodbc::connection& _db_conn,
                                       const std::string_view _db_instance_name,
                                       id_type _object_id,
                                       id_type _entity_id) -> bool;

    auto insert_acl(nanodbc::connection& _db_conn,
                    const std::string_view _db_instance_name,
                    id_type _object_id,
                    id_type _entity_id,
                    std::string_view acl) -> void;

    auto update_acl(nanodbc::connection& _db_conn,
                    const std::string_view _db_instance_name,
                    id_type _object_id,
                    id_type _entity_id,
                    std::string_view new_acl) -> void;

    auto remove_acl(nanodbc::connection& _db_conn,
                    const std::string_view _db_instance_name,
                    id_type _object_id,
                    id_type _entity_id) -> void;

    auto execute_acl_operation(nanodbc::connection& _db_conn,
                               const std::string_view _db_instance_name,
                               id_type _object_id,
                               const json& _operation,
                               int _op_index) -> std::tuple<int, bytesBuf_t*>;

    auto rs_atomic_apply_acl_operations(rsComm_t*, bytesBuf_t*, bytesBuf_t**) -> int;

    //
    // Function Implementations
    //

    auto call_atomic_apply_acl_operations(irods::api_entry* _api,
                                          rsComm_t* _comm,
                                          bytesBuf_t* _input,
                                          bytesBuf_t** _output) -> int
    {
        return _api->call_handler<bytesBuf_t*, bytesBuf_t**>(_comm, _input, _output);
    }

    auto is_input_valid(const bytesBuf_t* _input) -> std::tuple<bool, std::string>
    {
        if (!_input) {
            return {false, "Missing JSON input"};
        }

        if (_input->len <= 0) {
            return {false, "Length of buffer must be greater than zero"};
        }

        if (!_input->buf) {
            return {false, "Missing input buffer"};
        }

        return {true, ""};
    }

    auto make_error_object(const json& _op, int _op_index, const std::string& _error_msg) -> json
    {
        return json{
            {"operation", _op},
            {"operation_index", _op_index},
            {"error_message", _error_msg}
        };
    }

    auto get_object_id(rsComm_t& _comm, std::string_view _logical_path) -> id_type
    {
        fs::path p = _logical_path.data();
        std::string gql;

        const auto s = fs::server::status(_comm, p);

        if (!fs::server::exists(s)) {
            log::api::error("Object does not exist at the provided logical path [path={}]", _logical_path);
            return OBJ_PATH_DOES_NOT_EXIST;
        }

        if (fs::server::is_collection(s)) {
            gql = fmt::format(
                "select COLL_ID where COLL_NAME = '{}'", irods::single_quotes_to_hex(std::string{_logical_path}));
        }
        else if (fs::server::is_data_object(s)) {
            fs::path p = _logical_path.data();
            gql = fmt::format("select DATA_ID where COLL_NAME = '{}' and DATA_NAME = '{}'",
                              irods::single_quotes_to_hex(p.parent_path()),
                              irods::single_quotes_to_hex(p.object_name()));
        }
        else {
            log::api::error("Object is not a data object or collection [path={}]", _logical_path);
            return CAT_NOT_A_DATAOBJ_AND_NOT_A_COLLECTION;
        }

        for (auto&& row : irods::query{&_comm, gql}) {
            return std::stoll(row[0]);
        }

        log::api::error("Failed to resolve path to an ID [path={}]", _logical_path);

        return SYS_UNKNOWN_ERROR;
    }

    auto throw_if_invalid_acl(std::string_view _acl) -> void
    {
        if (acl_to_id.find(_acl) == acl_to_id.cend()) {
            THROW(SYS_INVALID_INPUT_PARAM, fmt::format("Invalid ACL [acl={}]", _acl));
        }
    }

    auto throw_if_invalid_entity_id(id_type _entity_id) -> void
    {
        if (-1 == _entity_id) {
            THROW(SYS_INVALID_INPUT_PARAM, "Invalid entity");
        }
    }

    auto to_access_type_id(std::string_view _acl) -> int
    {
        return acl_to_id.at(_acl);
    }

    auto entity_has_acls_set_on_object(nanodbc::connection& _db_conn,
                                       std::string_view _db_instance_name,
                                       id_type _object_id,
                                       id_type _entity_id) -> bool
    {
        nanodbc::statement stmt{_db_conn};

        prepare(stmt, "select count(*) from R_OBJT_ACCESS where object_id = ? and user_id = ?");

        if ("oracle" == _db_instance_name) {
            const auto object_id_string = std::to_string(_object_id);
            const auto entity_id_string = std::to_string(_entity_id);

            stmt.bind(0, object_id_string.data());
            stmt.bind(1, entity_id_string.data());

            if (auto row = execute(stmt); row.next()) {
                return row.get<std::uint64_t>(0) > 0;
            }
        }
        else {
            stmt.bind(0, &_object_id);
            stmt.bind(1, &_entity_id);

            if (auto row = execute(stmt); row.next()) {
                return row.get<std::uint64_t>(0) > 0;
            }
        }

        return false;
    }

    auto insert_acl(nanodbc::connection& _db_conn,
                    const std::string_view _db_instance_name,
                    id_type _object_id,
                    id_type _entity_id,
                    std::string_view _new_acl) -> void
    {
        nanodbc::statement stmt{_db_conn};

        prepare(stmt, "insert into R_OBJT_ACCESS (object_id, user_id, access_type_id, create_ts, modify_ts) "
                      "values (?, ?, ?, ?, ?)");

        using std::chrono::system_clock;
        using std::chrono::duration_cast;
        using std::chrono::seconds;

        const auto timestamp = fmt::format("{:011}", duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
        const auto access_type_id = to_access_type_id(_new_acl);

        stmt.bind(2, &access_type_id);
        stmt.bind(3, timestamp.c_str());
        stmt.bind(4, timestamp.c_str());

        if ("oracle" == _db_instance_name) {
            const auto object_id_string = std::to_string(_object_id);
            const auto entity_id_string = std::to_string(_entity_id);

            stmt.bind(0, object_id_string.data());
            stmt.bind(1, entity_id_string.data());

            execute(stmt);
        }
        else {
            stmt.bind(0, &_object_id);
            stmt.bind(1, &_entity_id);

            execute(stmt);
        }
    }

    auto update_acl(nanodbc::connection& _db_conn,
                    const std::string_view _db_instance_name,
                    id_type _object_id,
                    id_type _entity_id,
                    std::string_view _new_acl) -> void
    {
        nanodbc::statement stmt{_db_conn};

        prepare(stmt, "update R_OBJT_ACCESS set access_type_id = ?, modify_ts = ? where object_id = ? and user_id = ?");

        using std::chrono::system_clock;
        using std::chrono::duration_cast;
        using std::chrono::seconds;

        const auto timestamp = fmt::format("{:011}", duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
        const auto access_type_id = to_access_type_id(_new_acl);

        stmt.bind(0, &access_type_id);
        stmt.bind(1, timestamp.c_str());

        if ("oracle" == _db_instance_name) {
            const auto object_id_string = std::to_string(_object_id);
            const auto entity_id_string = std::to_string(_entity_id);

            stmt.bind(2, object_id_string.data());
            stmt.bind(3, entity_id_string.data());

            execute(stmt);
        }
        else {
            stmt.bind(2, &_object_id);
            stmt.bind(3, &_entity_id);

            execute(stmt);
        }
    }

    auto remove_acl(nanodbc::connection& _db_conn,
                    const std::string_view _db_instance_name,
                    id_type _object_id,
                    id_type _entity_id) -> void
    {
        nanodbc::statement stmt{_db_conn};

        prepare(stmt, "delete from R_OBJT_ACCESS where object_id = ? and user_id = ?");

        if ("oracle" == _db_instance_name) {
            const auto object_id_string = std::to_string(_object_id);
            const auto entity_id_string = std::to_string(_entity_id);

            stmt.bind(0, object_id_string.data());
            stmt.bind(1, entity_id_string.data());

            execute(stmt);
        }
        else {
            stmt.bind(0, &_object_id);
            stmt.bind(1, &_entity_id);

            execute(stmt);
        }
    }

    auto get_entity_id(nanodbc::connection& _db_conn, std::string_view _entity_name, std::string_view _entity_zone)
        -> id_type
    {
        nanodbc::statement stmt{_db_conn};

        prepare(stmt, "select user_id from R_USER_MAIN where user_name = ? and zone_name = ?");

        stmt.bind(0, _entity_name.data());
        stmt.bind(1, _entity_zone.data());

        if (auto row = execute(stmt); row.next()) {
            return row.get<id_type>(0);
        }

        return -1;
    }

    auto execute_acl_operation(nanodbc::connection& _db_conn,
                               const std::string_view _db_instance_name,
                               id_type _object_id,
                               const json& _op,
                               int _op_index) -> std::tuple<int, bytesBuf_t*>
    {
        try {
            log::api::trace("Checking if ACL is valid ...");
            const auto acl = _op.at("acl").get<std::string>();
            throw_if_invalid_acl(acl);

            log::api::trace("Retrieving entity ID ...");

            std::string_view zone = getLocalZoneName();
            if (const auto iter = _op.find("zone"); iter != std::end(_op)) {
                zone = iter->get_ref<const std::string&>();
            }
            const auto entity_id = get_entity_id(_db_conn, _op.at("entity_name").get<std::string>(), zone);
            throw_if_invalid_entity_id(entity_id);

            if (acl == "null") {
                remove_acl(_db_conn, _db_instance_name, _object_id, entity_id);
            }
            else if (entity_has_acls_set_on_object(_db_conn, _db_instance_name, _object_id, entity_id)) {
                update_acl(_db_conn, _db_instance_name, _object_id, entity_id, acl);
            }
            else {
                insert_acl(_db_conn, _db_instance_name, _object_id, entity_id, acl);
            }

            return {0, nullptr};
        }
        catch (const nanodbc::database_error& e) {
            rodsLog(LOG_ERROR, "%s [acl_operation=%s]", e.what(), _op.dump().data());
            return {SYS_LIBRARY_ERROR, irods::to_bytes_buffer(make_error_object(_op, _op_index, e.what()).dump())};
        }
        catch (const irods::exception& e) {
            log::api::error({{"log_message", e.what()}, {"acl_operation", _op.dump()}});
            return {
                e.code(), irods::to_bytes_buffer(make_error_object(_op, _op_index, e.client_display_what()).dump())};
        }
        catch (const fs::filesystem_error& e) {
            log::api::error({{"log_message", e.what()}, {"acl_operation", _op.dump()}});
            return {e.code().value(), irods::to_bytes_buffer(make_error_object(_op, _op_index, e.what()).dump())};
        }
        catch (const json::exception& e) {
            log::api::error({{"log_message", e.what()}, {"acl_operation", _op.dump()}});
            return {SYS_INTERNAL_ERR, irods::to_bytes_buffer(make_error_object(_op, _op_index, e.what()).dump())};
        }
        catch (const std::system_error& e) {
            log::api::error({{"log_message", e.what()}, {"acl_operation", _op.dump()}});
            return {e.code().value(), irods::to_bytes_buffer(make_error_object(_op, _op_index, e.what()).dump())};
        }
    }

    auto rs_atomic_apply_acl_operations(rsComm_t* _comm, bytesBuf_t* _input, bytesBuf_t** _output) -> int
    {
        try {
            if (!ic::connected_to_catalog_provider(*_comm)) {
                log::api::trace("Redirecting request to catalog service provider ...");

                auto* host_info = ic::redirect_to_catalog_provider(*_comm);

                const std::string json_input(static_cast<const char*>(_input->buf), _input->len);
                char* json_output = nullptr;

                const auto ec = rc_atomic_apply_acl_operations(host_info->conn, json_input.data(), &json_output);
                *_output = irods::to_bytes_buffer(json_output);

                return ec;
            }

            ic::throw_if_catalog_provider_service_role_is_invalid();
        }
        catch (const irods::exception& e) {
            std::string_view msg = e.what();
            log::api::error(msg.data());
            *_output = irods::to_bytes_buffer(make_error_object(json{}, 0, msg.data()).dump());
            return e.code();
        }

        log::api::trace("Performing basic input validation ...");

        if (const auto [valid, msg] = is_input_valid(_input); !valid) {
            log::api::error(msg);
            *_output = irods::to_bytes_buffer(make_error_object(json{}, 0, "Invalid input").dump());
            return INPUT_ARG_NOT_WELL_FORMED_ERR;
        }

        json input;

        try {
            log::api::trace("Parsing string into JSON ...");
            input = json::parse(std::string(static_cast<const char*>(_input->buf), _input->len));
        }
        catch (const json::exception& e) {
            // clang-format off
            log::api::error({{"log_message", "Failed to parse input into JSON"},
                             {"error_message", e.what()}});
            // clang-format on

            const auto err_info = make_error_object(json{}, 0, e.what());
            *_output = irods::to_bytes_buffer(err_info.dump());

            return INPUT_ARG_NOT_WELL_FORMED_ERR;
        }

        std::string logical_path;

        try {
            logical_path = input.at("logical_path").get<std::string>();
        }
        catch (const json::exception& e) {
            *_output = irods::to_bytes_buffer(make_error_object(json{}, 0, e.what()).dump());
            return SYS_INVALID_INPUT_PARAM;
        }

        const id_type object_id = get_object_id(*_comm, logical_path);

        if (object_id < 0) {
            const auto msg = fmt::format("Failed to retrieve object id [error_code={}]", object_id);
            *_output = irods::to_bytes_buffer(make_error_object(json{}, 0, msg).dump());
            return object_id;
        }

        std::string db_instance_name;
        nanodbc::connection db_conn;

        try {
            log::api::trace("Connecting to database ...");
            std::tie(db_instance_name, db_conn) = ic::new_database_connection();
        }
        catch (const irods::exception& e) {
            *_output = irods::to_bytes_buffer(make_error_object(json{}, 0, e.what()).dump());
            return e.code();
        }
        catch (const std::exception& e) {
            *_output = irods::to_bytes_buffer(make_error_object(json{}, 0, e.what()).dump());
            return SYS_CONFIG_FILE_ERR;
        }

        log::api::trace("Checking if user has permission to modify permissions ...");

        if (const auto iter = input.find("admin_mode"); iter != std::end(input) && iter->get<bool>()) {
            if (!irods::is_privileged_client(*_comm)) {
                const auto msg = fmt::format(
                    "User [{}#{}] not allowed to modify ACLs [logical_path={}, object_id={}]. "
                    "admin_mode cannot be enabled because user is not an administrator.",
                    _comm->clientUser.userName,
                    _comm->clientUser.rodsZone,
                    logical_path,
                    object_id);
                log::api::error(msg);
                *_output = irods::to_bytes_buffer(make_error_object(json{}, 0, msg).dump());
                return CAT_INSUFFICIENT_PRIVILEGE_LEVEL;
            }
        }
        else if (!ic::user_has_permission_to_modify_acls(*_comm, db_conn, db_instance_name, object_id)) {
            const auto msg = fmt::format(
                "User [{}#{}] not allowed to modify ACLs [logical_path={}, object_id={}]",
                _comm->clientUser.userName,
                _comm->clientUser.rodsZone,
                logical_path.c_str(),
                object_id);
            log::api::error(msg);
            *_output = irods::to_bytes_buffer(make_error_object(json{}, 0, msg).dump());
            return CAT_NO_ACCESS_PERMISSION;
        }

        log::api::trace("Executing ACL operations ...");

        return ic::execute_transaction(db_conn, [&](auto& _trans) -> int
        {
            try {
                const auto& operations = input.at("operations");

                for (json::size_type i = 0; i < operations.size(); ++i) {
                    const auto [ec, bbuf] = execute_acl_operation(_trans.connection(),
                                                                  db_instance_name,
                                                                  object_id,
                                                                  operations[i],
                                                                  i);

                    if (ec != 0) {
                        *_output = bbuf;
                        return ec;
                    }
                }

                _trans.commit();

                *_output = irods::to_bytes_buffer("{}");

                return 0;
            }
            catch (const json::exception& e) {
                *_output = irods::to_bytes_buffer(make_error_object(json{}, 0, e.what()).dump());
                return SYS_INTERNAL_ERR;
            }
        });
    }

    const operation op = rs_atomic_apply_acl_operations;
    #define CALL_ATOMIC_APPLY_ACL_OPERATIONS call_atomic_apply_acl_operations
} // anonymous namespace

#else // RODS_SERVER

//
// Client-side Implementation
//

namespace
{
    using operation = std::function<int(rsComm_t*, bytesBuf_t*, bytesBuf_t**)>;
    const operation op{};
    #define CALL_ATOMIC_APPLY_ACL_OPERATIONS nullptr
} // anonymous namespace

#endif // RODS_SERVER

// The plugin factory function must always be defined.
extern "C"
auto plugin_factory(const std::string& _instance_name,
                    const std::string& _context) -> irods::api_entry*
{
#ifdef RODS_SERVER
    irods::client_api_allowlist::add(ATOMIC_APPLY_ACL_OPERATIONS_APN);
#endif // RODS_SERVER

    // clang-format off
    irods::apidef_t def{
        ATOMIC_APPLY_ACL_OPERATIONS_APN,    // API number
        RODS_API_VERSION,                   // API version
        REMOTE_USER_AUTH,                   // Client auth
        REMOTE_USER_AUTH,                   // Proxy auth
        "BinBytesBuf_PI", 0,                // In PI / bs flag
        "BinBytesBuf_PI", 0,                // Out PI / bs flag
        op,                                 // Operation
        "api_atomic_apply_acl_operations",  // Operation name
        clearBytesBuffer,                   // Clear input function
        clearBytesBuffer,                   // Clear output function
        (funcPtr) CALL_ATOMIC_APPLY_ACL_OPERATIONS
    };
    // clang-format on

    auto* api = new irods::api_entry{def};

    api->in_pack_key = "BinBytesBuf_PI";
    api->in_pack_value = BytesBuf_PI;

    api->out_pack_key = "BinBytesBuf_PI";
    api->out_pack_value = BytesBuf_PI;

    return api;
} // plugin_factory
