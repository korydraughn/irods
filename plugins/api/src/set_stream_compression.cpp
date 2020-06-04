#include "set_stream_compression.h"

#include "api_plugin_number.h"
#include "rodsDef.h"
#include "rcConnect.h"
#include "rodsPackInstruct.h"
#include "apiHandler.hpp"
#include "client_api_whitelist.hpp"

#include <functional>

#ifdef RODS_SERVER

//
// Server-side Implementation
//

#include "objDesc.hpp"
#include "irods_stacktrace.hpp"
#include "irods_server_api_call.hpp"
#include "irods_re_serialization.hpp"
#include "irods_get_l1desc.hpp"

#include <string>
#include <tuple>
#include <algorithm>

namespace
{
    using operation = std::function<int(rsComm_t*, compression_input_t*)>;
    using irods::re_serialization::serialized_parameter_t;

    //
    // Function Prototypes
    //

    auto serialize_compression_input_ptr(boost::any p, serialized_parameter_t& out) -> irods::error
    {
        try {
            compression_input_t* t = boost::any_cast<compression_input_t*>(p);

            if (t) {
                out["fd"] = std::to_string(t->fd);
                out["compression"] = std::to_string(t->compression);
            }
            else {
                out["null_value"] = "null_value";
            }
        }
        catch (const std::exception&) {
            return ERROR(INVALID_ANY_CAST, "Failed to serialize compression_input");
        }

        return SUCCESS();
    }

    auto call_set_stream_compression(irods::api_entry* api,
                                     rsComm_t* comm,
                                     compression_input_t* input) -> int
    {
        return api->call_handler<compression_input_t*>(comm, input);
    }

    auto is_input_valid(const compression_input_t* input) -> std::tuple<bool, std::string>
    {
        if (!input) {
            return {false, "Missing compression input"};
        }

        if (input->fd < 3) {
            return {false, "File descriptor out of range"};
        }

        const std::initializer_list<int> algos{
            COMPRESSION_NONE,
            COMPRESSION_SNAPPY,
            COMPRESSION_GZIP
        };

        const auto is_valid_algo = [algo = input->compression](int valid_algo) noexcept
        {
            return algo == valid_algo; 
        };

        if (!std::any_of(std::begin(algos), std::end(algos), is_valid_algo)) {
            return {false, "Invalid compression algorithm"};
        }

        return {true, ""};
    }

    auto rs_set_stream_compression(rsComm_t* comm, compression_input_t* input) -> int
    {
        if (const auto [valid, msg] = is_input_valid(input); !valid) {
            rodsLog(LOG_ERROR, msg.c_str());
            return 0;
        }

        irods::get_l1desc(input->fd).compression = input->compression;

        return 0;
    }

    const operation op = rs_set_stream_compression;
    #define CALL_SET_STREAM_COMPRESSION call_set_stream_compression
} // anonymous namespace

#else // RODS_SERVER

//
// Client-side Implementation
//

namespace
{
    using operation = std::function<int(rsComm_t*, compression_input_t*)>;
    const operation op{};
    #define CALL_SET_STREAM_COMPRESSION nullptr
} // anonymous namespace

#endif // RODS_SERVER

// The plugin factory function must always be defined.
extern "C"
auto plugin_factory(const std::string& _instance_name,
                    const std::string& _context) -> irods::api_entry*
{
#ifdef RODS_SERVER
    irods::client_api_whitelist::instance().add(SET_STREAM_COMPRESSION_APN);
#endif // RODS_SERVER

    // clang-format off
    irods::apidef_t def{SET_STREAM_COMPRESSION_APN,      // API number
                        RODS_API_VERSION,                // API version
                        NO_USER_AUTH,                    // Client auth
                        NO_USER_AUTH,                    // Proxy auth
                        "CompressionInp_PI", 0,          // In PI / bs flag
                        nullptr, 0,                      // Out PI / bs flag
                        op,                              // Operation
                        "set_stream_compression",        // Operation name
                        nullptr,                         // Null clear function
                        (funcPtr) CALL_SET_STREAM_COMPRESSION};
    // clang-format on

    auto* api = new irods::api_entry{def};

#ifdef RODS_SERVER
    irods::re_serialization::add_operation(typeid(compression_input_t*), serialize_compression_input_ptr);
#endif

    api->in_pack_key = "CompressionInp_PI";
    api->in_pack_value = CompressionInp_PI;

    return api;
}

