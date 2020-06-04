#include "rs_set_stream_compression.hpp"

#include "api_plugin_number.h"
#include "rodsErrorTable.h"

#include "irods_server_api_call.hpp"

extern "C"
auto rs_set_stream_compression(rsComm* comm, const compression_input_t* input) -> int
{
    if (!input) {
        return SYS_INVALID_INPUT_PARAM;
    }

    return irods::server_api_call(SET_STREAM_COMPRESSION_APN, comm, &input);
}

