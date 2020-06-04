#include "compression_input.h"
#include "set_stream_compression.h"

#include "api_plugin_number.h"
#include "procApiRequest.h"
#include "rodsErrorTable.h"

extern "C"
int rc_set_stream_compression(rcComm* comm, const compression_input_t* input)
{
    if (!input) {
        return SYS_INVALID_INPUT_PARAM;
    }
    
    return procApiRequest(comm,
                          SET_STREAM_COMPRESSION_APN,
                          const_cast<compression_input_t*>(input),
                          nullptr, nullptr, nullptr);
}

