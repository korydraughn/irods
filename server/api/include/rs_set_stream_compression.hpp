#ifndef IRODS_RS_SET_STREAM_COMPRESSION_HPP
#define IRODS_RS_SET_STREAM_COMPRESSION_HPP

/// \file

#include "compression_input.h"

struct rsComm;

#ifdef __cplusplus
extern "C" {
#endif

/// Sets the compression algorithm used for streaming data in/out of the opened replica.
///
/// \user Server
///
/// \since 4.2.9
///
/// \param[in] comm  A pointer to a rsComm_t.
/// \param[in] input A compression_input containing the open file descriptor and compression to use.
///
/// \return An integer.
/// \retval 0        On success.
/// \retval non-zero On failure.
int rs_set_stream_compression(struct rsComm* comm, const compression_input_t* input);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_RS_SET_STREAM_COMPRESSION_HPP

