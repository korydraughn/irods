#ifndef IRODS_SET_STREAM_COMPRESSION_H
#define IRODS_SET_STREAM_COMPRESSION_H

/// \file

#include "compression_input.h"

struct rcComm;

#ifdef __cplusplus
extern "C" {
#endif

/// Sets the compression algorithm used for streaming data in/out of the opened replica.
///
/// \user Client
///
/// \since 4.2.9
///
/// \param[in] comm  A pointer to a rcComm_t.
/// \param[in] input A compression_input_t containing the open file descriptor and compression to use.
///
/// \return An integer.
/// \retval 0        On success.
/// \retval non-zero On failure.
int rc_set_stream_compression(struct rcComm* comm, const compression_input_t* input);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_SET_STREAM_COMPRESSION_H

