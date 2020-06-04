#ifndef IRODS_COMPRESSION_INPUT_H
#define IRODS_COMPRESSION_INPUT_H

#include "compression_algorithm.h"

typedef struct compression_input
{
    int fd;
    compression_t compression;
} compression_input_t;

#define CompressionInp_PI "int fd; int compression;"

#endif // IRODS_COMPRESSION_INPUT_H
