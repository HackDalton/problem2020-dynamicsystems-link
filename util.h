#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdint.h>
#include <stdio.h>

uint32_t crc32(uint32_t crc, const void *buf, size_t size);

#endif