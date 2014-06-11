/*
This software is in the public domain. Where that dedication is not recognized,
you are granted a perpetual, irrevocable license to copy and modify this file
as you see fit.
*/

#ifndef _BASE64_H_
#define _BASE64_H_

#include <stdint.h>
#include <stddef.h>

int base64_encode(uint8_t* src, size_t n, char* dst);

#endif /*_BASE64_H_*/
