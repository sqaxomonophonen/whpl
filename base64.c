/*
This software is in the public domain. Where that dedication is not recognized,
you are granted a perpetual, irrevocable license to copy and modify this file
as you see fit.
*/

#include "base64.h"
#include <stdio.h>

static char _b64_chr(uint8_t i)
{
	i = i & 63;
	if (i < 26) return 'A' + (i - 0);
	if (i < 52) return 'a' + (i - 26);
	if (i < 62) return '0' + (i - 52);
	if (i == 62) return '+';
	if (i == 63) return '/';
	return '?';
}

int base64_encode(uint8_t* src, size_t n, char* dst)
{
	while (n > 2) {
		dst[0] = _b64_chr(src[0] >> 2);
		dst[1] = _b64_chr((src[0] << 4) + (src[1] >> 4));
		dst[2] = _b64_chr((src[1] << 2) + (src[2] >> 6));
		dst[3] = _b64_chr(src[2]);
		src += 3;
		n -= 3;
		dst += 4;
	}
	switch (n) {
		case 0:
			dst[0] = 0;
			break;
		case 1:
			dst[0] = _b64_chr(src[0] >> 2);
			dst[1] = _b64_chr(src[0] << 4);
			dst[2] = '=';
			dst[3] = '=';
			dst[4] = 0;
			break;
		case 2:
			dst[0] = _b64_chr(src[0] >> 2);
			dst[1] = _b64_chr((src[0] << 4) + (src[1] >> 4));
			dst[2] = _b64_chr(src[1] << 2);
			dst[3] = '=';
			dst[4] = 0;
			break;
	}
	return 0;
}

