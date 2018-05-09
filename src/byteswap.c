#include "byteswap.h"

/* Byte swapping functions for various inttypes */
uint64_t byteswap64(uint64_t num)
{
	return (byteswap32((num&0xFFFFFFFF00000000ULL)>>32))
	      |((uint64_t)byteswap32(num&0x00000000FFFFFFFFULL)<<32);
}

uint32_t byteswap32(uint32_t num)
{
	return ((num&0x000000FFU)<<24)
		| ((num&0x0000FF00U)<<8)
		| ((num&0x00FF0000U)>>8)
		| ((num&0xFF000000U)>>24);
}

uint16_t byteswap16(uint16_t num)
{
	return ((num<<8)&0xFF00)|((num>>8)&0x00FF);
}

