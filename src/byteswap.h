#ifndef LT_BYTESWAP_H_
#define LT_BYTESWAP_H_
#include <arpa/inet.h>
#include <inttypes.h>

#ifdef __cplusplus 
extern "C" {
#endif

/** Byteswaps a 64-bit value.
 *
 * @param num           The value to be byteswapped.
 * @return The byteswapped 64-bit number
 *
 */
uint64_t byteswap64(uint64_t num);

/** Byteswaps a 32-bit value.
 *
 * @param num           The value to be byteswapped.
 * @return The byteswapped 32-bit number
 *
 */
uint32_t byteswap32(uint32_t num);

/** Byteswaps a 16-bit value.
 *
 * @param num           The value to be byteswapped.
 * @return The byteswapped 16-bit number
 *
 */
uint16_t byteswap16(uint16_t num);


#if __BYTE_ORDER == __BIG_ENDIAN
#define bswap_host_to_be64(num) ((uint64_t)(num))
#define bswap_host_to_le64(num) byteswap64(num)
#define bswap_host_to_be32(num) ((uint32_t)(num))
#define bswap_host_to_le32(num) byteswap32(num)
#define bswap_host_to_be16(num) ((uint16_t)(num))
#define bswap_host_to_le16(num) byteswap16(num)

#define bswap_be_to_host64(num) ((uint64_t)(num))
#define bswap_le_to_host64(num) byteswap64(num)
#define bswap_be_to_host32(num) ((uint32_t)(num))
#define bswap_le_to_host32(num) byteswap32(num)
#define bswap_be_to_host16(num) ((uint16_t)(num))
#define bswap_le_to_host16(num) byteswap16(num)

/* We use ntoh*() here, because the compiler may
 * attempt to optimise it
 */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define bswap_host_to_be64(num) (byteswap64(num))
#define bswap_host_to_le64(num) ((uint64_t)(num))
#define bswap_host_to_be32(num) (htonl(num))
#define bswap_host_to_le32(num) ((uint32_t)(num))
#define bswap_host_to_be16(num) (htons(num))
#define bswap_host_to_le16(num) ((uint16_t)(num))

#define bswap_be_to_host64(num) (byteswap64(num))
#define bswap_le_to_host64(num) ((uint64_t)(num))
#define bswap_be_to_host32(num) (ntohl(num))
#define bswap_le_to_host32(num) ((uint32_t)(num))
#define bswap_be_to_host16(num) (ntohs(num))
#define bswap_le_to_host16(num) ((uint16_t)(num))

#else
#error "Unknown byte order"
#endif

#ifdef __cplusplus 
}
#endif

#endif
