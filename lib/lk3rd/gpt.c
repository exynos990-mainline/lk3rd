#include <part.h>
#include <string.h>
#include <lib/cksum.h>

#include <lk3rd/gpt.h>

void utf16_to_str(const u16 *src, char *dst, int max)
{
    int i;
    for (i = 0; i < max - 1 && src[i]; i++)
        dst[i] = (char)(src[i] & 0x7F);
    dst[i] = '\0';
}

void str_to_utf16(const char *src, u16 *dst, int max_u16)
{
    int i;
    for (i = 0; i < max_u16 - 1 && src[i]; i++)
        dst[i] = (u16)(unsigned char)src[i];
    dst[i] = 0;
}

void gpt_fix_crcs(struct gpt_header *hdr, struct gpt_part_table *entries)
{
    hdr->part_table_crc = crc32(0, (const unsigned char *)entries, hdr->part_num_entry * hdr->part_size_entry);
    hdr->head_crc = 0;
    hdr->head_crc = crc32(0, (const unsigned char *)hdr, hdr->head_sz);
}
