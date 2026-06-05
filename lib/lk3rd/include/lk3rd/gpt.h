#include <part.h>
#include <string.h>

#pragma once

#define GPT_MAX_ENTRIES 128

void utf16_to_str(const u16 *src, char *dst, int max);
void str_to_utf16(const char *src, u16 *dst, int max_u16);
void gpt_fix_crcs(struct gpt_header *hdr, struct gpt_part_table *entries);

