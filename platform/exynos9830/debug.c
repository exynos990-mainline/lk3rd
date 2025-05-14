/*
 * Copyright@ Samsung Electronics Co. LTD
 *
 * This software is proprietary of Samsung Electronics.
 *
 * No part of this software, either material or conceptual may be copied or
 * distributed, transmitted, transcribed, stored in a retrieval system or
 * translated into any human or computer language in any form by any means,
 * electronic, mechanical, manual or otherwise, or disclosed to third parties
 * without the express written permission of Samsung Electronics.
 *
 */
#include <platform/debug.h>
#include <platform/uart.h>
#include <types.h>
#include <stdint.h>

/* Clears the framebuffer by filling it with a specified color */
void clear_screen(uint32_t color);

typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

#include <stdint.h>
#include <kernel/thread.h>
#include "exynos_font.h"

void uart_char_out(char cData);

void platform_dputc(char c)
{
#ifdef PRINT_DEBUG
	uart_char_out(c);
#endif
}

int platform_dgetc(char *c, bool wait)
{
    return 0;
}
