/* Copyright (c) 2018 Samsung Electronics Co, Ltd.

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.

 *

 * Alternatively, Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <lk/reg.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h> /* TODO : divide print_lcd function */
#include <stdbool.h>

#include "exynos_font.h"
#include <dpu/lcd_ctrl.h>
#include <target/dpu_config.h>

/*
#include <target/lcd_module.h>
*/

typedef unsigned char u8;
typedef unsigned int u32;

static u32 y_pos = 0;

#define MAX_NUM_CHAR_PER_LINE		(LCD_WIDTH / (FONT_X + 1))
#define ALPHANUMERIC_OFFSET		0
#define LENGTH_OF_A_CHAR_ARRAY		((FONT_Y) * 2)
#define FONT_PTR_BIT			(((FONT_X) / 2) - 1)
#ifndef LCD_OFFSET 
#define LCD_OFFSET			0
#endif

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef abs
#define abs(a) (((int)(a) < 0) ? -(a) : (a))
#endif

void draw_pixel(uint32_t x, uint32_t y, uint32_t color)
{
	volatile u32 *_fb = (u32*)0xf1000000;
	_fb[(y + LCD_OFFSET) * LCD_WIDTH + x] = color;
}

void draw_squircle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t radius, uint32_t color, bool corners[4])
{
	if (radius > min(width, height) / 2)
	{
		radius = min(width, height) / 2;
	}

	for (uint32_t i = 0; i < height; i++)
	{
		for (uint32_t j = 0; j < width - 2 * radius; j++)
		{
			draw_pixel(x + radius + j, y + i, color);
		}
	}

	if (radius == 0) return;

	for (uint32_t i = 0; i < height - 2 * radius; i++)
	{
		for (uint32_t j = 0; j < width; j++)
		{
			draw_pixel(x + j, y + radius + i, color);
		}
	}

    for (uint32_t i = 0; i <= radius; i++)
    {
        for (uint32_t j = 0; j <= radius; j++)
        {
            if (i * i + j * j <= radius * radius)
            {
                // Top-left corner
				if (corners[0]) draw_pixel(x + radius - i, y + radius - j, color);
				// Top-right corner
				if (corners[1]) draw_pixel(x + width - radius + i - 1, y + radius - j, color);
				// Bottom-left corner
				if (corners[2]) draw_pixel(x + radius - i, y + height - radius + j - 1, color);
				// Bottom-right corner
				if (corners[3]) draw_pixel(x + width - radius + i - 1, y + height - radius + j - 1, color);
            }
        }
    }
}

void draw_line(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t width, uint32_t color)
{
	int dx = x2 - x1;
	int dy = y2 - y1;
	int steps = max(abs(dx), abs(dy));
	float x_inc = dx / (float)steps;
	float y_inc = dy / (float)steps;

	for (int i = 0; i < steps; i++)
	{
		draw_squircle(x1 + i * x_inc, y1 + i * y_inc, width, width, 0, color, (bool[]){true, true, true, true});
	}
}

void draw_full_squircle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t radius, uint32_t color)
{
	draw_squircle(x, y, width, height, radius, color, (bool[]){true, true, true, true});
}

void draw_circle(uint32_t x, uint32_t y, uint32_t radius, uint32_t color)
{
	draw_squircle(x, y, 2 * radius, 2 * radius, radius, color, (bool[]){true, true, true, true});
}

void draw_rectangle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t color)
{
	draw_full_squircle(x, y, width, height, 0, color);
}

void draw_triangle(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t x3, uint32_t y3, uint32_t fill_colour)
{
	/*
	 *      x1,y1
	 *        /\
	 *       /  \
	 *      /    \
	 *     /______\
	 *   x2,y2   x3,y3
	 */

	int minX = min(x1, min(x2, x3));
	int minY = min(y1, min(y2, y3));
	int maxX = max(x1, max(x2, x3));
	int maxY = max(y1, max(y2, y3));

	for (int x = minX; x <= maxX; x++)
	{
		for (int y = minY; y <= maxY; y++)
		{
			int w0 = (x1 - x) * (y2 - y1) - (x2 - x1) * (y1 - y);
			int w1 = (x2 - x) * (y3 - y2) - (x3 - x2) * (y2 - y);
			int w2 = (x3 - x) * (y1 - y3) - (x1 - x3) * (y3 - y);

			if ((w0 >= 0 && w1 >= 0 && w2 >= 0) || (w0 <= 0 && w1 <= 0 && w2 <= 0))
			{
				draw_pixel(x, y, fill_colour);
			}
		}
	}
}

/* Clears the framebuffer by filling it with a specified color */
void clear_screen(uint32_t color)
{
	y_pos = 0;
	draw_rectangle(0, 0, LCD_WIDTH, LCD_HEIGHT, color);
}

void clear_line(uint32_t color, uint32_t clear_y_pos, bool reset_y_pos)
{
	if (reset_y_pos) y_pos = 0;
	draw_rectangle(0, clear_y_pos, LCD_WIDTH, FONT_Y, color);
}

#define FONT_SCALE 2

/* Fill the frame buffer one character at a time */
static int fill_fb_one_char(u32 *fb_buf, u32 x_pos, u32 fb_width, char ascii,
	u32 y_pos, u32 font_color, u32 bg_color)
{
int i, j;
u32 offset; /* Offset of font array, exynos_font.h */
u32 *fb_ptr;

/* From Null(0x00) to '~'(0x7E) */
if (ascii < 32 || ascii > 126)
	return -1;

offset = LENGTH_OF_A_CHAR_ARRAY * (ascii - ALPHANUMERIC_OFFSET);

	for (i = 0; i < FONT_Y; i++) {
		/* Move to fill next or start pixel of fb */
		fb_ptr = fb_buf + ((i + y_pos) * fb_width) + x_pos;

		/* Fill a first half part of a font width, 8bit */
		for (j = 0; j < (FONT_X / 2); j++) {
			if (font[offset] & (1 << j)) {
				/* Filled area in font */
				fb_ptr[(FONT_X / 2 - 1) - j] = font_color;
			} else {
				/* Unfilled area in font */
				fb_ptr[(FONT_X / 2 - 1) - j] = bg_color;
			}
		}
		/* Move to next (FONT / 2) pixel pointer of fb */
		fb_ptr = fb_ptr + (FONT_X / 2);
		/* Move to next (FONT / 2) pixel pointer of font */
		offset++;
		/* Fill the other half part of a font width, 8bit */
		for (j = 0; j < (FONT_X / 2); j++) {
			if (font[offset] & (1 << j)) {
				/* Filled area in font */
				fb_ptr[(FONT_X / 2 - 1) - j] = font_color;
			} else {
				/* Unfilled area in font */
				fb_ptr[(FONT_X / 2 - 1) - j] = bg_color;
			}
		}

		/* Move to next (FONT / 2) pixel pointer of font */
		offset++;
	}

return 0;
}


static void initialize_font_fb(void)
{
	memset((void *)CONFIG_DISPLAY_FONT_BASE_ADDRESS, 0, LCD_WIDTH * LCD_HEIGHT * 4);
}

/* Fill one line of the frame buffer with characters */
static int _fill_fb_string(u32 *fb_buf, u32 x_pos, u8 *str,
		u32 font_color, u32 bg_color, int lgth)
{

	int i = 0;
	int cnt = 0;
	char ch = 0;

	if (lgth > MAX_NUM_CHAR_PER_LINE)
		cnt = MAX_NUM_CHAR_PER_LINE;
	else
		cnt = lgth;

	if (y_pos > LCD_HEIGHT - LCD_OFFSET) {
		/* Rolling fb, y_pos and fb address reinit */
		y_pos = 0;
		fb_buf = (u32 *)CONFIG_DISPLAY_FONT_BASE_ADDRESS;
		initialize_font_fb();
	}

	for (i = 0; i < cnt; i++) {
		ch = *(str++);
		if (fill_fb_one_char(fb_buf, x_pos + (i * FONT_X), LCD_WIDTH,
			ch, y_pos + LCD_OFFSET, font_color, bg_color)) {
			printf("This(%c) character is not supported\n", ch);
		}
	}

	y_pos += FONT_Y;
	lgth = lgth - MAX_NUM_CHAR_PER_LINE;

	return lgth;
}

/* Fill a frame buffer with characters */
int fill_fb_string(u32 *fb_buf, u32 x_pos, u8 *str, u32 font_color, u32 bg_color)
{
	int lgth = 0;

	if (!str)
		return 1;
	else
		lgth = strlen((char *)str);

	do {
		lgth = _fill_fb_string(fb_buf, x_pos, str,
					font_color, bg_color, lgth);
		if (lgth) {
			/* for updating the position of the remaining
			 * string points after filling one line of the LCD.
			 */
			str = str + MAX_NUM_CHAR_PER_LINE;
		}
	} while (lgth > 0);

	return 0;
}

#define PRINT_BUF_SIZE 384
#define TOP_MARGIN	40
u32 _win_fb0 = 0xf1000000;
extern void decon_string_update(void);

int print_lcd(u32 font_color, u32 bg_color, const char *fmt, ...)
{
	va_list args;
	char printbuffer[PRINT_BUF_SIZE];
	u64 ptr = _win_fb0;
	va_start(args, fmt);

	/* For this to work, printbuffer must be larger than
	 * anything we ever want to print.
	 */
	vsnprintf(printbuffer, sizeof(printbuffer), fmt, args);
	va_end(args);

	if (fill_fb_string((u32 *)ptr, TOP_MARGIN,
				(u8 *)printbuffer, font_color, bg_color)) {
		printf("failed to print on lcd\n");
		return -1;
	}

	return 0;
}

int print_lcd_update(u32 font_color, u32 bg_color, const char *fmt, ...)
{
	va_list args;
	char printbuffer[PRINT_BUF_SIZE];
	u64 ptr = _win_fb0;
	va_start(args, fmt);

	/* For this to work, printbuffer must be larger than
	 * anything we ever want to print.
	 */
	vsnprintf(printbuffer, sizeof(printbuffer), fmt, args);
	va_end(args);

	if (fill_fb_string((u32 *)ptr, TOP_MARGIN,
				(u8 *)printbuffer, font_color, bg_color)) {
		printf("failed to print on lcd\n");
		return -1;
	}

	decon_string_update();

	return 0;
}

u32 get_y_pos(void)
{
	return y_pos;
}

void update_y_pos(u32 y)
{
	y_pos = y;
}