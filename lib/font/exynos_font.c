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
#include <stdlib.h>

#include "exynos_font.h"
#include <dpu/lcd_ctrl.h>

#include <platform/mmu/cache.h>

#include <target/dpu_config.h>

#include <lib/font_display.h>

#define PRINT_BUF_SIZE			384
#define TOP_MARGIN			40
#define MAX_NUM_CHAR_PER_LINE		(LCD_WIDTH / (FONT_X + 1))
#define ALPHANUMERIC_OFFSET		0
#define LENGTH_OF_A_CHAR_ARRAY		((FONT_Y) * 2)
#define FONT_PTR_BIT			(((FONT_X) / 2) - 1)
#ifndef LCD_OFFSET 
#define LCD_OFFSET			0
#endif

#define WARNING_TEXT_PADDING 18
#define MIN_BOX_HEIGHT 250

extern bool brightness_lowered;
extern bool in_fastboot_menu;
extern u32 orig_y_pos;
static u32 y_pos = 0;
u32 _win_fb0 = 0xf1000000;
extern void decon_string_update(void);

void draw_pixel(uint32_t x, uint32_t y, uint32_t color)
{
	if(brightness_lowered)
	{
		color = (color & 0xFF000000) | ((color & 0x00FCFCFC) >> 2);
	}

	volatile u32 *_fb = (u32*)0xf1000000;
	_fb[(y + LCD_OFFSET) * LCD_WIDTH + x] = color;
}

// Yes these are using bit magic for division and multiplication, fight me.

void lower_brightness(void)
{
	volatile uint64_t *fb = (volatile uint64_t *)0xF1000000;

	// Freeze FB updates to prevent flickering.
	writel(0x3070, 0x19050070);

	for (uint32_t i = 0; i < (LCD_WIDTH * LCD_HEIGHT) / 2; i++)
	{
		uint64_t c = fb[i];

		fb[i] = (c & 0xFF000000FF000000ULL) |
			((c & 0x00FCFCFC00FCFCFCULL) >> 2);
	}

	// Unfreeze FB updates.
	writel(0x1281, 0x19050070);

	clean_invalidate_dcache_all();
}

void heighten_brightness(void)
{
    volatile uint64_t *fb = (volatile uint64_t *)0xF1000000;

	// Freeze FB updates to prevent flickering.
	writel(0x3070, 0x19050070);

    for (uint32_t i = 0; i < (LCD_WIDTH * LCD_HEIGHT) / 2; i++)
    {
        uint64_t c = fb[i];
 
		fb[i] = (c & 0xFF000000FF000000ULL) |
			(((c << 2) & 0x00FCFCFC00FCFCFCULL));
	}

	// Unfreeze FB updates.
	writel(0x1281, 0x19050070);

	clean_invalidate_dcache_all();
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
				if (corners[0])
					draw_pixel(x + radius - i, y + radius - j, color);

				// Top-right corner
				if (corners[1])
					draw_pixel(x + width - radius + i - 1, y + radius - j, color);

				// Bottom-left corner
				if (corners[2])
					draw_pixel(x + radius - i, y + height - radius + j - 1, color);

				// Bottom-right corner
				if (corners[3])
					draw_pixel(x + width - radius + i - 1, y + height - radius + j - 1, color);
			}
		}
	}
	clean_invalidate_dcache_all();
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
	clean_invalidate_dcache_all();
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

/* Fill the frame buffer one character at a time */
static int fill_fb_one_char(u32 *fb_buf, u32 x_pos, u32 fb_width, char ascii,
	u32 y_pos, u32 font_color, u32 bg_color)
{
	int i, j;
	u32 offset; /* Offset of font array, exynos_font.h */
	u32 *fb_ptr;

	if(brightness_lowered)
	{
		font_color = (font_color & 0xFF000000) | ((font_color & 0x00FCFCFC) >> 2);
		bg_color = (bg_color & 0xFF000000) | ((bg_color & 0x00FCFCFC) >> 2);
	}

	/* From Null(0x00) to '~'(0x7E) */
	if (ascii < 32 || ascii > 126)
		return -1;

	offset = LENGTH_OF_A_CHAR_ARRAY * (ascii - ALPHANUMERIC_OFFSET);

	for (i = 0; i < FONT_Y; i++)
	{
		/* Move to fill next or start pixel of fb */
		fb_ptr = fb_buf + ((i + y_pos) * fb_width) + x_pos;

		/* Fill a first half part of a font width, 8bit */
		for (j = 0; j < (FONT_X / 2); j++)
		{
			if (font[offset] & (1 << j))
			{
				/* Filled area in font */
				fb_ptr[(FONT_X / 2 - 1) - j] = font_color;
			}
			else
			{
				/* Unfilled area in font */
				fb_ptr[(FONT_X / 2 - 1) - j] = bg_color;
			}
		}

		/* Move to next (FONT / 2) pixel pointer of fb */
		fb_ptr = fb_ptr + (FONT_X / 2);

		/* Move to next (FONT / 2) pixel pointer of font */
		offset++;

		/* Fill the other half part of a font width, 8bit */
		for (j = 0; j < (FONT_X / 2); j++)
		{
			if (font[offset] & (1 << j))
			{
				/* Filled area in font */
				fb_ptr[(FONT_X / 2 - 1) - j] = font_color;
			}
			else
			{
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
	memset((void *)(uintptr_t)_win_fb0, 0, LCD_WIDTH * LCD_HEIGHT * 4);
	clean_invalidate_dcache_all();
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

	if (y_pos > LCD_HEIGHT - LCD_OFFSET)
	{
		/* Rolling fb, y_pos and fb address reinit */
		y_pos = 0;
		fb_buf = (u32 *)CONFIG_DISPLAY_FONT_BASE_ADDRESS;

		if(!in_fastboot_menu)
		{
			initialize_font_fb();
		}
		else
		{
			for (int i = orig_y_pos; i < (LCD_HEIGHT - LCD_OFFSET); i += FONT_Y)
			{
				clear_line(0, i, false);
			}
			y_pos = orig_y_pos;
		}
	}

	for (i = 0; i < cnt; i++)
	{
		ch = *(str++);
		if (fill_fb_one_char(fb_buf, x_pos + (i * FONT_X), LCD_WIDTH,
			ch, y_pos + LCD_OFFSET, font_color, bg_color)) {
			// printf("This(%c) character is not supported\n", ch);
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

	do
	{
		lgth = _fill_fb_string(fb_buf, x_pos, str,
					font_color, bg_color, lgth);
		if (lgth)
		{
			/* for updating the position of the remaining
			 * string points after filling one line of the LCD.
			 */
			str = str + MAX_NUM_CHAR_PER_LINE;
		}
	} while (lgth > 0);

	clean_invalidate_dcache_all();

	return 0;
}

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
				(u8 *)printbuffer, font_color, bg_color))
	{
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
				(u8 *)printbuffer, font_color, bg_color))
	{
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

const char *empty_pad_string(u32 pad, const char *str)
{
	u32 str_length = strlen(str);
	char *padded_string = malloc(pad + str_length + 1);

	memset(padded_string, '\200', pad);
	memcpy(padded_string + pad, str, str_length);
	padded_string[pad + str_length] = '\0';

	return padded_string;
}

static int measure_lines(int text_pad, const char *text)
{
	int max_chars = MAX_NUM_CHAR_PER_LINE - text_pad;
	int lines = 0;

	while (*text)
	{
		int len = 0;
		int last_space = -1;

		if (*text == '\n')
		{
			lines++;
			text++;
			continue;
		}

		while (text[len] && text[len] != '\n' && len < max_chars)
		{
			if (text[len] == ' ')
				last_space = len;
			len++;
		}

		if (text[len] && text[len] != '\n' && last_space > 0)
			len = last_space;

		text += len;

		while (*text == ' ')
			text++;

		lines++;
	}

	return lines;
}

static void print_status_text(u32 font_color, u32 bg_color, u32 text_pad, const char *text)
{
	char line[PRINT_BUF_SIZE];
	int max_chars = MAX_NUM_CHAR_PER_LINE - text_pad;

	while (*text)
	{
		int len = 0;
		int last_space = -1;

		if (*text == '\n')
		{
			update_y_pos(get_y_pos() + FONT_Y);
			text++;
			continue;
		}

		while (text[len] && text[len] != '\n' && len < max_chars)
		{
			if (text[len] == ' ')
				last_space = len;
			len++;
		}

		if (text[len] && text[len] != '\n' && last_space > 0)
			len = last_space;

		memcpy(line, text, len);
		line[len] = '\0';

		print_lcd_update(font_color, bg_color, empty_pad_string(text_pad, line));

		text += len;

		while (*text == ' ')
			text++;
	}
}

void show_warning(const char *title, const char *fmt, ...)
{
	char text_buf[PRINT_BUF_SIZE];

	va_list args;
	va_start(args, fmt);
	vsnprintf(text_buf, sizeof(text_buf), fmt, args);
	va_end(args);

	int warning_x = LCD_WIDTH / 20;
	int warning_width = LCD_WIDTH * 3 / 32;
	int warning_height = LCD_HEIGHT * 3 / 80;
	int warning_thickness = LCD_WIDTH / 80;

	int text_pad = (warning_x + warning_width + WARNING_TEXT_PADDING) / FONT_X;

	int body_lines = measure_lines(text_pad, text_buf);
	int total_lines = 2 + body_lines;

	int text_height = total_lines * FONT_Y;

	int content_height = max(warning_height, text_height);

	int box_top = 5;
	int box_height = max(content_height + 60, MIN_BOX_HEIGHT);

	int center_y = box_top + box_height / 2;

	int icon_x = warning_x + warning_width / 2;
	int icon_y = center_y - warning_height / 2;

	int text_start_y = center_y - text_height / 2;

	draw_rectangle(0, box_top, LCD_WIDTH, box_height, FONT_RED);

	draw_triangle(icon_x, icon_y, warning_x, icon_y + warning_height, warning_x + warning_width, icon_y + warning_height, FONT_WHITE);

	draw_full_squircle(icon_x - warning_thickness / 2, icon_y + warning_height / 3, warning_thickness, warning_height / 3, warning_thickness / 2, FONT_RED);
	draw_circle(icon_x - warning_thickness / 2, icon_y + warning_height * 27 / 36, warning_thickness / 2, FONT_RED);

	update_y_pos(text_start_y);

	print_lcd_update(FONT_WHITE, FONT_RED, empty_pad_string(text_pad, title));
	print_lcd_update(FONT_WHITE, FONT_RED, "");
	print_status_text(FONT_WHITE, FONT_RED, text_pad, text_buf);
}

void show_success(const char *title, const char *fmt, ...)
{
	char text_buf[PRINT_BUF_SIZE];

	va_list args;
	va_start(args, fmt);
	vsnprintf(text_buf, sizeof(text_buf), fmt, args);
	va_end(args);

	int tick_area_x = LCD_WIDTH / 20;
	int tick_area_width = LCD_WIDTH * 3 / 32;
	int tick_area_height = LCD_HEIGHT * 3 / 80;

	int text_pad = (tick_area_x + tick_area_width + WARNING_TEXT_PADDING) / FONT_X;

	int body_lines = measure_lines(text_pad, text_buf);
	int total_lines = 2 + body_lines;

	int text_height = total_lines * FONT_Y;
	int content_height = max(tick_area_height, text_height);

	int box_top = 5;
	int box_height = max(content_height + 60, MIN_BOX_HEIGHT);

	int center_y = box_top + box_height / 2;

	int icon_center_x = tick_area_x + tick_area_width / 2;
	int icon_center_y = center_y;

	int text_start_y = center_y - text_height / 2;

	int circle_radius = LCD_WIDTH * 3 / 64;

	int tick_thickness = LCD_WIDTH / 180;

	int tick_start_x = icon_center_x - circle_radius * 5 / 12;
	int tick_start_y = icon_center_y - circle_radius / 20;

	int tick_mid_x = icon_center_x - circle_radius / 4;
	int tick_mid_y = icon_center_y + circle_radius / 4;

	int tick_end_x = icon_center_x + circle_radius * 3 / 8;
	int tick_end_y = icon_center_y - circle_radius / 4;

	draw_rectangle(0, box_top, LCD_WIDTH, box_height, 0xFF00C000);

	draw_circle(icon_center_x - circle_radius, icon_center_y - circle_radius, circle_radius, FONT_WHITE);

	draw_line(tick_start_x, tick_start_y, tick_mid_x, tick_mid_y, tick_thickness, 0xFF00C000);
	draw_line(tick_mid_x, tick_mid_y, tick_end_x, tick_end_y, tick_thickness, 0xFF00C000);

	update_y_pos(text_start_y);

	print_lcd_update(FONT_WHITE, 0xFF00C000, empty_pad_string(text_pad, title));
	print_lcd_update(FONT_WHITE, 0xFF00C000, "");
	print_status_text(FONT_WHITE, 0xFF00C000, text_pad, text_buf);
}
