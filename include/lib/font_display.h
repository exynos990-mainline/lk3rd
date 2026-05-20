/* Copyright (c) 2018 Samsung Electronics Co, Ltd.

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.

 * Copyright@ Samsung Electronics Co. LTD
 * Manseok Kim <manseoks.kim@samsung.com>

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

#ifndef __FONT_DISPLAY_H__
#define __FONT_DISPLAY_H__

#include <target/dpu_config.h>
#include <stdbool.h>

#define FONT_BLACK		0xFF000000
#define FONT_GRAY		0xFF808080
#define FONT_WHITE		0xFFFFFFFF
#define FONT_RED		0xFFFF0000
#define FONT_GREEN		0xFF00FF00
#define FONT_BLUE		0xFF0000FF
#define FONT_YELLOW		0xFFFFFF00
#define FONT_ORANGE		0xFFFFA000

#ifdef CONFIG_DISPLAY_DRAWFONT
int print_lcd(u32 font_color, u32 bg_color, const char *fmt, ...);
int print_lcd_update(u32 font_color, u32 bg_color, const char *fmt, ...);
#else
#define print_lcd(font_color, bg_color, fmt, str...) do {} while (0)
#define print_lcd_update(font_color, bg_color, fmt, str...) do {} while (0)
#endif

void draw_pixel(uint32_t x, uint32_t y, uint32_t color);
void draw_line(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint width, uint32_t color);

void draw_squircle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t radius, uint32_t color, bool corners[4]);
void draw_full_squircle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t radius, uint32_t color);
void draw_circle(uint32_t x, uint32_t y, uint32_t radius, uint32_t color);
void draw_rectangle(uint32_t x, uint32_t y, uint32_t width, uint32_t height, uint32_t color);
void draw_triangle(uint32_t x1, uint32_t y1, uint32_t x2, uint32_t y2, uint32_t x3, uint32_t y3, uint32_t fill_colour);

void clear_screen(uint32_t color);
void clear_line(uint32_t color, uint32_t line_number, bool reset_y_pos);

u32 get_y_pos(void);
void update_y_pos(u32 y);

const char *empty_pad_string(u32 pad, const char *str);

void lower_brightness(void);
void heighten_brightness(void);

#endif /* __FONT_DISPLAY_H__ */
