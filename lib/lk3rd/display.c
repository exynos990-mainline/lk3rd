/*
 * Copyright (c) 2024 Igor Belwon <igor.belwon@mentallysanemainliners.org>
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 *
 */
#include <lib/font_display.h>
#include <lib/version.h>
#include <stdlib.h>
#include <string.h>

#include "include/lk3rd/display.h"
#include "include/lk3rd/fastboot_menu.h"
#include "include/lk3rd/mainline_quirks.h"
#include "../lib/font/exynos_font.h"

void draw_line_lcd(int color_fg, int color_bg)
{
	char *str = malloc(MAX_NUM_CHAR_PER_LINE + 1);
	memset(str, '-', MAX_NUM_CHAR_PER_LINE);
	str[MAX_NUM_CHAR_PER_LINE] = '\0';
	print_lcd_update(color_fg, color_bg, str);
}

const char* add_padding(uint16_t left, uint16_t right, const char *str)
{
	int left_spaces = left / FONT_X;
	int right_spaces = right / FONT_X;
	int str_len = strlen(str);
	int total_len = left_spaces + str_len + right_spaces;

	char *padded_str = malloc(total_len + 1);
	memset(padded_str, ' ', total_len);
	memcpy(padded_str + left_spaces, str, str_len);
	padded_str[total_len] = '\0';

	return padded_str;
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

const char* get_action_text(enum action current_action)
{
	switch(current_action)
	{
		case ACTION_START:
			return "Start";
		case ACTION_REBOOT_RECOVERY:
			return "Reboot Recovery";
		case ACTION_REBOOT_BOOTLOADER:
			return "Reboot Bootloader";
		case ACTION_REBOOT_FASTBOOTD:
			return "Reboot FastbootD";
		case ACTION_REBOOT_DOWNLOAD:
			return "Reboot Download";
		case ACTION_POWEROFF:
			return "Power Off";
		default:
			return "Unknown Action";
	}
}

void draw_menu(enum action current_action)
{
	int start_offset = LCD_WIDTH / 12.1;

	int chevron_height = LCD_HEIGHT / 77.2;
	int chevron_width = LCD_WIDTH / 24;
	int chevron_offset = (start_offset - chevron_width) / 2;  // Calculate centering offset
	int chevron_thickness = LCD_WIDTH / 210;

	int power_width = LCD_WIDTH / 14.4;
	int power_radius = LCD_WIDTH / 120;

	int text_offset = LCD_WIDTH / 8.8888888888888;

	int warning_x = LCD_WIDTH / 13;
	int warning_y = LCD_HEIGHT * .566;
	int warning_width = LCD_WIDTH * (1 / 10);
	int warning_height = LCD_HEIGHT * .07;
	int warning_thickness = LCD_WIDTH / 80;

	draw_line(LCD_WIDTH - start_offset + chevron_offset, VOL_TOP + chevron_height, LCD_WIDTH - start_offset + chevron_offset + chevron_width / 2, VOL_TOP, chevron_thickness, FONT_WHITE);						//  "//\\"
	draw_line(LCD_WIDTH - start_offset + chevron_offset + chevron_width / 2, VOL_TOP, LCD_WIDTH - start_offset + chevron_offset + chevron_width, VOL_TOP + chevron_height, chevron_thickness, FONT_WHITE);				// "//  \\"

	draw_line(LCD_WIDTH - start_offset + chevron_offset, VOL_TOP + VOL_HEIGHT - chevron_height, LCD_WIDTH - start_offset + chevron_offset + chevron_width / 2, VOL_TOP + VOL_HEIGHT, chevron_thickness, FONT_WHITE);		// "\\  //"
	draw_line(LCD_WIDTH - start_offset + chevron_offset + chevron_width / 2, VOL_TOP + VOL_HEIGHT, LCD_WIDTH - start_offset + chevron_offset + chevron_width, VOL_TOP + VOL_HEIGHT - chevron_height, chevron_thickness, FONT_WHITE); // "\\//" 

	update_y_pos(VOL_TOP + VOL_HEIGHT / 2 - FONT_Y);
	print_lcd(FONT_WHITE, FONT_BLACK, add_padding(LCD_WIDTH - strlen("Press the volume keys") * FONT_X - text_offset,  0, "Press the volume keys"));
	print_lcd(FONT_WHITE, FONT_BLACK, add_padding(LCD_WIDTH - strlen("to select different menu") * FONT_X - text_offset,  0, "to select different menu"));

	draw_full_squircle(LCD_WIDTH - start_offset, POWER_TOP, power_width, POWER_HEIGHT, power_radius, FONT_WHITE);
	draw_rectangle(LCD_WIDTH - 10 - start_offset + power_width, POWER_TOP, 10 + start_offset - power_width, POWER_HEIGHT, FONT_WHITE);

	update_y_pos(POWER_TOP + POWER_HEIGHT / 2 - FONT_Y / 2);

	draw_line(LCD_WIDTH - start_offset + start_offset / 3, POWER_TOP + (POWER_HEIGHT / 2) - (chevron_height / 2), LCD_WIDTH - start_offset + (2 * start_offset) / 3, POWER_TOP + (POWER_HEIGHT / 2), chevron_thickness, FONT_BLACK); // "\"
	draw_line(LCD_WIDTH - start_offset + (2 * start_offset) / 3, POWER_TOP + (POWER_HEIGHT / 2), LCD_WIDTH - start_offset + start_offset / 3, POWER_TOP + (POWER_HEIGHT / 2) + (chevron_height / 2), chevron_thickness, FONT_BLACK); // "/"

	const char* action_text = get_action_text(current_action);
	print_lcd(FONT_WHITE, FONT_BLACK, add_padding(LCD_WIDTH - strlen(action_text) * FONT_X - text_offset,  0, action_text));

	draw_triangle(warning_x + warning_width / 2, warning_y, warning_x, warning_y + warning_height, warning_x + warning_width, warning_y + warning_height, FONT_RED); // triangle
	draw_full_squircle(warning_x + warning_width / 2 - warning_thickness / 2, warning_y + warning_height / 3, warning_thickness,  warning_height / 3, warning_thickness / 2, FONT_BLACK); // |
	draw_circle(warning_x + warning_width / 2 - warning_thickness / 2, warning_y + warning_height * 27 / 36, warning_thickness / 2, FONT_BLACK); //						 .

	update_y_pos(LCD_HEIGHT * .64);
	print_lcd_update(FONT_RED, FONT_BLACK, "lk3rd FastBoot Mode", MAX_NUM_CHAR_PER_LINE);
	update_y_pos(LCD_HEIGHT * .66);

	print_lcd_update(FONT_WHITE, FONT_BLACK, "PRODUCT_NAME - %s", version.platform);
	print_lcd_update(FONT_WHITE, FONT_BLACK, "BOOTLOADER VERSION - 2.0 (%s)", version.buildid);

	u32 orig_y_pos = get_y_pos();

	print_lcd_update(FONT_WHITE, FONT_BLACK, "DEVICE STATE - ");

	update_y_pos(orig_y_pos);

	print_lcd_update(FONT_RED,   FONT_BLACK, empty_pad_string(strlen("DEVICE STATE - "), "unlocked"));

	if(lk3rd_get_mainline_quirks() == 1)
		print_lcd_update(FONT_YELLOW, FONT_BLACK, "MAINLINE QUIRKS - enabled "); 
	else
		print_lcd_update(FONT_GREEN, FONT_BLACK,  "MAINLINE QUIRKS - disabled");

	print_lcd_update(FONT_BLACK, FONT_BLACK, ""); // Padding for any device messages
}
