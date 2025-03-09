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
#include "include/lk3rd/theme.h"

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

const char* get_action_text(enum action current_action)
{
	switch(current_action)
	{
		case ACTION_START:
			return "START";
		case ACTION_REBOOT_RECOVERY:
			return "Reboot recovery";
		case ACTION_REBOOT_BOOTLOADER:
			return "Reboot bootloader";
		case ACTION_REBOOT_FASTBOOTD:
			return "Reboot FastbootD";
		case ACTION_REBOOT_DOWNLOAD:
			return "Reboot Download";
		case ACTION_POWEROFF:
			return "Power off";
		case ACTION_SWITCH_THEME:
			return "Switch theme";
		default:
			return "Unknown action";
	}
}

u32 get_action_colour(enum action current_action)
{
	switch(current_action)
	{
		case ACTION_START:
			return FONT_GREEN;
		case ACTION_REBOOT_RECOVERY:
			return FONT_YELLOW;
		case ACTION_REBOOT_BOOTLOADER:
			return FONT_RED;
		case ACTION_REBOOT_FASTBOOTD:
			return FONT_ORANGE;
		case ACTION_REBOOT_DOWNLOAD:
			return FONT_BLUE;
		case ACTION_POWEROFF:
			return FONT_RED;
		case ACTION_SWITCH_THEME:
			return FONT_WHITE;
		default:
			return FONT_WHITE;
	}
}

void draw_menu(enum action current_action)
{
	switch (lk3rd_get_theme())
	{
		case THEME_DEBUG:
			for (int i = 0; i < LCD_HEIGHT; i+=100)
				draw_rectangle(0, i, LCD_WIDTH, 50, FONT_BLUE);
			
			for (int i = 0; i < LCD_WIDTH; i+=100)
				draw_rectangle(i, 0, 50, LCD_HEIGHT, FONT_RED);

			for (int i = 0; i < LCD_HEIGHT; i += 200) {
				char coord_text[50];
				snprintf(coord_text, sizeof(coord_text), "(%d, %d)", 0, i);
				update_y_pos(i);
				print_lcd(FONT_GREEN, FONT_BLACK, coord_text);
			}
			__attribute__ ((fallthrough));
						
		case THEME_SNAPDRAGON:
			clear_line(FONT_BLACK, FONT_Y, true);
			u32 font_color = get_action_colour(current_action);
			draw_line_lcd(font_color, FONT_BLACK);
			print_lcd_update(font_color, FONT_BLACK, get_action_text(current_action));
			draw_line_lcd(font_color, FONT_BLACK);

			update_y_pos(get_y_pos() + FONT_Y);
			print_lcd_update(FONT_WHITE, FONT_BLACK, "Press volume key to select, and press power key to select");
			update_y_pos(get_y_pos() + FONT_Y);
			print_lcd_update(FONT_RED,   FONT_BLACK, "lk3rd FastBoot Mode", MAX_NUM_CHAR_PER_LINE);

			break;
#if defined(POWER_TOP) && defined(POWER_HEIGHT) && defined(VOL_TOP) && defined(VOL_HEIGHT)
		case THEME_PIXEL:
			int start_offset = LCD_WIDTH / 12.1;

			int chevron_height = LCD_HEIGHT / 77.2;
			int chevron_width = LCD_WIDTH / 24;
			int chevron_thickness = LCD_WIDTH / 144;

			int power_width = LCD_WIDTH / 14.4;
			int power_radius = LCD_WIDTH / 120;

			int text_offset = LCD_WIDTH / 8.8888888888888;

			int warning_x = LCD_WIDTH / 13;
			int warning_y = LCD_HEIGHT * .566;
			int warning_width = LCD_WIDTH * 1 / 8;
			int warning_height = LCD_HEIGHT * .05;
			int warning_thickness = LCD_WIDTH / 80;

			draw_line(LCD_WIDTH - start_offset, VOL_TOP + chevron_height, LCD_WIDTH - start_offset + chevron_width / 2, VOL_TOP, chevron_thickness, FONT_WHITE);					// `  //\\  `
			draw_line(LCD_WIDTH - start_offset + chevron_width / 2, VOL_TOP, LCD_WIDTH - start_offset + chevron_width, VOL_TOP + chevron_height, chevron_thickness, FONT_WHITE); 	// ` //  \\ `
			draw_line(LCD_WIDTH - start_offset, VOL_TOP + VOL_HEIGHT - chevron_height, LCD_WIDTH - start_offset + chevron_width / 2, VOL_TOP + VOL_HEIGHT, chevron_thickness, FONT_WHITE);					// ` \\  // `
			draw_line(LCD_WIDTH - start_offset + chevron_width / 2, VOL_TOP + VOL_HEIGHT, LCD_WIDTH - start_offset + chevron_width, VOL_TOP + VOL_HEIGHT - chevron_height, chevron_thickness, FONT_WHITE); // `   \\//  `

			update_y_pos(VOL_TOP + VOL_HEIGHT / 2 - FONT_Y);
			print_lcd(FONT_WHITE, FONT_BLACK, add_padding(LCD_WIDTH - strlen("Press the volume keys") * FONT_X - text_offset,  0, "Press the volume keys"));
			print_lcd(FONT_WHITE, FONT_BLACK, add_padding(LCD_WIDTH - strlen("to select different menu") * FONT_X - text_offset,  0, "to select different menu"));

			draw_full_squircle(LCD_WIDTH - start_offset, POWER_TOP, power_width, POWER_HEIGHT, power_radius, FONT_WHITE);
			update_y_pos(POWER_TOP + POWER_HEIGHT / 2 - FONT_Y / 2);
			const char* action_text = get_action_text(current_action);
			print_lcd(FONT_WHITE, FONT_BLACK, add_padding(LCD_WIDTH - strlen(action_text) * FONT_X - text_offset,  0, action_text));

			draw_triangle(warning_x + warning_width / 2, warning_y, warning_x, warning_y + warning_height, warning_x + warning_width, warning_y + warning_height, FONT_RED); // triangle
			draw_full_squircle(warning_x + warning_width / 2 - warning_thickness / 2, warning_y + warning_height / 3, warning_thickness,  warning_height / 3, warning_thickness / 2, FONT_BLACK); // |
			draw_circle(warning_x + warning_width / 2 - warning_thickness / 2, warning_y + warning_height * 27 / 36, warning_thickness / 2, FONT_BLACK); //											 .

			update_y_pos(LCD_HEIGHT * .64);
			print_lcd_update(FONT_RED, FONT_BLACK, "lk3rd FastBoot Mode", MAX_NUM_CHAR_PER_LINE);
			update_y_pos(LCD_HEIGHT * .66);
			break;
#endif
		case THEME_UNIFIED:
			update_y_pos(0);
			for (int i = 0; i < ACTION_END; i++)
			{
				if (i == (int)current_action)
				{
					draw_line_lcd(get_action_colour(i), FONT_BLACK);
					print_lcd_update(get_action_colour(i), FONT_BLACK, get_action_text(i));
					draw_line_lcd(get_action_colour(i), FONT_BLACK);
				}
				else
				{
					clear_line(FONT_BLACK, get_y_pos(), false);
					update_y_pos(get_y_pos() + FONT_Y);
					print_lcd_update(FONT_GRAY, FONT_BLACK, get_action_text(i));
					clear_line(FONT_BLACK, get_y_pos(), false);
					update_y_pos(get_y_pos() + FONT_Y);
				}
			}

			update_y_pos(get_y_pos() + FONT_Y);
			print_lcd_update(FONT_WHITE, FONT_BLACK, "Press volume key to select, and press power key to select");
			update_y_pos(get_y_pos() + FONT_Y);
			print_lcd_update(FONT_RED,   FONT_BLACK, "lk3rd FastBoot Mode", MAX_NUM_CHAR_PER_LINE);

			break;

		default:
			break;
	}
	
	print_lcd_update(FONT_WHITE, FONT_BLACK, "PRODUCT_NAME - %s", version.platform);
	print_lcd_update(FONT_WHITE, FONT_BLACK, "BOOTLOADER VERSION - 2.0 (%s)", version.buildid);
	print_lcd_update(FONT_RED,   FONT_BLACK, "DEVICE STATE - unlocked");
	if(lk3rd_get_mainline_quirks() == 1)
		print_lcd_update(FONT_YELLOW, FONT_BLACK, "MAINLINE QUIRKS - enabled "); 
	else
		print_lcd_update(FONT_GREEN, FONT_BLACK,  "MAINLINE QUIRKS - disabled");
	print_lcd_update(FONT_GREEN, FONT_BLACK, "THEME - %s", lk3rd_get_current_theme_name());
}
