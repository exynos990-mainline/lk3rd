/*
 * Copyright (c) 2024 Igor Belwon <igor.belwon@mentallysanemainliners.org>
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 *
 */
#include <platform/device_info.h>
#include <platform/secure_boot.h>
#include <platform/usb.h>

#include <ctype.h>
#include <lib/font_display.h>
#include <lib/version.h>
#include <stdlib.h>
#include <string.h>

#include <lk3rd/boot_reason.h>
#include "include/lk3rd/display.h"
#include "include/lk3rd/fastboot_menu.h"
#include "include/lk3rd/mainline_quirks.h"
#include "include/lk3rd/kaslr_status.h"
#include "../lib/font/exynos_font.h"

u32 orig_y_pos = 0;

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

const char *title_case(const char *str) {
	char *title_str = malloc(strlen(str) + 1);
	int newWord = 1;

	strcpy(title_str, str);

	for (int i = 0; title_str[i] != '\0'; i++) {
		if (isspace(title_str[i])) {
			newWord = 1; // Next character will be a new word
		}
		else {
			if (newWord) {
				title_str[i] = toupper(title_str[i]);
				newWord = 0;
			}
			else {
				title_str[i] = tolower(title_str[i]);
			}
		}
	}

	return title_str;
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
	int warning_y = LCD_HEIGHT * .585;
	int warning_width = LCD_WIDTH * 3 / 32;
	int warning_height = LCD_HEIGHT * .0375;
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

	print_lcd_update(FONT_WHITE, FONT_BLACK, "Product name: %s", TARGET);
	print_lcd_update(FONT_WHITE, FONT_BLACK, "Bootloader version: 2.3 (%s)", version.buildid);
	print_lcd_update(FONT_WHITE, FONT_BLACK, "SoC: %s", version.platform);
	print_lcd_update(FONT_WHITE, FONT_BLACK, "Serial (ChipID): %s", fastboot_get_serialno_string());

	orig_y_pos = get_y_pos();
	print_lcd_update(FONT_WHITE, FONT_BLACK, "Secure boot: ");
	update_y_pos(orig_y_pos);

	switch(read_secure_chip())
	{
		case 0:
			print_lcd_update(FONT_RED,   FONT_BLACK, empty_pad_string(strlen("Secure boot: "), "DISABLED"));
			break;

		case 1:
			print_lcd_update(FONT_YELLOW, FONT_BLACK, empty_pad_string(strlen("Secure boot: "), "TEST KEY"));
			break;

		case 2:
			print_lcd_update(FONT_WHITE, FONT_BLACK, empty_pad_string(strlen("Secure boot: "), "PRODUCTION"));
			break;

		default:
			print_lcd_update(FONT_RED,   FONT_BLACK, empty_pad_string(strlen("Secure boot: "), "BROKEN!"));
			break;
	}

	orig_y_pos = get_y_pos();
	print_lcd_update(FONT_WHITE, FONT_BLACK, "Lk3rd production build: ");
	update_y_pos(orig_y_pos);

	print_lcd_update(FONT_RED,   FONT_BLACK, empty_pad_string(strlen("Lk3rd production build: "), "no"));

	print_lcd_update(FONT_WHITE, FONT_BLACK, "DRAM: %lldGB %s %s", dram_info.ram_size, dram_info.ram_manufacturer, dram_info.ram_type);
	print_lcd_update(FONT_WHITE, FONT_BLACK, "UFS: %iGB %s", ufs_info.ufs_size, title_case(ufs_info.ufs_manufacturer));

	orig_y_pos = get_y_pos();
	print_lcd_update(FONT_WHITE, FONT_BLACK, "Device state: ");
	update_y_pos(orig_y_pos);

	print_lcd_update(FONT_RED,   FONT_BLACK, empty_pad_string(strlen("Device state: "), "unlocked"));

	orig_y_pos = get_y_pos();
	print_lcd_update(FONT_WHITE, FONT_BLACK, "Mainline quirks: ");
	update_y_pos(orig_y_pos);

	if(lk3rd_get_mainline_quirks() == 1)
		print_lcd_update(FONT_YELLOW, FONT_BLACK, empty_pad_string(strlen("Mainline quirks: "), "enabled ")); 
	else
		print_lcd_update(FONT_GREEN, FONT_BLACK, empty_pad_string(strlen("Mainline quirks: "), "disabled"));

	orig_y_pos = get_y_pos();
	print_lcd_update(FONT_WHITE, FONT_BLACK, "KASLR status: ");
	update_y_pos(orig_y_pos);

	if(lk3rd_get_kaslr_status() == 1)
		print_lcd_update(FONT_GREEN, FONT_BLACK, empty_pad_string(strlen("KASLR status: "), "enabled "));
	else
		print_lcd_update(FONT_RED, FONT_BLACK, empty_pad_string(strlen("KASLR status: "), "disabled"));

	orig_y_pos = get_y_pos();
	print_lcd_update(FONT_WHITE, FONT_BLACK, "Enter reason: ");
	update_y_pos(orig_y_pos);

	if(strcmp(enter_reason, "boot failure!") == 0)
		print_lcd_update(FONT_RED,   FONT_BLACK, "%s", empty_pad_string(strlen("Enter reason: "), enter_reason));
	else
		print_lcd_update(FONT_WHITE, FONT_BLACK, "%s", empty_pad_string(strlen("Enter reason: "), enter_reason));

	orig_y_pos = get_y_pos();
	print_lcd_update(FONT_WHITE, FONT_BLACK, "UART: ");
	update_y_pos(orig_y_pos);

#ifdef PRINT_DEBUG
	print_lcd_update(FONT_RED,   FONT_BLACK, empty_pad_string(strlen("UART: "), "enabled"));
#else
	print_lcd_update(FONT_WHITE, FONT_BLACK, empty_pad_string(strlen("UART: "), "disabled"));
#endif
	print_lcd_update(FONT_BLACK, FONT_BLACK, ""); // Padding for any device messages
	orig_y_pos = get_y_pos() - FONT_Y;
}
