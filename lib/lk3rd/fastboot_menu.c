/*
 * Copyright (c) 2024 Igor Belwon <igor.belwon@mentallysanemainliners.org>
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 *
 */

#include <dev/usb/gadget.h>
#include <dev/scsi.h>
#include <kernel/thread.h>

#include <lib/font_display.h>
#include <platform.h>
#include <platform/gpio.h>
#include <platform/sfr.h>
#include <lk/reg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "include/lk3rd/keys.h"
#include "include/lk3rd/fastboot_menu.h"
#include "include/lk3rd/display.h"

#if WITH_DEV_POWER_PMIC_S2MPS_19_22
#include <dev/pmic_s2mps_19_22.h>
#endif

bool block_keys = false;
enum action current_action = ACTION_START;

void notify_action_switch(int modifier)
{
	current_action = current_action + modifier;

	/* Rollover */
	if(current_action == ACTION_END)
	{
		current_action = 0;
	}

	if((int)current_action == -1)
		current_action = ACTION_END - 1;

	draw_menu(current_action);
}

void platform_prepare_reboot(void);
void platform_do_reboot(const char *cmd_buf);

void do_reboot(enum action action)
{
	switch(action)
	{
		case ACTION_START:
			platform_prepare_reboot();
			platform_do_reboot("");
			break;
		case ACTION_REBOOT_BOOTLOADER:
			platform_prepare_reboot();
			platform_do_reboot("reboot-bootloader");
			break;
		case ACTION_REBOOT_RECOVERY:
			platform_prepare_reboot();
			platform_do_reboot("reboot-recovery");
			break;
		case ACTION_REBOOT_FASTBOOTD:
			platform_prepare_reboot();
			platform_do_reboot("reboot-fastboot");
			break;
		case ACTION_REBOOT_DOWNLOAD:
			platform_prepare_reboot();
			platform_do_reboot("reboot-download");
			break;
		case ACTION_POWEROFF:
#if WITH_DEV_POWER_PMIC_S2MPS_19_22
			while(true) {
				clear_screen(FONT_BLACK);

				if(!exynos_gpio_get_value((struct exynos_gpio_bank *)EXYNOS9830_GPA2CON, GPIO_POWER)) {
					udelay(1000000);
					continue;
				}

				u32 ps_hold;

				pmic_disable_wtsr();
				pmic_disable_smpl();
				pmic_shutdown();

				ps_hold = readl(EXYNOS_PMU_PS_HOLD_CONTROL);
				ps_hold &= 0xfffffeff;

				writel(ps_hold, EXYNOS_PMU_PS_HOLD_CONTROL);
				break;
			}
			break;
#else
			// For platforms with shutdown unimplemented.
			platform_prepare_reboot();
			platform_do_reboot("");
			break;
#endif
		default:
			break;
	}

	// Should never return.
	thread_exit(0);
}

void notify_action_start(void)
{
	do_reboot(current_action);
	return;
}


int fastboot_menu_entry(void *arg)
{

	struct exynos_gpio_bank *bank_volume = (struct exynos_gpio_bank *)EXYNOS_GPA0CON;
	struct exynos_gpio_bank *bank_power = (struct exynos_gpio_bank *)EXYNOS_GPA2CON;

	int volup, voldown, power, key_stuck = 0;

	lk_time_t last_button_press = current_time(), default_repeat_delay = 400, repeat_delay = default_repeat_delay;
	float repeat_delay_multiplier = .9;

	setup_keys(bank_volume, BANK_GPA0);
	setup_keys(bank_power, BANK_GPA2);
	clear_screen(FONT_BLACK);

	draw_menu(current_action);

	while (true)
	{
		volup = exynos_gpio_get_value(bank_volume, GPIO_VOLUP);
		voldown = exynos_gpio_get_value(bank_volume, GPIO_VOLDOWN);
		power = exynos_gpio_get_value(bank_power, GPIO_POWER);

		if(block_keys)
		{
			thread_sleep(100);
			continue;
		}

		if (volup && voldown && power)
		{
			repeat_delay = default_repeat_delay;
			key_stuck = 0;
		}
		else if (!power)
		{
			notify_action_start();
			key_stuck = 3;
			last_button_press = current_time();
			repeat_delay *= repeat_delay_multiplier;
		}
		else if(current_time() - last_button_press > repeat_delay || repeat_delay == default_repeat_delay)
		{
			if (!volup && (repeat_delay == default_repeat_delay || key_stuck == 1))
			{
				notify_action_switch(-1);
				key_stuck = 1;
				last_button_press = current_time();
				repeat_delay *= repeat_delay_multiplier;
			}
			else if (!voldown && (repeat_delay == default_repeat_delay || key_stuck == 2))
			{
				notify_action_switch(1);
				key_stuck = 2;
				last_button_press = current_time();
				repeat_delay *= repeat_delay_multiplier;
			}
			else
			{
				repeat_delay = default_repeat_delay;
				key_stuck = 0;
			}
		}

		// Don't freeze up lk.
		thread_sleep(100);
	}
}
