/*
 * Copyright (c) 2025 Igor Belwon <igor.belwon@mentallysanemainliners.org>
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 *
 */

#include <platform/exynos9830.h>
#include <platform/usb.h>
#include <lib/console.h>
#include <platform/bootimg.h>
#include <pit.h>
#include <string.h>
#include <arch/arch_ops.h>
#include <platform/sizes.h>
#include <platform/smc.h>
#include <libfdt.h>
#include <dev/usb/gadget.h>
#include <platform/mmu/mmu_func.h>
#include <lib/font_display.h>
#include <lib/fdtapi.h>

#include <lk3rd/boot_reason.h>

#define DEFAULT_CMDLINE "root=/dev/mem0 initrd=0x84000000,0x1000000"

extern char cmd_line_override[4096 - 42];

/* Hacky. */
void arm_generic_timer_disable(void);
int cmd_scatter_load_boot(int argc, const cmd_args *argv);
extern struct fdt_header *fdt_dtb;

void print_mainline_warning(void)
{
	/* Offset for the camera holepunch */
	for (int i = 0; i < 3; i++)
		print_lcd_update(FONT_RED, FONT_BLACK, "");

	print_lcd_update(FONT_RED, FONT_BLACK, "You are using mainline quirks.");
	print_lcd_update(FONT_RED, FONT_BLACK, "These quirks should not be used for booting Android.");
	print_lcd_update(FONT_RED, FONT_BLACK, "If you are booting Android, please reboot to fastboot and run");
	print_lcd_update(FONT_YELLOW, FONT_BLACK, "fastboot oem disable-mainline-quirks");
}

int add_dt_ramdisk(uint32_t ramdisk_size)
{
	int offset, ret;

	fdt_dtb = (struct fdt_header *)DT_BASE;

	ret = fdt_check_header(fdt_dtb);
	if (ret != 0)
		goto err;

	// Resize the DTB to fit the ramdisk properties
	resize_dt(SZ_4K);

	// Make /chosen node
	offset = fdt_path_offset(fdt_dtb, "/");
	if (offset < 0)
		goto err;

	fdt_add_subnode(fdt_dtb, offset, "chosen");

	ret = set_fdt_val("/chosen", "linux,initrd-start", "<0x84000000>");
	if (ret != 0)
		goto err;

	ret = set_fdt_val("/chosen", "linux,initrd-end", "<0x84FFFFFF>");
	if (ret != 0)
		goto err;

	return 0;

err:
	printf("Failed to add ramdisk props: %s\n", fdt_strerror(ret));
	return ret;
}

void mainline_boot_common(boot_img_hdr *b_hdr)
{
	int ret;
	cmd_args argv[6];
	char cmd_line[4096];

	if (strncmp((char *)b_hdr->magic, BOOT_MAGIC, 8))
	{
		enter_reason = (char*)"Boot image magic not found.";
		start_usb_gadget();
		while (1)
		{
		}
	}

	argv[1].u = BOOT_BASE;
	argv[2].u = KERNEL_BASE;
	argv[3].u = RAMDISK_BASE;
	argv[4].u = DT_BASE;
	argv[5].u = 0;
	cmd_scatter_load_boot(6, argv);

	ret = fdt_check_header((void *)DT_BASE);
	if (ret)
	{
		printf("libfdt fdt_check_header(): %s\n", fdt_strerror(ret));
		return;
	}

	if (b_hdr->ramdisk_size != 0)
	{
		ret = add_dt_ramdisk(b_hdr->ramdisk_size);
		if(ret != 0)
		{
			snprintf(enter_reason, ENTER_REASON_SIZE, "add_dt_ramdisk: %s", fdt_strerror(ret));
			start_usb_gadget();
			while (1)
			{
			}
		}
	}
	else
		printf("No ramdisk - skipping.\n");

	// The override takes full priority over boot image cmdline and defaults.
	if (cmd_line_override[0] != '\0') {
		snprintf(cmd_line, 4096, "%s %s", DEFAULT_CMDLINE, cmd_line_override);
	}
	else
	{
		if (b_hdr->cmdline[0] && (!b_hdr->cmdline[BOOT_ARGS_SIZE - 1])) {
			snprintf(cmd_line, 4096, "%s %s", DEFAULT_CMDLINE, b_hdr->cmdline);
		}
		else {
			printf("No cmdline - set default.\n");
			snprintf(cmd_line, 4096, "%s", DEFAULT_CMDLINE);
		}
	}

	ret = set_fdt_val("/chosen", "bootargs", cmd_line);
	if (ret != 0)
		printf("Failed to add bootargs: %s\n", fdt_strerror(ret));

	/* notify EL3 Monitor end of bootloader */
	exynos_smc(SMC_CMD_END_OF_BOOTLOADER, 0, 0, 0);

	/* before jumping to kernel. disable interrupts */
	arch_disable_ints();

	/* before jumping to kernel. disble arch_timer */
	arm_generic_timer_disable();

	clean_invalidate_dcache_all();
	disable_mmu_dcache();

	void (*kernel_entry)(int r0, int r1, int r2, int r3);
	kernel_entry = (void (*)(int, int, int, int))KERNEL_BASE;
	kernel_entry(DT_BASE, 0, 0, 0);

	/* We shouldn't get here. */
	return;
}

void mainline_boot(void)
{
	struct pit_entry *ptn;
	boot_img_hdr *b_hdr = (boot_img_hdr *)BOOT_BASE;

	print_mainline_warning();

	ptn = pit_get_part_info("boot");
	if (ptn == 0)
	{
		printf("Partition 'boot' does not exist\n");
		return;
	}
	else
	{
		pit_access(ptn, PIT_OP_LOAD, (u64)BOOT_BASE, 0);
	}

	mainline_boot_common(b_hdr);
}

void mainline_boot_fb_boot(unsigned long buf_addr, size_t size)
{
	struct boot_img_hdr *b_hdr;

	print_mainline_warning();

	memset((void *)BOOT_BASE, 0, SZ_64M);
	memcpy((void *)BOOT_BASE, (void *)buf_addr, size);
	b_hdr = (struct boot_img_hdr *)BOOT_BASE;

	stop_usb_gadget();

	mainline_boot_common(b_hdr);
}
