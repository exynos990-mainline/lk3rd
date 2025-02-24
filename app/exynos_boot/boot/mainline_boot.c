/*
 * Copyright (c) 2025 Igor Belwon <igor.belwon@mentallysanemainliners.org>
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 *
 */

#include <platform/exynos9830.h>
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

/* Hacky. */
void arm_generic_timer_disable(void);
int cmd_scatter_load_boot(int argc, const cmd_args *argv);

void mainline_boot(void)
{
	int ret;
	struct pit_entry *ptn;
	cmd_args argv[6];
	boot_img_hdr *boot_image = (boot_img_hdr *)BOOT_BASE;

	ptn = pit_get_part_info("boot");
	if (ptn == 0) {
		printf("Partition 'boot' does not exist\n");
		return;
	} else {
		pit_access(ptn, PIT_OP_LOAD, (u64)BOOT_BASE, 0);
	}

	if(strncmp((char*)boot_image->magic, BOOT_MAGIC, 8))
	{
		start_usb_gadget();
		while(1){}
	}

	argv[1].u = BOOT_BASE;
	argv[2].u = KERNEL_BASE;
	argv[3].u = RAMDISK_BASE;
	argv[4].u = DT_BASE;
	argv[5].u = 0;
	cmd_scatter_load_boot(6, argv);

	ret = fdt_check_header((void*)DT_BASE);
	if (ret) {
		printf("libfdt fdt_check_header(): %s\n", fdt_strerror(ret));
		return;
	}

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

void mainline_boot_fb_boot(unsigned long buf_addr, size_t size)
{
	struct boot_img_hdr *b_hdr;
	cmd_args argv[6];
	int ret = 0;

	memset((void *)BOOT_BASE, 0, SZ_64M);
	memcpy((void *)BOOT_BASE, (void *)buf_addr, size);
	b_hdr = (struct boot_img_hdr *)BOOT_BASE;

	stop_usb_gadget();

	if(strncmp((char*)b_hdr->magic, BOOT_MAGIC, 8))
	{
		start_usb_gadget();
		while(1){}
	}

	argv[1].u = BOOT_BASE;
	argv[2].u = KERNEL_BASE;
	argv[3].u = RAMDISK_BASE;
	argv[4].u = DT_BASE;
	argv[5].u = 0;
	cmd_scatter_load_boot(6, argv);

        ret = fdt_check_header((void*)DT_BASE);
        if (ret) {
                printf("libfdt fdt_check_header(): %s\n", fdt_strerror(ret));
                return;
        }

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
