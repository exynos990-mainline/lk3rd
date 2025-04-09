/*
 * Copyright (c) 2025 Umer Uddin <umer.uddin@mentallysanemainliners.org>
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 *
 */

#include <sys/types.h>

#ifndef __DEVICE_INFO_H__
#define __DEVICE_INFO_H__

struct ufs_device_info
{
	u64 ufs_size; // In GB
	char *ufs_manufacturer;
};

struct ram_info
{
	u64 ram_size; // In GB
	char *ram_manufacturer;
	char *ram_type;
};

extern struct ufs_device_info ufs_info;
extern struct ram_info dram_info;

#endif
