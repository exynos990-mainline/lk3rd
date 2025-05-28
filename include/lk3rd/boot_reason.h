/*
 * Copyright (c) 2025 Umer Uddin <umer.uddin@mentallysanemainliners.org>
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 *
 */

#ifndef __BOOT_REASON_H__
#define __BOOT_REASON_H__

#include <lk3rd/display.h>

#define ENTER_REASON_SIZE MAX_NUM_CHAR_PER_LINE * sizeof(char)
extern char *enter_reason;

#endif
