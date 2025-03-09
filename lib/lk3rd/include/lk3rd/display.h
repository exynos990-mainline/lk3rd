/*
 * Copyright (c) 2024 Igor Belwon <igor.belwon@mentallysanemainliners.org>
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 *
 */

#ifndef DISPLAY
#define DISPLAY

#include <lib/font_display.h>

#include "fastboot_menu.h"


#define MAX_NUM_CHAR_PER_LINE ((LCD_WIDTH / FONT_X) - 6)

void draw_menu(enum action current_action);

#endif /* DISPLAY */
