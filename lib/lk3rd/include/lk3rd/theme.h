/*
 * Copyright (c) 2024 Igor Belwon <igor.belwon@mentallysanemainliners.org>
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 *
 */

 #ifndef THEME_H
 #define THEME_H
 
enum theme {
    THEME_SNAPDRAGON,
#if defined(POWER_TOP) && defined(POWER_HEIGHT) && defined(VOL_TOP) && defined(VOL_HEIGHT)
    THEME_PIXEL,
#endif
    THEME_UNIFIED,
    THEME_DEBUG,
    THEME_END
};

int lk3rd_set_theme(int theme);
int lk3rd_get_theme(void);
const char* lk3rd_get_current_theme_name(void);

#endif