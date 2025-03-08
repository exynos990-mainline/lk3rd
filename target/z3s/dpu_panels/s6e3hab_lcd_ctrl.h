/*
 * Copyright@ Samsung Electronics Co. LTD
 *
 * This software is proprietary of Samsung Electronics.
 *
 * No part of this software, either material or conceptual may be copied or
 * distributed, transmitted, transcribed, stored in a retrieval system or
 * translated into any human or computer language in any form by any means,
 * electronic, mechanical, manual or otherwise, or disclosed to third parties
 * without the express written permission of Samsung Electronics.
 *
 */

#ifndef __S6E3HAB_LCD_CTRL_H__
#define __S6E3HAB_LCD_CTRL_H__

void s6e3hab_lcd_init(unsigned int id, struct exynos_panel_info *lcd);
void s6e3hab_lcd_enable_exynos(unsigned int id);
void s6e3hab_lcd_set_resol(unsigned int id, struct exynos_panel_info *lcd);
void s6e3hab_lcd_disable_exynos(unsigned int id);
int s6e3hab_lcd_gamma_ctrl(unsigned int id, unsigned int backlightlevel);
int s6e3hab_lcd_gamma_update(int id);

#endif /* __S6E3HAB_LCD_CTRL_H__ */