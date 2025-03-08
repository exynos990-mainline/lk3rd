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

#include <dpu/exynos_panel.h>
#include <dpu/dsim.h>

#include "s6e3hab_lcd_ctrl.h"

#define MAX_BRIGHTNESS 255
#define MIN_BRIGHTNESS 0
#define DEFAULT_BRIGHTNESS 0

#define S6E3HAB_DDI_ID_COMPARE_MASK 0x000000ff
/* PANEL_ID : ID3[23:16]-ID2[15:8]-ID1[7:0] */
#define PANEL_ID_1 0x421081 /* value was confirmed when bringup */
#define PANEL_ID_2 0x031181 /* value was confirmed when bringup */
#define PANEL_ID_3 0x041181 /* value was confirmed when bringup */

extern struct exynos_panel_info s6e3hab_lcd_info;

extern unsigned int board_id;

static int s6e3hab_get_id(struct dsim_device *dsim)
{
	dsim_info("%s panel ID is (0x%08x)\n", __func__, PANEL_ID_3);
	return PANEL_ID_3;
}

static struct exynos_panel_info *s6e3hab_get_lcd_info(void)
{
	return &s6e3hab_lcd_info;
}

static int s6e3hab_probe(struct dsim_device *dsim)
{
	return 1;
}

static int s6e3hab_displayon(struct dsim_device *dsim)
{
	s6e3hab_lcd_init(dsim->id, dsim->lcd_info);
	s6e3hab_lcd_enable_exynos(dsim->id);
	s6e3hab_lcd_set_resol(dsim->id, dsim->lcd_info);
	return 1;
}

static int s6e3hab_suspend(struct dsim_device *dsim)
{
	return 1;
}

static int s6e3hab_resume(struct dsim_device *dsim)
{
	return 1;
}

struct dsim_lcd_driver s6e3hab_mipi_lcd_driver = {
    .get_id = s6e3hab_get_id,
    .get_lcd_info = s6e3hab_get_lcd_info,
    .probe = s6e3hab_probe,
    .displayon = s6e3hab_displayon,
    .suspend = s6e3hab_suspend,
    .resume = s6e3hab_resume,
};