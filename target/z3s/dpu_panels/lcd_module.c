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

#include <target/lcd_module.h>

#define S6E3HAB_CMD_VBP 15
#define S6E3HAB_CMD_VFP 8
#define S6E3HAB_CMD_VSA 1
#define S6E3HAB_CMD_HBP 2
#define S6E3HAB_CMD_HFP 2
#define S6E3HAB_CMD_HSA 2
//#define CONFIG_DISPLAY_RESOL_1080X2400

#ifdef CONFIG_DISPLAY_RESOL_1080X2400
#define S6E3HAB_HORIZONTAL 1080
#define S6E3HAB_VERTICAL 2400

static struct exynos_panel_info common_lcd_info = {
    .mode = DECON_MIPI_COMMAND_MODE,
    .vfp = S6E3HAB_CMD_VFP,
    .vbp = S6E3HAB_CMD_VBP,
    .hfp = S6E3HAB_CMD_HFP,
    .hbp = S6E3HAB_CMD_HBP,
    .vsa = S6E3HAB_CMD_VSA,
    .hsa = S6E3HAB_CMD_HSA,
    .xres = S6E3HAB_HORIZONTAL,
    .yres = S6E3HAB_VERTICAL,

    /* Maybe, width and height will be removed */
    .width = 69,
    .height = 154,

    /* Mhz */
    .hs_clk = 1100,
    .esc_clk = 20,

    /* pmsk */
    .dphy_pms = {
	0x3,
	0xFE,
	0x2,
	0x0
    },
    .cmd_underrun_cnt = {5115},

    /* Maybe, width and height will be removed */
    .fps = 60,

    .bpc = 8,
    .dsc = {true, 1, 2, 540, 40},
    .data_lane = 4,
    .mres_mode = 0,
};
#else
#define S6E3HAB_HORIZONTAL 1440
#define S6E3HAB_VERTICAL 3200

struct exynos_panel_info common_lcd_info = {
    .mode = DECON_MIPI_COMMAND_MODE,
    .vfp = S6E3HAB_CMD_VFP,
    .vbp = S6E3HAB_CMD_VBP,
    .hfp = S6E3HAB_CMD_HFP,
    .hbp = S6E3HAB_CMD_HBP,
    .vsa = S6E3HAB_CMD_VSA,
    .hsa = S6E3HAB_CMD_HSA,
    .xres = S6E3HAB_HORIZONTAL,
    .yres = S6E3HAB_VERTICAL,

    /* Maybe, width and height will be removed */
    .width = 70,
    .height = 121,

    /* Mhz */
    .hs_clk = 896,
    .esc_clk = 20,

    /* pmsk */
    .dphy_pms = {
	0x3,
	0x46,
	0x1,
	0x0
    },
    .cmd_underrun_cnt = {3022},

    /* Maybe, width and height will be removed */
    .fps = 60,

    .bpc = 8,
    .dsc = {true, 2, 2, 720, 40},
    .data_lane = 4,
    .mres_mode = 0,
};
#endif

struct exynos_panel_info *common_get_lcd_info(void)
{
	return &common_lcd_info;
}

extern struct dsim_lcd_driver s6e3hab_mipi_lcd_driver;

struct dsim_lcd_driver *panel_list[NUM_OF_VERIFIED_PANEL] = {
    /* dependency MAX_PANEL_ID */
    &s6e3hab_mipi_lcd_driver,
};

/* fill panel id to panel_ids arrary from panel driver each */
int cm_fill_id(struct dsim_device *dsim)
{
	int i;

	for (i = 0; i < NUM_OF_VERIFIED_PANEL; i++)
	{

		if (panel_list[i] == NULL)
			break;
		dsim->cm_panel_ops->panel_ids[i] = panel_list[i]->get_id(dsim);
	}

	return 0;
}

static u32 ddi_id = 0;

u32 get_ddi_id(void)
{
	return ddi_id;
}

/* read ddi's id(panel_ids[]) for matching expected id */
int cm_read_id(struct dsim_device *dsim)
{
	int err = 0;
	u32 id = 0, i;

	u8 buf[DSIM_DDI_ID_LEN] = {
	    0,
	};

	/* dsim sends the request for the lcd id and gets it buffer */
	err = dsim_read_data(dsim, MIPI_DSI_DCS_READ,
			     MIPI_DCS_GET_DISPLAY_ID, DSIM_DDI_ID_LEN, buf);
	if (err < 0)
	{
		printf("Failed to read panel id!\n");
		return -EINVAL;
	}
	else
	{
		for (i = 0; i < DSIM_DDI_ID_LEN; i++)
		{
			// id |= buf[i] << (24 - i * 8);	/* LSB is left */
			id |= buf[i] << (i * 8); /* LSB is right */
			printf("id : 0x%06x\n", id);
		}

		printf("Suceeded to read panel id : 0x%06x\n", id);
		ddi_id = id;
	}

	return dsim->cm_panel_ops->id = id;
}

/* return panel_ops of matched panel driver */
struct dsim_lcd_driver *cm_get_panel_info(struct dsim_device *dsim)
{
	return &s6e3hab_mipi_lcd_driver;
}

struct lcd_driver common_lcd_driver = {
    .fill_id = cm_fill_id,
    .read_id = cm_read_id,
    .get_panel_info = cm_get_panel_info,
};

struct lcd_driver *get_lcd_drv_ops(void)
{
	return &common_lcd_driver;
}