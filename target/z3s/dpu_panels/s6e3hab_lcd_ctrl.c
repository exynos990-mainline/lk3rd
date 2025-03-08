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

#include <dpu/mipi_dsi_cmd.h>
#include <dpu/dsim.h>

#include "s6e3hab_param.h"
#include "s6e3hab_lcd_ctrl.h"

/* Porch values. It depends on command or video mode */
#define S6E3HAB_CMD_VBP 15
#define S6E3HAB_CMD_VFP 8
#define S6E3HAB_CMD_VSA 1
#define S6E3HAB_CMD_HBP 2
#define S6E3HAB_CMD_HFP 2
#define S6E3HAB_CMD_HSA 2

#define CONFIG_FB_I80_COMMAND_MODE
//#define CONFIG_DISPLAY_RESOL_1080X2400

#ifdef CONFIG_DISPLAY_RESOL_1080X2400
#define S6E3HAB_HORIZONTAL 1080
#define S6E3HAB_VERTICAL 2400

struct exynos_panel_info s6e3hab_lcd_info = {
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
	0x0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	false,
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

struct exynos_panel_info s6e3hab_lcd_info = {
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
	0x0,
    },
    .cmd_underrun_cnt = {3022},

    /* Maybe, width and height will be removed */
    .fps = 60,

    .bpc = 8,
    .dsc = {1, 2, 2, 40, 720, 240},
    .data_lane = 4,
    .mres_mode = 0,
};
#endif

u32 s6e3hab_find_idx(u32 yres)
{
	u32 i, val;
	for (i = 0; i < ARRAY_SIZE(SEQ_PPS_PARAM); i++)
	{
		val = (SEQ_PPS_PARAM[i][6] << 8) | (SEQ_PPS_PARAM[i][7] << 0);
		if (val == yres)
			return i;
	}
	dsim_err("No match for yres(%u). Forcing 1080x2400\n", yres);
	return 0;
}

void s6e3hab_lcd_set_resol(unsigned int id, struct exynos_panel_info *lcd)
{
	// TBD
	static const unsigned char SEQ_TEST_ON[] = {0x9F, 0xA5, 0xA5};
	static const unsigned char SEQ_TEST_OFF[] = {0x9F, 0x5A, 0x5A};
	u32 idx;

	/* Scaler settings*/
	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TEST_ON,
			 ARRAY_SIZE(SEQ_TEST_ON)) < 0)
		dsim_err("fail to write SEQ_TEST_ON command.\n");

	/* DSC related configuration */
	if (dsim_wr_data(id, MIPI_DSI_DSC_PRA, (unsigned long)SEQ_DSC_EN[0], 0) < 0)
		dsim_err("fail to write SEQ_DSC_EN command.\n");

	idx = s6e3hab_find_idx(lcd->yres);
	if (dsim_wr_data(id, MIPI_DSI_DSC_PPS, (unsigned long)SEQ_PPS_PARAM[idx],
			 ARRAY_SIZE(SEQ_PPS_PARAM[idx])) < 0)
		dsim_err("fail to write SEQ_PPS_PARAM command.\n");

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TEST_OFF,
			 ARRAY_SIZE(SEQ_TEST_OFF)) < 0)
		dsim_err("fail to write SEQ_TEST_OFF command.\n");

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_PASET_TABLE,
			 ARRAY_SIZE(SEQ_PASET_TABLE)) < 0)
		dsim_err("fail to write SEQ_PASET_TABLE command.\n");

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_CASET_TABLE,
			 ARRAY_SIZE(SEQ_CASET_TABLE)) < 0)
		dsim_err("fail to write SEQ_CASET_TABLE command.\n");

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TEST_KEY_ON_F0,
			 ARRAY_SIZE(SEQ_TEST_KEY_ON_F0)) < 0)
		dsim_err("fail to write SEQ_TEST_KEY_ON_F0 command.\n");

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_SCALER_TABLE,
			 ARRAY_SIZE(SEQ_SCALER_TABLE)) < 0)
		dsim_err("fail to write SEQ_SCALER_TABLE command.\n");

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TEST_KEY_OFF_F0,
			 ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0)) < 0)
		dsim_err("fail to write SEQ_TEST_KEY_OFF_F0 command.\n");
}

/*
 * 3HA9 lcd init sequence
 */

void s6e3hab_lcd_init(unsigned int id, struct exynos_panel_info *lcd)
{
	u32 idx;

	dsim_dbg("%s +\n", __func__);

	mdelay(5);

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TEST_KEY_ON_F0,
			 ARRAY_SIZE(SEQ_TEST_KEY_ON_F0)) < 0)
		dsim_err("fail to write SEQ_TEST_KEY_ON_F0 command.\n");

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TEST_KEY_ON_FC,
			 ARRAY_SIZE(SEQ_TEST_KEY_ON_FC)) < 0)
		dsim_err("fail to write SEQ_TEST_KEY_ON_FC command.\n");

	/* DSC related configuration */
	if (dsim_wr_data(id, MIPI_DSI_DSC_PRA, (unsigned long)SEQ_DSC_EN[0], 0) < 0)
		dsim_err("fail to write SEQ_DSC_EN command.\n");

	idx = s6e3hab_find_idx(lcd->yres);
	if (dsim_wr_data(id, MIPI_DSI_DSC_PPS, (unsigned long)SEQ_PPS_PARAM[idx],
			 ARRAY_SIZE(SEQ_PPS_PARAM[idx])) < 0)
		dsim_err("fail to write SEQ_PPS_PARAM command.\n");

	/* sleep out: 200ms delay */
	if (dsim_wr_data(id, MIPI_DSI_DCS_SHORT_WRITE,
			 (unsigned long)SEQ_SLEEP_OUT[0], 0) < 0)
		dsim_err("fail to send SEQ_SLEEP_OUT command.\n");

	mdelay(200);

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TSP_HSYNC,
			 ARRAY_SIZE(SEQ_TSP_HSYNC)) < 0)
		dsim_err("fail to write SEQ_TSP_HSYNC command.\n");

	/* enable brightness control */
	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_BRIGHT_CTL,
			 ARRAY_SIZE(SEQ_BRIGHT_CTL)) < 0)
		dsim_err("fail to write SEQ_BRIGHT_CTL command.\n");

	/* WRDISBV(51h) = 1st[7:0], 2nd[15:8] */
	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_WRDISBV,
			 ARRAY_SIZE(SEQ_WRDISBV)) < 0)
		dsim_err("fail to write SEQ_WRDISBV command.\n");

	/* TE on */
	if (dsim_wr_data(id, MIPI_DSI_DCS_SHORT_WRITE,
			 (unsigned long)SEQ_TE_ON[0], 0) < 0)
		dsim_err("fail to send SEQ_TE_ON command.\n");

	/* ESD flag: [2]=VLIN3, [6]=VLIN1 error check*/
	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_ESD_FG,
			 ARRAY_SIZE(SEQ_ESD_FG)) < 0)
		dsim_err("fail to write SEQ_ESD_FG command.\n");

	/* Typical high duration: 123.57 (122~125us) */
	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TE_START_SETTING,
			 ARRAY_SIZE(SEQ_TE_START_SETTING)) < 0)
		dsim_err("fail to write SEQ_TE_START_SETTING command.\n");

	/* vrefresh rate configuration */
	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TEST_KEY_ON_F0,
			 ARRAY_SIZE(SEQ_TEST_KEY_ON_F0)) < 0)
		dsim_err("fail to write SEQ_TEST_KEY_ON_F0 command.\n");

	if (lcd->fps == 60)
	{
		if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_VREFRESH_60FPS,
				 ARRAY_SIZE(SEQ_VREFRESH_60FPS)) < 0)
			dsim_err("fail to write SEQ_VREFRESH_60FPS command.\n");
	}
	else if (lcd->fps == 120)
	{
		if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_VREFRESH_120FPS,
				 ARRAY_SIZE(SEQ_VREFRESH_120FPS)) < 0)
			dsim_err("fail to write SEQ_VREFRESH_120FPS command.\n");
	}
	else
	{
		dsim_err("not suported fps(%d)\n", lcd->fps);
	}

	/* Panelupdate : gamma set, ltps set, transition control update */
	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_GAMMA_LTPS_TRANS_UPDATE,
			 ARRAY_SIZE(SEQ_GAMMA_LTPS_TRANS_UPDATE)) < 0)
		dsim_err("fail to write SEQ_GAMMA_LTPS_TRANS_UPDATE command.\n");

	if (dsim_wr_data(id, MIPI_DSI_DCS_LONG_WRITE, (unsigned long)SEQ_TEST_KEY_OFF_F0,
			 ARRAY_SIZE(SEQ_TEST_KEY_OFF_F0)) < 0)
		dsim_err("fail to write SEQ_TEST_KEY_OFF_F0 command.\n");

	/* display on : move to s6e3hab_lcd_enable_exynos() */

	dsim_dbg("%s -\n", __func__);
}

void s6e3hab_lcd_enable_exynos(unsigned int id)
{
	if (dsim_wr_data(id, MIPI_DSI_DCS_SHORT_WRITE,
			 (unsigned long)SEQ_DISPLAY_ON[0], 0) < 0)
		dsim_err("fail to send SEQ_DISPLAY_ON command.\n");
}

void s6e3hab_lcd_disable(unsigned int id)
{
	/* This function needs to implement */
}

/*
 * Set gamma values
 *
 * Parameter
 *	- backlightlevel : It is from 0 to 26.
 */
int s6e3hab_lcd_gamma_ctrl(unsigned int id, unsigned int backlightlevel)
{
	/* This will be implemented */
	return 0;
}

int s6e3hab_lcd_gamma_update(int id)
{
	/* This will be implemented */
	return 0;
}