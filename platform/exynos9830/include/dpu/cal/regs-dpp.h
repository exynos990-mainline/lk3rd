/* Copyright (c) 2018 Samsung Electronics Co, Ltd.

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.

 * Copyright@ Samsung Electronics Co. LTD
 * Manseok Kim <manseoks.kim@samsung.com>

 * Alternatively, Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DPP_REGS_H_
#define DPP_REGS_H_

/*
 * DPU WB MUX base address  : 0x19080000
 * DPU_DMA SFR base address : 0x19090000
 * - GLOBAL         : 0x19090000
 * - IDMA GF0(L0)   : 0x19091000
 * - IDMA GF1(L1)   : 0x19092000
 * - IDMA VG(L2)    : 0x19093000
 * - IDMA VGS(L3)   : 0x19094000
 * - IDMA VGF(L4)   : 0x19095000
 * - IDMA VGRFS(L5) : 0x19096000
 * - ODMA           : 0x19097000
 */
#define DPU_DMA_VERSION				0x0000
#define DPU_DMA_VER				0x05000000

#define DPU_DMA_QCH_EN				0x000C
#define DMA_QCH_EN				(1 << 0)

#define DPU_DMA_SWRST				0x0010
#define DMA_CH2_SWRST				(1 << 3)
#define DMA_CH1_SWRST				(1 << 2)
#define DMA_CH0_SWRST				(1 << 1)
#define DMA_ALL_SWRST				(1 << 0)
#define DMA_CH_SWRST(_ch)			(1 << ((_ch)))

#define DPU_DMA_TEST_PATTERN0_3			0x0020
#define DPU_DMA_TEST_PATTERN0_2			0x0024
#define DPU_DMA_TEST_PATTERN0_1			0x0028
#define DPU_DMA_TEST_PATTERN0_0			0x002C
#define DPU_DMA_TEST_PATTERN1_3			0x0030
#define DPU_DMA_TEST_PATTERN1_2			0x0034
#define DPU_DMA_TEST_PATTERN1_1			0x0038
#define DPU_DMA_TEST_PATTERN1_0			0x003C

#define DPU_DMA_GLB_CGEN_CH0			0x0040
#define DMA_SFR_CGEN(_v)			((_v) << 31)
#define DMA_SFR_CGEN_MASK			(1 << 31)
#define DMA_INT_CGEN(_v)			((_v) << 0)
#define DMA_INT_CGEN_MASK			(0x7FFFFFFF << 0)

#define DPU_DMA_GLB_CGEN_CH1			0x0044
#define DMA_INT_CGEN(_v)			((_v) << 0)
#define DMA_INT_CGEN_MASK			(0x7FFFFFFF << 0)

#define DPU_DMA_GLB_CGEN_CH2			0x0048
#define DMA_INT_CGEN(_v)			((_v) << 0)
#define DMA_INT_CGEN_MASK			(0x7FFFFFFF << 0)

#define DPU_DMA_DEBUG_CONTROL			0x0100
#define DPU_DMA_DEBUG_CONTROL_SEL(_v)		((_v) << 16)
#define DPU_DMA_DEBUG_CONTROL_EN		(0x1 << 0)

#define DPU_DMA_DEBUG_DATA			0x0104

/*
 * 1.1 - IDMA Register
 * < DMA.offset >
 *  G0      G1      VG      VGS     VGF     VGRFS
 *  0x1000  0x2000  0x3000  0x4000  0x5000  0x6000
 */
#define IDMA_ENABLE				0x0000
#define IDMA_ASSIGNED_MO(_v)			((_v) << 24)
#define IDMA_ASSIGNED_MO_MASK			(0xff << 24)
#define IDMA_SRESET				(1 << 8)
#define IDMA_SFR_UPDATE_FORCE			(1 << 4)
#define IDMA_OP_STATUS				(1 << 2)
#define OP_STATUS_IDLE				(0)
#define OP_STATUS_BUSY				(1)
#define IDMA_INSTANT_OFF_PENDING		(1 << 1)
#define INSTANT_OFF_PENDING			(1)
#define INSTANT_OFF_NOT_PENDING			(0)

#define IDMA_IRQ				0x0004
/* [9830] AXI_ADDR_ERR_IRQ is added */
#define IDMA_AXI_ADDR_ERR_IRQ			(1 << 26)
#define IDMA_AFBC_CONFLICT_IRQ			(1 << 25)
#define IDMA_VR_CONFLICT_IRQ			(1 << 24)
#define IDMA_SBWC_ERR_IRQ			(1 << 23)
#define IDMA_RECOVERY_TRG_IRQ			(1 << 22)
#define IDMA_CONFIG_ERROR			(1 << 21)
#define IDMA_LOCAL_HW_RESET_DONE		(1 << 20)
#define IDMA_READ_SLAVE_ERROR			(1 << 19)
#define IDMA_STATUS_DEADLOCK_IRQ		(1 << 17)
#define IDMA_STATUS_FRAMEDONE_IRQ		(1 << 16)
#define IDMA_ALL_IRQ_CLEAR			(0x7FB << 16)
/* [9830] AXI_ADDR_ERR_IRQ_MASK is added */
#define IDMA_AXI_ADDR_ERR_IRQ_MASK		(1 << 11)
#define IDMA_AFBC_CONFLICT_MASK			(1 << 10)
#define IDMA_VR_CONFLICT_MASK			(1 << 9)
#define IDMA_SBWC_ERR_MASK			(1 << 8)
#define IDMA_RECOVERY_TRG_MASK			(1 << 7)
#define IDMA_CONFIG_ERROR_MASK			(1 << 6)
#define IDMA_LOCAL_HW_RESET_DONE_MASK		(1 << 5)
#define IDMA_READ_SLAVE_ERROR_MASK		(1 << 4)
#define IDMA_IRQ_DEADLOCK_MASK			(1 << 2)
#define IDMA_IRQ_FRAMEDONE_MASK			(1 << 1)
#define IDMA_ALL_IRQ_MASK			(0x7FB << 1)
#define IDMA_IRQ_ENABLE				(1 << 0)

#define IDMA_IN_CON				0x0008
#define IDMA_PIXEL_ALPHA(_v)			((_v) << 24)
#define IDMA_PIXEL_ALPHA_MASK			(0xff << 24)
#define IDMA_IN_IC_MAX(_v)			((_v) << 16)
#define IDMA_IN_IC_MAX_MASK			(0xff << 16)
#define IDMA_IMG_FORMAT(_v)			((_v) << 8)
#define IDMA_IMG_FORMAT_MASK			(0x3f << 8)
#define IDMA_IMG_FORMAT_ARGB8888		(0)
#define IDMA_IMG_FORMAT_ABGR8888		(1)
#define IDMA_IMG_FORMAT_RGBA8888		(2)
#define IDMA_IMG_FORMAT_BGRA8888		(3)
#define IDMA_IMG_FORMAT_XRGB8888		(4)
#define IDMA_IMG_FORMAT_XBGR8888		(5)
#define IDMA_IMG_FORMAT_RGBX8888		(6)
#define IDMA_IMG_FORMAT_BGRX8888		(7)
#define IDMA_IMG_FORMAT_RGB565			(8)
#define IDMA_IMG_FORMAT_BGR565			(9)
#define IDMA_IMG_FORMAT_ARGB1555		(12)
#define IDMA_IMG_FORMAT_ARGB4444		(13)
#define IDMA_IMG_FORMAT_ABGR1555		(14)
#define IDMA_IMG_FORMAT_ABGR4444		(15)
#define IDMA_IMG_FORMAT_ARGB2101010		(16)
#define IDMA_IMG_FORMAT_ABGR2101010		(17)
#define IDMA_IMG_FORMAT_RGBA1010102		(18)
#define IDMA_IMG_FORMAT_BGRA1010102		(19)
#define IDMA_IMG_FORMAT_RGBA5551		(20)
#define IDMA_IMG_FORMAT_RGBA4444		(21)
#define IDMA_IMG_FORMAT_BGRA5551		(22)
#define IDMA_IMG_FORMAT_BGRA4444		(23)
#define IDMA_IMG_FORMAT_YUV420_2P		(24)
#define IDMA_IMG_FORMAT_YVU420_2P		(25)
#define IDMA_IMG_FORMAT_YUV420_8P2		(26)
#define IDMA_IMG_FORMAT_YVU420_8P2		(27)
#define IDMA_IMG_FORMAT_YUV420_P010		(29)
#define IDMA_IMG_FORMAT_YVU420_P010		(28)
#define IDMA_IMG_FORMAT_YVU422_2P		(56)
#define IDMA_IMG_FORMAT_YUV422_2P		(57)
#define IDMA_IMG_FORMAT_YVU422_8P2		(58)
#define IDMA_IMG_FORMAT_YUV422_8P2		(59)
#define IDMA_IMG_FORMAT_YVU422_P210		(60)
#define IDMA_IMG_FORMAT_YUV422_P210		(61)
#define IDMA_ROTATION(_v)			((_v) << 4)
#define IDMA_ROTATION_MASK			(0x7 << 4)
#define IDMA_ROTATION_X_FLIP			(1 << 4)
#define IDMA_ROTATION_Y_FLIP			(2 << 4)
#define IDMA_ROTATION_180			(3 << 4)
#define IDMA_ROTATION_90			(4 << 4)
#define IDMA_ROTATION_90_X_FLIP			(5 << 4)
#define IDMA_ROTATION_90_Y_FLIP			(6 << 4)
#define IDMA_ROTATION_270			(7 << 4)
#define IDMA_IN_FLIP(_v)			((_v) << 4)
#define IDMA_IN_FLIP_MASK			(0x3 << 4)
/* #define IDMA_CSET_EN				(1 << 3) */
#define IDMA_SBWC_EN				(1 << 2)
#define IDMA_AFBC_EN				(1 << 1)
#define IDMA_BLOCK_EN				(1 << 0)

#define IDMA_SRC_SIZE				0x0010
#define IDMA_SRC_HEIGHT(_v)			((_v) << 16)
#define IDMA_SRC_HEIGHT_MASK			(0xFFFF << 16)
#define IDMA_SRC_WIDTH(_v)			((_v) << 0)
#define IDMA_SRC_WIDTH_MASK			(0xFFFF << 0)

#define IDMA_SRC_OFFSET				0x0014
#define IDMA_SRC_OFFSET_Y(_v)			((_v) << 16)
#define IDMA_SRC_OFFSET_Y_MASK			(0x3FFF << 16)
#define IDMA_SRC_OFFSET_X(_v)			((_v) << 0)
#define IDMA_SRC_OFFSET_X_MASK			(0x3FFF << 0)

#define IDMA_IMG_SIZE				0x0018
#define IDMA_IMG_HEIGHT(_v)			((_v) << 16)
#define IDMA_IMG_HEIGHT_MASK			(0x3FFF << 16)
#define IDMA_IMG_WIDTH(_v)			((_v) << 0)
#define IDMA_IMG_WIDTH_MASK			(0x3FFF << 0)

#define IDMA_BLOCK_OFFSET			0x0020
#define IDMA_BLK_OFFSET_Y(_v)			((_v) << 16)
#define IDMA_BLK_OFFSET_Y_MASK			(0x3FFF << 16)
#define IDMA_BLK_OFFSET_X(_v)			((_v) << 0)
#define IDMA_BLK_OFFSET_X_MASK			(0x3FFF << 0)

#define IDMA_BLOCK_SIZE				0x0024
#define IDMA_BLK_HEIGHT(_v)			((_v) << 16)
#define IDMA_BLK_HEIGHT_MASK			(0x3FFF << 16)
#define IDMA_BLK_WIDTH(_v)			((_v) << 0)
#define IDMA_BLK_WIDTH_MASK			(0x3FFF << 0)

#define IDMA_IN_BASE_ADDR_Y8			0x0040
#define IDMA_IN_BASE_ADDR_C8			0x0044
#define IDMA_IN_BASE_ADDR_Y2			0x0048
#define IDMA_IN_BASE_ADDR_C2			0x004C

#define IDMA_SRC_STRIDE_0			0x0050
#define IDMA_PLANE_3_STRIDE_SEL			(1 << 23)
#define IDMA_PLANE_2_STRIDE_SEL			(1 << 22)
#define IDMA_PLANE_1_STRIDE_SEL			(1 << 21)
#define IDMA_PLANE_0_STRIDE_SEL			(1 << 20)
#define IDMA_CHROM_STRIDE_SEL			(1 << 16)
#define IDMA_CHROM_STRIDE(_v)			((_v) << 0)
#define IDMA_CHROM_STRIDE_MASK			(0xFFFF << 0)

#define IDMA_SRC_STRIDE_1			0x0054
#define IDMA_PLANE_1_STRIDE(_v)			((_v) << 16)
#define IDMA_PLANE_1_STRIDE_MASK		(0xffff << 16)
#define IDMA_PLANE_0_STRIDE(_v)			((_v) << 0)
#define IDMA_PLANE_0_STRIDE_MASK		(0xffff << 0)

#define IDMA_SRC_STRIDE_2			0x0058
#define IDMA_PLANE_3_STRIDE(_v)			((_v) << 16)
#define IDMA_PLANE_3_STRIDE_MASK		(0xffff << 16)
#define IDMA_PLANE_2_STRIDE(_v)			((_v) << 0)
#define IDMA_PLANE_2_STRIDE_MASK		(0xffff << 0)

/*
// Not support in 9830
#define IDMA_AFBC_PARAM				0x0060
#define IDMA_AFBC_BLOCK_SIZE(_v)		((_v) << 0)
#define IDMA_AFBC_BLOCK_SIZE_MASK		(0x3 << 0)
#define IDMA_AFBC_BLOCK_SIZE_16_16		(0)
#define IDMA_AFBC_BLOCK_SIZE_32_8		(1)
#define IDMA_AFBC_BLOCK_SIZE_64_4		(2)
*/

/* [9830] SWBC_PARAM is added */
#define IDMA_SBWC_PARAM				0x0064
#define IDMA_CHM_BLK_SIZE(_v)			((_v) << 2)
#define IDMA_CHM_BLK_SIZE_MASK			(0x3 << 2)
#define IDMA_CHM_BLK_SIZE_32_4			(0)
#define IDMA_CHM_BLK_SIZE_16_8			(1)
#define IDMA_CHM_BLK_SIZE_64_4			(2)
#define IDMA_LUM_BLK_SIZE(_v)			((_v) << 0)
#define IDMA_LUM_BLK_SIZE_MASK			(0x3 << 0)
#define IDMA_LUM_BLK_SIZE_16_16			(0)
#define IDMA_LUM_BLK_SIZE_32_8			(1)
#define IDMA_LUM_BLK_SIZE_64_4			(2)

/*
// Not support in 9830
#define IDMA_CSET_PARAM				0x0068
#define IDMA_GB_BASE(_v)			((_v) << 0)
#define IDMA_GB_BASE_MASK			(0x1f << 0)
*/

#define IDMA_RECOVERY_CTRL			0x0070
#define IDMA_RECOVERY_NUM(_v)			((_v) << 1)
#define IDMA_RECOVERY_NUM_MASK			(0x7fffffff << 1)
#define IDMA_RECOVERY_EN			(1 << 0)

/* [9830] IDMA_DEADLOCK_NUM -> IDMA_DEADLOCK_EN */
#define IDMA_DEADLOCK_EN			0x0100
#define IDMA_DEADLOCK_TIMER(_v)			((_v) << 1)
#define IDMA_DEADLOCK_TIMER_MASK		(0x7fffffff << 1)
#define IDMA_DEADLOCK_TIMER_EN			(1 << 0)

#define IDMA_BUS_CON				0x0110

/* [9830] IDMA_CACHE_CON is added */
#define IDMA_CACHE_CON				0x0114
#define IDMA_DATA_SAHRE_TYPE_P3(_v)		((_v) << 28)
#define IDMA_DATA_SAHRE_TYPE_P3_MASK		(0x3 << 28)
#define IDMA_LLC_HINT_P3(_v)			((_v) << 24)
#define IDMA_LLC_HINT_P3_MASK			(0x7 << 24)
#define IDMA_DATA_SAHRE_TYPE_P2(_v)		((_v) << 20)
#define IDMA_DATA_SAHRE_TYPE_P2_MASK		(0x3 << 20)
#define IDMA_LLC_HINT_P2(_v)			((_v) << 16)
#define IDMA_LLC_HINT_P2_MASK			(0x7 << 16)
#define IDMA_DATA_SAHRE_TYPE_P1(_v)		((_v) << 12)
#define IDMA_DATA_SAHRE_TYPE_P1_MASK		(0x3 << 12)
#define IDMA_LLC_HINT_P1(_v)			((_v) << 8)
#define IDMA_LLC_HINT_P1_MASK			(0x7 << 8)
#define IDMA_DATA_SAHRE_TYPE_P0(_v)		((_v) << 4)
#define IDMA_DATA_SAHRE_TYPE_P0_MASK		(0x3 << 4)
#define IDMA_LLC_HINT_P0(_v)			((_v) << 0)
#define IDMA_LLC_HINT_P0_MASK			(0x7 << 0)

/* [9830] IDMA_PERFORMANCE_CON is added at each layer */
#define IDMA_PERFORMANCE_CON			0x0120
#define IDMA_DEGRADATION_TIME(_v)		((_v) << 16)
#define IDMA_DEGRADATION_TIME_MASK		(0xFFFF << 16)
#define IDMA_IN_IC_MAX_DEG(_v)			((_v) << 4)
#define IDMA_IN_IC_MAX_DEG_MASK			(0xFF << 4)
#define IDMA_DEGRADATION_EN			(1 << 0)

/* [9830] IDMA_QOS_LUT is added at each layer */
/* _n: [0,7], _v: [0x0, 0xF] */
#define IDMA_QOS_LUT07_00			0x0130
#define IDMA_QOS_LUT15_08			0x0134
#define IDMA_QOS_LUT(_n, _v)			((_v) << (4*(_n)))
#define IDMA_QOS_LUT_MASK(_n)			(0xF << (4*(_n)))

#define IDMA_DYNAMIC_GATING_EN			0x0140
#define IDMA_SRAM_CG_EN				(1 << 31)
#define IDMA_DG_EN(_n, _v)			((_v) << (_n))
#define IDMA_DG_EN_MASK(_n)			(1 << (_n))
#define IDMA_DG_EN_ALL				(0x7FFFFFFF << 0)

#define IDMA_DEBUG_CONTROL			0x0300
#define IDMA_DEBUG_CONTROL_SEL(_v)		((_v) << 16)
#define IDMA_DEBUG_CONTROL_EN			(0x1 << 0)

#define IDMA_DEBUG_DATA				0x0304

/* 0: AXI, 3: Pattern */
#define IDMA_IN_REQ_DEST			0x0308
#define IDMA_IN_REG_DEST_SEL(_v)		((_v) << 0)
#define IDMA_IN_REG_DEST_SEL_MASK		(0x3 << 0)

/* [9830] IDMA_PSLV_ERR_CTRL is added */
#define IDMA_PSLV_ERR_CTRL			0x030c
#define IDMA_PSLVERR_CTRL			(1 << 0)

/* [9830] IDMA_DEBUG_ADDR_Y/C is added */
#define IDMA_DEBUG_ADDR_Y8			0x0310
#define IDMA_DEBUG_ADDR_C8			0x0314
#define IDMA_DEBUG_ADDR_Y2			0x0318
#define IDMA_DEBUG_ADDR_C2			0x031C

/* [9830] IDMA_DEBUG_ADDR_CTRL is added */
#define IDMA_DEBUG_ADDR_CTRL			0x0320
#define IDMA_DBG_EN_ADDR_C2			(1 << 3)
#define IDMA_DBG_EN_ADDR_Y2			(1 << 2)
#define IDMA_DBG_EN_ADDR_C8			(1 << 1)
#define IDMA_DBG_EN_ADDR_Y8			(1 << 0)

#define IDMA_CFG_ERR_STATE			0x0b30
#define IDMA_CFG_ERR_ROTATION			(1 << 21)
#define IDMA_CFG_ERR_IMG_HEIGHT_ROTATION	(1 << 20)
#define IDMA_CFG_ERR_AFBC			(1 << 18)
#define IDMA_CFG_ERR_SBWC			(1 << 17)
#define IDMA_CFG_ERR_BLOCK			(1 << 16)
#define IDMA_CFG_ERR_FORMAT			(1 << 15)
#define IDMA_CFG_ERR_STRIDE3			(1 << 14)
#define IDMA_CFG_ERR_STRIDE2			(1 << 13)
#define IDMA_CFG_ERR_STRIDE1			(1 << 12)
#define IDMA_CFG_ERR_STRIDE0			(1 << 11)
#define IDMA_CFG_ERR_CHROM_STRIDE		(1 << 10)
#define IDMA_CFG_ERR_BASE_ADDR_C2		(1 << 9)
#define IDMA_CFG_ERR_BASE_ADDR_Y2		(1 << 8)
#define IDMA_CFG_ERR_BASE_ADDR_C8		(1 << 7)
#define IDMA_CFG_ERR_BASE_ADDR_Y8		(1 << 6)
#define IDMA_CFG_ERR_SRC_OFFSET_Y		(1 << 5)
#define IDMA_CFG_ERR_SRC_OFFSET_X		(1 << 4)
#define IDMA_CFG_ERR_IMG_HEIGHT			(1 << 3)
#define IDMA_CFG_ERR_IMG_WIDTH			(1 << 2)
#define IDMA_CFG_ERR_SRC_HEIGHT			(1 << 1)
#define IDMA_CFG_ERR_SRC_WIDTH			(1 << 0)
#define IDMA_CFG_ERR_GET(_v)			(((_v) >> 0) & 0x3FFFFF)

/*
 * ODMA SFR list
 * base address : 0x19077000
 */
#define ODMA_ENABLE				0x0000
#define ODMA_SRSET				(1 << 24)
#define ODMA_SFR_UPDATE_FORCE			(1 << 4)
#define ODMA_OP_STATUS				(1 << 2)
#define ODMA_INSTANT_OFF_PENDING		(1 << 1)

#define ODMA_IRQ				0x0004
#define ODMA_CONFIG_ERROR			(1 << 28)
#define ODMA_LOCAL_HW_RESET_DONE		(1 << 20)
#define ODMA_WRITE_SLAVE_ERROR			(1 << 19)
#define ODMA_STATUS_DEADLOCK_IRQ		(1 << 17)
#define ODMA_STATUS_FRAMEDONE_IRQ		(1 << 16)
#define ODMA_ALL_IRQ_CLEAR			(0x101B << 16)

#define ODMA_CONFIG_ERROR_MASK			(1 << 13)
#define ODMA_LOCAL_HW_RESET_DONE_MASK		(1 << 5)
#define ODMA_WRITE_SLAVE_ERROR_MASK		(1 << 4)
#define ODMA_IRQ_DEADLOCK_MASK			(1 << 2)
#define ODMA_IRQ_FRAMEDONE_MASK			(1 << 1)
#define ODMA_ALL_IRQ_MASK			(0x101B << 1)
#define ODMA_IRQ_ENABLE				(1 << 0)

#define ODMA_CHROMINANCE_STRIDE			0x0020
#define ODMA_STRIDE_3_SEL			(1 << 23)
#define ODMA_STRIDE_2_SEL			(1 << 22)
#define ODMA_STRIDE_1_SEL			(1 << 21)
#define ODMA_STRIDE_0_SEL			(1 << 20)
#define ODMA_CHROM_STRIDE_SEL			(1 << 16)
#define ODMA_CHROM_STRIDE(_v)			((_v) << 0)
#define ODMA_CHROM_STRIDE_MASK			(0xFFFF << 0)

#define ODMA_WB_STRIDE_0			0x0024
#define ODMA_STRIDE_1(_v)			((_v) << 16)
#define ODMA_STRIDE_1_MASK			(0xffff << 16)
#define ODMA_STRIDE_0(_v)			((_v) << 0)
#define ODMA_STRIDE_0_MASK			(0xffff << 16)

#define ODMA_WB_STRIDE_1			0x0028
#define ODMA_STRIDE_3(_v)			((_v) << 16)
#define ODMA_STRIDE_3_MASK			(0xffff << 16)
#define ODMA_STRIDE_2(_v)			((_v) << 0)
#define ODMA_STRIDE_2_MASK			(0xffff << 16)

#define ODMA_PERFORMANCE_CON0			0x0030
#define ODMA_DEGRADATION_TIME(_v)		((_v) << 16)
#define ODMA_DEGRADATION_TIME_MASK		(0xFFFF << 16)
#define ODMA_DEGRADATION_EN			(1 << 15)
#define ODMA_IN_IC_MAX_DEG(_v)			((_v) << 0)
#define ODMA_IN_IC_MAX_DEG_MASK			(0xFF << 0)

#define ODMA_OUT_CON0				0x004C
#define ODMA_OUT_IC_MAX(_v)			((_v) << 19)
#define ODMA_OUT_IC_MAX_MASK			(0xFF << 19)
#define ODMA_IMG_FORMAT(_v)			((_v) << 11)
#define ODMA_IMG_FORMAT_MASK			(0x3f << 11)

#define ODMA_OUT_CON1				0x0050
#define ODMA_OUT_FRAME_ALPHA(_v)		((_v) << 24)
#define ODMA_OUT_FRAME_ALPHA_MASK		(0xff << 24)

#define ODMA_DST_SIZE				0x0054
#define ODMA_DST_HEIGHT(_v)			((_v) << 16)
#define ODMA_DST_HEIGHT_MASK			(0x3FFF << 16)
#define ODMA_DST_WIDTH(_v)			((_v) << 0)
#define ODMA_DST_WIDTH_MASK			(0xFFFF << 0)

#define ODMA_DST_OFFSET				0x0058
#define ODMA_DST_OFFSET_Y(_v)			((_v) << 16)
#define ODMA_DST_OFFSET_Y_MASK			(0x1FFF << 16)
#define ODMA_DST_OFFSET_X(_v)			((_v) << 0)
#define ODMA_DST_OFFSET_X_MASK			(0x1FFF << 0)

#define ODMA_OUT_IMG_SIZE			0x005C
#define ODMA_OUT_IMG_HEIGHT(_v)			((_v) << 16)
#define ODMA_OUT_IMG_HEIGHT_MASK		(0x1FFF << 16)
#define ODMA_OUT_IMG_WIDTH(_v)			((_v) << 0)
#define ODMA_OUT_IMG_WIDTH_MASK			(0x1FFF << 0)

#define ODMA_OUT_QOS_LUT07_00			0x0060
#define ODMA_OUT_QOS_LUT15_08			0x0064
#define ODMA_OUT_QOS_LUT(_n, _v)		((_v) << (4*(_n)))
#define ODMA_OUT_QOS_LUT_MASK(_n)		(0xF << (4*(_n)))

#define ODMA_IN_BASE_ADDR_Y8			0x0074
#define ODMA_IN_BASE_ADDR_Y2			0x0078
#define ODMA_IN_BASE_ADDR_C8			0x0094
#define ODMA_IN_BASE_ADDR_C2			0x0098

#define ODMA_DEADLOCK_NUM			0x0300
#define ODMA_DEADLOCK_VAL(_v)			((_v) << 1)
#define ODMA_DEADLOCK_VAL_MASK			(0x7FFFFFFF << 1)
#define ODMA_DEADLOCK_EN			(1 << 0)

#define ODMA_BUS_CON				0x0304

#define ODMA_CACHE_CON				0x0308
#define ODMA_DATA_SAHRE_TYPE_P3(_v)		((_v) << 28)
#define ODMA_DATA_SAHRE_TYPE_P3_MASK		(0x3 << 28)
#define ODMA_LLC_HINT_P3(_v)			((_v) << 24)
#define ODMA_LLC_HINT_P3_MASK			(0x7 << 24)
#define ODMA_DATA_SAHRE_TYPE_P2(_v)		((_v) << 20)
#define ODMA_DATA_SAHRE_TYPE_P2_MASK		(0x3 << 20)
#define ODMA_LLC_HINT_P2(_v)			((_v) << 16)
#define ODMA_LLC_HINT_P2_MASK			(0x7 << 16)
#define ODMA_DATA_SAHRE_TYPE_P1(_v)		((_v) << 12)
#define ODMA_DATA_SAHRE_TYPE_P1_MASK		(0x3 << 12)
#define ODMA_LLC_HINT_P1(_v)			((_v) << 8)
#define ODMA_LLC_HINT_P1_MASK			(0x7 << 8)
#define ODMA_DATA_SAHRE_TYPE_P0(_v)		((_v) << 4)
#define ODMA_DATA_SAHRE_TYPE_P0_MASK		(0x3 << 4)
#define ODMA_LLC_HINT_P0(_v)			((_v) << 0)
#define ODMA_LLC_HINT_P0_MASK			(0x7 << 0)

/* _n: [0,31], v: [0,1] */
#define ODMA_DYNAMIC_GATING_EN			0x0354
#define ODMA_DG_EN(_n, _v)			((_v) << (_n))
#define ODMA_DG_EN_MASK(_n)			(1 << (_n))
#define ODMA_DG_EN_ALL				(0xFFFFFFFF)

#define ODMA_DEBUG_CONTROL			0x0360
#define ODMA_DEBUG_CONTROL_SEL(_v)		((_v) << 16)
#define ODMA_DEBUG_CONTROL_EN			(0x1 << 0)
#define ODMA_DEBUG_DATA				0x0364

#define ODMA_PSLV_ERR_CTRL			0x0370
#define ODMA_PSLVERR_CTRL			(1 << 0)


#define DMA_SHD_OFFSET				0x800
// ADD field def

#define ODMA_CFG_ERR_STATE			0x0C08
#define ODMA_CFG_ERR_STRIDE2			(1 << 12)
#define ODMA_CFG_ERR_STRIDE0			(1 << 11)
#define ODMA_CFG_ERR_CHROM_STRIDE		(1 << 10)
#define ODMA_CFG_ERR_BASE_ADDR_C2		(1 << 9)
#define ODMA_CFG_ERR_BASE_ADDR_Y2		(1 << 8)
#define ODMA_CFG_ERR_BASE_ADDR_C8		(1 << 7)
#define ODMA_CFG_ERR_BASE_ADDR_Y8		(1 << 6)
#define ODMA_CFG_ERR_DST_OFFSET_Y		(1 << 5)
#define ODMA_CFG_ERR_DST_OFFSET_X		(1 << 4)
#define ODMA_CFG_ERR_IMG_HEIGHT			(1 << 3)
#define ODMA_CFG_ERR_IMG_WIDTH			(1 << 2)
#define ODMA_CFG_ERR_DST_HEIGHT			(1 << 1)
#define ODMA_CFG_ERR_DST_WIDTH			(1 << 0)
#define ODMA_CFG_ERR_GET(_v)			(((_v) >> 0) & 0x1FFFF)

/*
 * 2 - DPU_WB_MUX.base
 *  Non-secure        : 0x1908_0000
 */
#define DPU_WB_ENABLE				0x0000
#define DPU_WB_SRSET				(1 << 24)
#define DPU_WB_SFR_CLOCK_GATE_EN		(1 << 10)
#define DPU_WB_SRAM_CLOCK_GATE_EN		(1 << 9)
#define DPU_WB_INT_CLOCK_GATE_EN		(1 << 8)
#define DPU_WB_ALL_CLOCK_GATE_EN_MASK		(0x7 << 8)
#define DPU_WB_PSLVERR_EN			(1 << 5)
#define DPU_WB_SFR_UPDATE_FORCE			(1 << 4)
#define DPU_WB_QCHANNEL_EN			(1 << 3)
#define DPU_WB_OP_STATUS			(1 << 2)
#define DPU_WB_TZPC_FLAG			(1 << 0)

#define DPU_WB_CSC_CON				0x0008
#define DPU_WB_BPC_MODE(_v)			((_v) << 18)
#define DPU_WB_BPC_MODE_MASK			(1 << 18)
#define DPU_WB_CSC_RANGE(_v)			((_v) << 17)
#define DPU_WB_CSC_RANGE_MASK			(1 << 17)
#define DPU_WB_CSC_MODE(_v)			((_v) << 16)
#define DPU_WB_CSC_MODE_MASK			(1 << 16)
#define DPU_WB_YUV_TYPE(_v)			((_v) << 15)
#define DPU_WB_YUV_TYPE_420			(0 << 15)
#define DPU_WB_YUV_TYPE_422			(1 << 15)
#define DPU_WB_YUV_TYPE_MASK			(1 << 15)
#define DPU_WB_UV_OFFSET_Y(_v)			((_v) << 12)
#define DPU_WB_UV_OFFSET_Y_MASK			(0x7 << 12)
#define DPU_WB_UV_OFFSET_X(_v)			((_v) << 9)
#define DPU_WB_UV_OFFSET_X_MASK			(0x7 << 9)
#define DPU_WB_DITH_MASK_SEL			(1 << 5)
#define DPU_WB_DITH_MASK_SPIN			(1 << 4)
#define DPU_WB_CSC_TYPE(_v)			((_v) << 1)
#define DPU_WB_CSC_TYPE_BT601			(0 << 1)
#define DPU_WB_CSC_TYPE_BT709			(1 << 1)
#define DPU_WB_CSC_TYPE_BT2020			(2 << 1)
#define DPU_WB_CSC_TYPE_DCI_P3			(3 << 1)
#define DPU_WB_CSC_TYPE_MASK			(0x3 << 1)
#define DPU_WB_CSC_R2Y				(1 << 0)

#define DPU_WB_IMG_SIZE				0x0014
#define DPU_WB_IMG_HEIGHT(_v)			((_v) << 16)
#define DPU_WB_IMG_HEIGHT_MASK			(0x1FFF << 16)
#define DPU_WB_IMG_WIDTH(_v)			((_v) << 0)
#define DPU_WB_IMG_WIDTH_MASK			(0x1FFF << 0)

/*
 * (00-01-02) : Reg0.L-Reg0.H-Reg1.L
 * (10-11-12) : Reg1.H-Reg2.L-Reg2.H
 * (20-21-22) : Reg3.L-Reg3.H-Reg4.L
 */
#define DPU_WB_CSC_COEF0			0x0030
#define DPU_WB_CSC_COEF1			0x0034
#define DPU_WB_CSC_COEF2			0x0038
#define DPU_WB_CSC_COEF3			0x003c
#define DPU_WB_CSC_COEF4			0x0040
#define DPU_WB_CSC_COEF_H(_v)			((_v) << 16)
#define DPU_WB_CSC_COEF_H_MASK			(0xFFFF << 16)
#define DPU_WB_CSC_COEF_L(_v)			((_v) << 0)
#define DPU_WB_CSC_COEF_L_MASK			(0xFFFF << 0)
#define DPU_WB_CSC_COEF_XX(_n, _v)		((_v) << (0 + (16 * (_n))))
#define DPU_WB_CSC_COEF_XX_MASK(_n)		(0xFFF << (0 + (16 * (_n))))

#define DPU_WB_DYNAMIC_GATING_EN		0x0A54
#define DPU_WB_DYNAMIC_GATING_EN_ALL		(0xF << 0)
#define DPU_WB_DYNAMIC_GATING_EN_3		(1 << 3)
#define DPU_WB_DYNAMIC_GATING_EN_2		(1 << 2)
#define DPU_WB_DYNAMIC_GATING_EN_1		(1 << 1)
#define DPU_WB_DYNAMIC_GATING_EN_0		(1 << 0)

#define DPU_WB_ENABLE_SHD			0x0B00
#define DPU_WB_CSC_CON_SHD			0x0B08
#define DPU_WB_IMG_SIZE_SHD			0x0B14

#define DPU_WB_LINECNT_CON			0x0D00
#define DPU_WB_CAPTURE				(1 << 2)
#define DPU_WB_MODE				(1 << 1)
#define DPU_WB_LC_ENABLE			(1 << 0)

#define DPU_WB_LINECNT_VAL			0x0D04
#define DPU_WB_COUNTER_C(_v)			((_v) << 16)
#define DPU_WB_COUNTER_C_MASK			(0x1FFF << 16)
#define DPU_WB_COUNTER_Y(_v)			((_v) << 0)
#define DPU_WB_COUNTER_Y_MASK			(0x1FFF << 0)

#define DPU_WB_CFG_ERR_STATE			0x0D08
#define DPU_WB_CFG_ERR_WRONG_PATH		(1 << 3)
#define DPU_WB_CFG_ERR_ODD_SIZE			(1 << 2)
#define DPU_WB_CFG_ERR_MAX_SIZE			(1 << 1)
#define DPU_WB_CFG_ERR_MIN_SIZE			(1 << 0)

/*
 * DPP SFR base address : 0x19040000
 * - DPP GF0(L0)   : 0x19041000
 * - DPP GF1(L1)   : 0x19042000
 * - DPP VG(L2)    : 0x19043000
 * - DPP VGF(L3)   : 0x19044000
 * - DPP VGS(L4)   : 0x19045000
 * - DPP VGRFS(L5) : 0x19046000
 */
#define DPP_ENABLE				0x0000
#define DPP_SRSET				(1 << 24)
#define DPP_HDR_SEL				(1 << 11)
#define DPP_SFR_CLOCK_GATE_EN			(1 << 10)
#define DPP_SRAM_CLOCK_GATE_EN			(1 << 9)
#define DPP_INT_CLOCK_GATE_EN			(1 << 8)
#define DPP_ALL_CLOCK_GATE_EN_MASK		(0x7 << 8)
#define DPP_PSLVERR_EN				(1 << 5)
#define DPP_SFR_UPDATE_FORCE			(1 << 4)
#define DPP_QCHANNEL_EN				(1 << 3)
#define DPP_OP_STATUS				(1 << 2)
#define DPP_TZPC_FLAG				(1 << 0)

#define DPP_IRQ					0x0004
#define DPP_CONFIG_ERROR			(1 << 21)
#define DPP_FRAMEDONE_IRQ			(1 << 16)
#define DPP_ALL_IRQ_CLEAR			(0x21 << 16)
#define DPP_CONFIG_ERROR_MASK			(1 << 6)
#define DPP_FRAMEDONE_IRQ_MASK			(1 << 1)
#define DPP_ALL_IRQ_MASK			(0x21 << 1)
#define DPP_IRQ_ENABLE				(1 << 0)

#define DPP_IN_CON				0x0008
#define DPP_CSC_TYPE(_v)			((_v) << 18)
#define DPP_CSC_TYPE_MASK			(3 << 18)
#define DPP_CSC_RANGE(_v)			((_v) << 17)
#define DPP_CSC_RANGE_MASK			(1 << 17)
#define DPP_CSC_MODE(_v)			((_v) << 16)
#define DPP_CSC_MODE_MASK			(1 << 16)
#define DPP_DITH_MASK_SEL			(1 << 5)
#define DPP_DITH_MASK_SPIN			(1 << 4)
#define DPP_ALPHA_SEL(_v)			((_v) << 3)
#define DPP_ALPHA_SEL_MASK			(1 << 3)
#define DPP_IMG_FORMAT(_v)			((_v) << 0)
#define DPP_IMG_FORMAT_MASK			(0x7 << 0)
#define DPP_IMG_FORMAT_ARGB8888			(0 << 0)
#define DPP_IMG_FORMAT_ARGB8101010		(1 << 0)
#define DPP_IMG_FORMAT_YUV420_8P		(2 << 0)
#define DPP_IMG_FORMAT_YUV420_P010		(3 << 0)
#define DPP_IMG_FORMAT_YUV420_8P2		(4 << 0)
#define DPP_IMG_FORMAT_YUV422_8P		(5 << 0)
#define DPP_IMG_FORMAT_YUV422_P210		(6 << 0)
#define DPP_IMG_FORMAT_YUV422_8P2		(7 << 0)

#define DPP_IMG_SIZE				0x0018
#define DPP_IMG_HEIGHT(_v)			((_v) << 16)
#define DPP_IMG_HEIGHT_MASK			(0x1FFF << 16)
#define DPP_IMG_WIDTH(_v)			((_v) << 0)
#define DPP_IMG_WIDTH_MASK			(0x1FFF << 0)

/* scaler configuration only */
#define DPP_SCALED_IMG_SIZE			0x002C
#define DPP_SCALED_IMG_HEIGHT(_v)		((_v) << 16)
#define DPP_SCALED_IMG_HEIGHT_MASK		(0x1FFF << 16)
#define DPP_SCALED_IMG_WIDTH(_v)		((_v) << 0)
#define DPP_SCALED_IMG_WIDTH_MASK		(0x1FFF << 0)

/*
 * (00-01-02) : Reg0.L-Reg0.H-Reg1.L
 * (10-11-12) : Reg1.H-Reg2.L-Reg2.H
 * (20-21-22) : Reg3.L-Reg3.H-Reg4.L
 */
#define DPP_CSC_COEF0				0x0030
#define DPP_CSC_COEF1				0x0034
#define DPP_CSC_COEF2				0x0038
#define DPP_CSC_COEF3				0x003C
#define DPP_CSC_COEF4				0x0040
#define DPP_CSC_COEF_H(_v)			((_v) << 16)
#define DPP_CSC_COEF_H_MASK			(0xFFFF << 16)
#define DPP_CSC_COEF_L(_v)			((_v) << 0)
#define DPP_CSC_COEF_L_MASK			(0xFFFF << 0)
#define DPP_CSC_COEF_XX(_n, _v)			((_v) << (0 + (16 * (_n))))
#define DPP_CSC_COEF_XX_MASK(_n)		(0xFFF << (0 + (16 * (_n))))

#define DPP_MAIN_H_RATIO			0x0044
#define DPP_H_RATIO(_v)				((_v) << 0)
#define DPP_H_RATIO_MASK			(0xFFFFFF << 0)

#define DPP_MAIN_V_RATIO			0x0048
#define DPP_V_RATIO(_v)				((_v) << 0)
#define DPP_V_RATIO_MASK			(0xFFFFFF << 0)

#define DPP_Y_VCOEF_0A				0x0200
#define DPP_Y_HCOEF_0A				0x0290
#define DPP_C_VCOEF_0A				0x0400
#define DPP_C_HCOEF_0A				0x0490
#define DPP_SCL_COEF(_v)			((_v) << 0)
#define DPP_SCL_COEF_MASK			(0x7FF << 0)
#define DPP_H_COEF(n, s, x)			(0x290 + (n) * 0x4 + (s) * 0x24 + (x) * 0x200)
#define DPP_V_COEF(n, s, x)			(0x200 + (n) * 0x4 + (s) * 0x24 + (x) * 0x200)

#define DPP_YHPOSITION				0x05B0
#define DPP_YVPOSITION				0x05B4
#define DPP_CHPOSITION				0x05B8
#define DPP_CVPOSITION				0x05BC
#define DPP_POS_I(_v)				((_v) << 20)
#define DPP_POS_I_MASK				(0xFFF << 20)
#define DPP_POS_I_GET(_v)			(((_v) >> 20) & 0xFFF)
#define DPP_POS_F(_v)				((_v) << 0)
#define DPP_POS_F_MASK				(0xFFFFF << 0)
#define DPP_POS_F_GET(_v)			(((_v) >> 0) & 0xFFFFF)

/* 0x0A00 ~ 0x0A1C : ASHE */

#define DPP_DYNAMIC_GATING_EN			0x0A54
/* _n: [0 ~ 4, 6], v: [0,1] */
#define DPP_DG_EN(_n, _v)			((_v) << (_n))
#define DPP_DG_EN_MASK(_n)			(1 << (_n))
#define DPP_DG_EN_ALL				(0x5F << 0)

#define DPP_LINECNT_CON				0x0D00
#define DPP_LC_CAPTURE(_v)			((_v) << 2)
#define DPP_LC_CAPTURE_MASK			(1 << 2)
#define DPP_LC_MODE(_V)				((_V) << 1)
#define DPP_LC_MODE_MASK			(1 << 1)
#define DPP_LC_ENABLE(_v)			((_v) << 0)
#define DPP_LC_ENABLE_MASK			(1 << 0)

#define DPP_LINECNT_VAL				0x0D04
#define DPP_LC_COUNTER(_v)			((_v) << 0)
#define DPP_LC_COUNTER_MASK			(0x1FFF << 0)
#define DPP_LC_COUNTER_GET(_v)			(((_v) >> 0) & 0x1FFF)

#define DPP_CFG_ERR_STATE			0x0D08
#define DPP_CFG_ERR_SCL_POS			(1 << 4)
#define DPP_CFG_ERR_SCALE_RATIO			(1 << 3)
#define DPP_CFG_ERR_ODD_SIZE			(1 << 2)
#define DPP_CFG_ERR_MAX_SIZE			(1 << 1)
#define DPP_CFG_ERR_MIN_SIZE			(1 << 0)
#define DPP_CFG_ERR_GET(_v)			(((_v) >> 0) & 0x1F)

/*
 * 9830 : no HDR Layer
 * E9830 doesn't support HDR, but we've left it because of the compilation.
 */
#if 1
/* HDR section */
/* Enable/Disable HDR processing */
#define DPP_VGRF_HDR_CON		0x600
#define DPP_TM_ON(_v)			((_v) << 3)
#define DPP_TM_ON_MASK			(1 << 3)
#define DPP_GM_ON(_v)			((_v) << 2)
#define DPP_GM_ON_MASK			(1 << 2)
#define DPP_EOTF_ON(_v)			((_v) << 1)
#define DPP_EOTF_ON_MASK		(1 << 1)
#define DPP_HDR_ON(_v)			((_v) << 0)
#define DPP_HDR_ON_MASK			(1 << 0)

/* EOTF */
#define DPP_HDR_EOTF_X_AXIS_ADDR(_n)	(((_n) / 2) * (0x4) + (0x610))
#define DPP_HDR_EOTF_X_AXIS_VAL(_n, _v)	\
	(((_n) % (2)) ? (((_v) & 0x3FFF) << 16) : (((_v) & 0x3FFF) << 0))

#define DPP_HDR_EOTF_Y_AXIS_ADDR(_n)	(((_n) / 2) * (0x4) + (0x694))
#define DPP_HDR_EOTF_Y_AXIS_VAL(_n, _v)	\
	(((_n) % (2)) ? (((_v) & 0x3FFF) << 16) : (((_v) & 0x3FFF) << 0))

#define DPP_HDR_EOTF_MASK(_n)		(((_n) % 2) ? (0x3FFF << 16) : (0x3FFF << 0))


/* GM */
#define DPP_HDR_GM_COEF_ADDR(_n)	((_n) * (0x4) + (0x720))
#define DPP_HDR_GM_COEF_MASK	(0x1FFFF << 0)

/* TM */
#define DPP_HDR_TM_X_AXIS_ADDR(_n)	(((_n) / 2) * (0x4) + (0x750))
#define DPP_HDR_TM_X_AXIS_VAL(_n, _v)	\
	(((_n) % (2)) ? (((_v) & 0x3FFF) << 16) : (((_v) & 0x3FFF) << 0))

#define DPP_HDR_TM_Y_AXIS_ADDR(_n)	(((_n) / 2) * (0x4) + (0x794))
#define DPP_HDR_TM_Y_AXIS_VAL(_n, _v)	\
	(((_n) % (2)) ? (((_v) & 0x3FFF) << 16) : (((_v) & 0x3FFF) << 0))

#define DPP_HDR_TM_MASK(_n)		(((_n) % 2) ? (0x3FFF << 16) : (0x3FFF << 0))

#define DPP_VGRF_HDR_EOTF_X_AXIS_0	0x0610
#define DPP_VGRF_HDR_EOTF_X_AXIS_1	0x0614
#define DPP_VGRF_HDR_EOTF_X_AXIS_2	0x0618
#define DPP_VGRF_HDR_EOTF_X_AXIS_3	0x061C
#define DPP_VGRF_HDR_EOTF_X_AXIS_4	0x0620
#define DPP_VGRF_HDR_EOTF_X_AXIS_5	0x0624
#define DPP_VGRF_HDR_EOTF_X_AXIS_6	0x0628
#define DPP_VGRF_HDR_EOTF_X_AXIS_7	0x062C
#define DPP_VGRF_HDR_EOTF_X_AXIS_8	0x0630
#define DPP_VGRF_HDR_EOTF_X_AXIS_9	0x0634
#define DPP_VGRF_HDR_EOTF_X_AXIS_10	0x0638
#define DPP_VGRF_HDR_EOTF_X_AXIS_11	0x063C
#define DPP_VGRF_HDR_EOTF_X_AXIS_12	0x0640
#define DPP_VGRF_HDR_EOTF_X_AXIS_13	0x0644
#define DPP_VGRF_HDR_EOTF_X_AXIS_14	0x0648
#define DPP_VGRF_HDR_EOTF_X_AXIS_15	0x064C
#define DPP_VGRF_HDR_EOTF_X_AXIS_16	0x0650
#define DPP_VGRF_HDR_EOTF_X_AXIS_17	0x0654
#define DPP_VGRF_HDR_EOTF_X_AXIS_18	0x0658
#define DPP_VGRF_HDR_EOTF_X_AXIS_19	0x065C
#define DPP_VGRF_HDR_EOTF_X_AXIS_20	0x0660
#define DPP_VGRF_HDR_EOTF_X_AXIS_21	0x0664
#define DPP_VGRF_HDR_EOTF_X_AXIS_22	0x0668
#define DPP_VGRF_HDR_EOTF_X_AXIS_23	0x066C
#define DPP_VGRF_HDR_EOTF_X_AXIS_24	0x0670
#define DPP_VGRF_HDR_EOTF_X_AXIS_25	0x0674
#define DPP_VGRF_HDR_EOTF_X_AXIS_26	0x0678
#define DPP_VGRF_HDR_EOTF_X_AXIS_27	0x067C
#define DPP_VGRF_HDR_EOTF_X_AXIS_28	0x0680
#define DPP_VGRF_HDR_EOTF_X_AXIS_29	0x0684
#define DPP_VGRF_HDR_EOTF_X_AXIS_30	0x0688
#define DPP_VGRF_HDR_EOTF_X_AXIS_31	0x068C
#define DPP_VGRF_HDR_EOTF_X_AXIS_32	0x0690

#define DPP_VGRF_HDR_EOTF_Y_AXIS_0	0x0694
#define DPP_VGRF_HDR_EOTF_Y_AXIS_1	0x0698
#define DPP_VGRF_HDR_EOTF_Y_AXIS_2	0x069C
#define DPP_VGRF_HDR_EOTF_Y_AXIS_3	0x06A0
#define DPP_VGRF_HDR_EOTF_Y_AXIS_4	0x06A4
#define DPP_VGRF_HDR_EOTF_Y_AXIS_5	0x06A8
#define DPP_VGRF_HDR_EOTF_Y_AXIS_6	0x06AC
#define DPP_VGRF_HDR_EOTF_Y_AXIS_7	0x06B0
#define DPP_VGRF_HDR_EOTF_Y_AXIS_8	0x06B4
#define DPP_VGRF_HDR_EOTF_Y_AXIS_9	0x06B8
#define DPP_VGRF_HDR_EOTF_Y_AXIS_10	0x06BC
#define DPP_VGRF_HDR_EOTF_Y_AXIS_11	0x06C0
#define DPP_VGRF_HDR_EOTF_Y_AXIS_12	0x06C4
#define DPP_VGRF_HDR_EOTF_Y_AXIS_13	0x06C8
#define DPP_VGRF_HDR_EOTF_Y_AXIS_14	0x06CC
#define DPP_VGRF_HDR_EOTF_Y_AXIS_15	0x06D0
#define DPP_VGRF_HDR_EOTF_Y_AXIS_16	0x06D4
#define DPP_VGRF_HDR_EOTF_Y_AXIS_17	0x06D8
#define DPP_VGRF_HDR_EOTF_Y_AXIS_18	0x06DC
#define DPP_VGRF_HDR_EOTF_Y_AXIS_19	0x06E0
#define DPP_VGRF_HDR_EOTF_Y_AXIS_20	0x06E4
#define DPP_VGRF_HDR_EOTF_Y_AXIS_21	0x06E8
#define DPP_VGRF_HDR_EOTF_Y_AXIS_22	0x06EC
#define DPP_VGRF_HDR_EOTF_Y_AXIS_23	0x06F0
#define DPP_VGRF_HDR_EOTF_Y_AXIS_24	0x06F4
#define DPP_VGRF_HDR_EOTF_Y_AXIS_25	0x06F8
#define DPP_VGRF_HDR_EOTF_Y_AXIS_26	0x06FC
#define DPP_VGRF_HDR_EOTF_Y_AXIS_27	0x0700
#define DPP_VGRF_HDR_EOTF_Y_AXIS_28	0x0704
#define DPP_VGRF_HDR_EOTF_Y_AXIS_29	0x0708
#define DPP_VGRF_HDR_EOTF_Y_AXIS_30	0x070C
#define DPP_VGRF_HDR_EOTF_Y_AXIS_31	0x0710
#define DPP_VGRF_HDR_EOTF_Y_AXIS_32	0x0714

#define DPP_VGRF_HDR_GM_COEF_0_0	0x0720
#define DPP_VGRF_HDR_GM_COEF_0_1	0x0724
#define DPP_VGRF_HDR_GM_COEF_0_2	0x0728
#define DPP_VGRF_HDR_GM_COEF_1_0	0x072C
#define DPP_VGRF_HDR_GM_COEF_1_1	0x0730
#define DPP_VGRF_HDR_GM_COEF_1_2	0x0734
#define DPP_VGRF_HDR_GM_COEF_2_0	0x0738
#define DPP_VGRF_HDR_GM_COEF_2_1	0x073C
#define DPP_VGRF_HDR_GM_COEF_2_2	0x0740

#define DPP_VGRF_HDR_TM_X_AXIS_0	0x0750
#define DPP_VGRF_HDR_TM_X_AXIS_1	0x0754
#define DPP_VGRF_HDR_TM_X_AXIS_2	0x0758
#define DPP_VGRF_HDR_TM_X_AXIS_3	0x075C
#define DPP_VGRF_HDR_TM_X_AXIS_4	0x0760
#define DPP_VGRF_HDR_TM_X_AXIS_5	0x0764
#define DPP_VGRF_HDR_TM_X_AXIS_6	0x0768
#define DPP_VGRF_HDR_TM_X_AXIS_7	0x076C
#define DPP_VGRF_HDR_TM_X_AXIS_8	0x0770
#define DPP_VGRF_HDR_TM_X_AXIS_9	0x0774
#define DPP_VGRF_HDR_TM_X_AXIS_10	0x0778
#define DPP_VGRF_HDR_TM_X_AXIS_11	0x077C
#define DPP_VGRF_HDR_TM_X_AXIS_12	0x0780
#define DPP_VGRF_HDR_TM_X_AXIS_13	0x0784
#define DPP_VGRF_HDR_TM_X_AXIS_14	0x0788
#define DPP_VGRF_HDR_TM_X_AXIS_15	0x078C
#define DPP_VGRF_HDR_TM_X_AXIS_16	0x0790

#define DPP_VGRF_HDR_TM_Y_AXIS_0	0x0794
#define DPP_VGRF_HDR_TM_Y_AXIS_1	0x0798
#define DPP_VGRF_HDR_TM_Y_AXIS_2	0x079C
#define DPP_VGRF_HDR_TM_Y_AXIS_3	0x07A0
#define DPP_VGRF_HDR_TM_Y_AXIS_4	0x07A4
#define DPP_VGRF_HDR_TM_Y_AXIS_5	0x07A8
#define DPP_VGRF_HDR_TM_Y_AXIS_6	0x07AC
#define DPP_VGRF_HDR_TM_Y_AXIS_7	0x07B0
#define DPP_VGRF_HDR_TM_Y_AXIS_8	0x07B4
#define DPP_VGRF_HDR_TM_Y_AXIS_9	0x07B8
#define DPP_VGRF_HDR_TM_Y_AXIS_10	0x07BC
#define DPP_VGRF_HDR_TM_Y_AXIS_11	0x07C0
#define DPP_VGRF_HDR_TM_Y_AXIS_12	0x07C4
#define DPP_VGRF_HDR_TM_Y_AXIS_13	0x07C8
#define DPP_VGRF_HDR_TM_Y_AXIS_14	0x07CC
#define DPP_VGRF_HDR_TM_Y_AXIS_15	0x07D0
#define DPP_VGRF_HDR_TM_Y_AXIS_16	0x07D4
#endif /* no HDR */

#endif
