/*
 * Copyright@ Samsung Electronics Co. LTD
 *
 * This software is proprietary of Samsung Electronics.
 * No part of this software, either material or conceptual may be copied or distributed, transmitted,
 * transcribed, stored in a retrieval system or translated into any human or computer language in any form by any means,
 * electronic, mechanical, manual or otherwise, or disclosed
 * to third parties without the express written permission of Samsung Electronics.
 */

#ifndef __CMD_BOOT_H__
#define __CMD_BOOT_H__
int boot_fb_continue(void);
int boot_fb_boot(unsigned long buf_addr, size_t size);

void mainline_boot(void);
void mainline_boot_fb_boot(unsigned long buf_addr, size_t size);
#endif // __CMD_BOOT_H__
