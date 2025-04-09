#ifndef _USB_H_
#define _USB_H_

const char *fastboot_get_serialno_string(void);

void platform_prepare_reboot(void);
void lk3rd_emergency_reboot(void);

#endif /* _BOOT_IMAGE_H_ */
