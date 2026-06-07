#include <string.h>
#include <stdlib.h>

#include <part.h>

#include <lib/font_display.h>

#include <dev/ufs.h>

#include <lk3rd/gpt.h>

void platform_do_reboot(const char *cmd_buf);

void show_automatic_repartitioning_warning(void)
{
    for (int i = 15; i > 0; i--)
    {
        show_warning("Automatic Repartitioning", "Notice! Lk3rd will automatically repartition your device to allow boot to be modifiable in userspace without breaking lk3rd, "
                                                 "if you do not want this, reboot now and uninstall lk3rd.\n\n"
                                                 "Starting in %ds", i);

        mdelay(1000);
    }
}

void show_repartition_success(int type)
{
    // We technically do not need to reboot but we may as well just for sanity's sake
    if(type == 0)
    {
        for (int i = 5; i > 0; i--)
        {
            show_success("Automatic Repartitioning", "Sucessfully repartitioned device, lk3rd and boot are now seperated in userspace.\n\n\n"
                                                     "Rebooting device in %ds", i);

            mdelay(1000);
        }
    }
    else if (type == 1)
    {
        for (int i = 5; i > 0; i--)
        {
            show_success("Automatic Repartitioning", "Successfully queried GPT rebuild, lk3rd is no longer installed on this device "
                                                     "and the next reboot Samsungs bootloader will rebuild the GPT from PIT, "
                                                     "restoring the partition table to stock.\n\n"
                                                     "Rebooting device in %ds", i);

            mdelay(1000);
        }
    }
    else
    {
        for (int i = 5; i > 0; i--)
        {
            show_success("Automatic Repartitioning", "Successfully queried GPT rebuild."
                                                     "The next reboot Samsungs bootloader will rebuild the GPT from PIT, "
                                                     "restoring the partition table to stock.\n\n"
                                                     "Rebooting device in %ds", i);

            mdelay(1000);
        }
    }

    platform_do_reboot("");
}

void query_gpt_rebuild(bool repartition_fail)
{
    bdev_t *dev;
    u8 *pmbr_buf = malloc(4096);

    dev = bio_open("scsi0");
    if (!dev) {
        printf("failed to open LU0\n");
        return;
    }

    dev->new_read_native(dev, pmbr_buf, 0, 1);

    pmbr_buf[511] = 0x00; // Just screw up mbr, S-LK rebuilds GPT with PIT as reference when the mbr is corrupted.

    dev->new_write_native(dev, pmbr_buf, 0, 1);

    if (repartition_fail)
        show_repartition_success(2);
    else
        show_repartition_success(1);
}

int add_lk3rd_part(void)
{
    bdev_t *dev;
    void *hdr_buf = NULL;
    void *ent_buf = NULL;
    void *bak_hdr_buf = NULL;
    u8 *mbr = NULL;
    struct gpt_header *hdr;
    int ret = -1, lk3rd_idx = -1, boot_idx = -1, free_idx = -1;

    u64 boot_start, boot_end, boot_blks, new_boot_start, new_boot_end, lk3rd_blks, lk3rd_start, lk3rd_end, alt_lba, bak_ent_lba;
    u32 bsz, num, esz;
    u64 elba;

    u8 zero_guid[16] = {0};
    const char *not_a_guid = "who are you?!!!!";

    efi_guid_t boot_type_guid, boot_part_guid;
    gpt_table_attributes boot_attributes;

    struct gpt_part_table *boot_e, *new_boot_e;

    dev = bio_open("scsi0");
    if (!dev) {
        printf("failed to open LU0\n");
        return -1;
    }

    bsz = (u32)dev->block_size;

    hdr_buf = malloc(bsz);
    if (!hdr_buf) goto out_close;

    if (dev->new_read_native(dev, hdr_buf, 1, 1) != 0) goto out_free;
    hdr = (struct gpt_header *)hdr_buf;

    if (hdr->signature != GPT_HEADER_SIGNATURE)
    {
        printf("no valid GPT\n");
        goto out_free;
    }

    num = hdr->part_num_entry;
    esz = hdr->part_size_entry;
    elba = hdr->part_table_lba;

    if (num == 0 || num > GPT_MAX_ENTRIES || esz == 0 || esz > 512)
    {
        printf("bad header fields\n");
        goto out_free;
    }

    u32 ent_bytes = num * esz;
    u32 ent_blocks = (ent_bytes + bsz - 1) / bsz;

    ent_buf = malloc(ent_blocks * bsz);
    if (!ent_buf) goto out_free;

    if (dev->new_read_native(dev, ent_buf, elba, ent_blocks)) goto out_free;

    for (int i = 0; i < (int)num; i++)
    {
        u16 name_tmp[PT_NAME_SZ];
        char name[PT_NAME_SZ + 1] = {0};

        struct gpt_part_table *e = (struct gpt_part_table *)((u8 *)ent_buf + (u32)i * esz);

        if (memcmp(e->part_type.b, zero_guid, 16) == 0)
            continue;

        memcpy(name_tmp, e->part_name, sizeof(name_tmp));
        utf16_to_str(name_tmp, name, sizeof(name));

        if (strcmp(name, "lk3rd") == 0) lk3rd_idx = i;
        if (strcmp(name, "boot") == 0) boot_idx = i;
    }

    if (lk3rd_idx >= 0)
    {
        ret = 0;
        goto out_free;
    }

    if (boot_idx < 0)
        goto out_free;

    show_automatic_repartitioning_warning();

    boot_e = (struct gpt_part_table *)((u8 *)ent_buf + boot_idx * esz);

    boot_start = boot_e->part_start_lba;
    boot_end = boot_e->part_end_lba;
    boot_blks = boot_end - boot_start + 1;
    lk3rd_blks = 2097152 / bsz;

    if (lk3rd_blks >= boot_blks)
    {
        printf("boot partition too small to split!\n");
        goto out_free;
    }

    new_boot_start = boot_start + lk3rd_blks;
    new_boot_end = boot_end;
    lk3rd_start = boot_start;
    lk3rd_end = boot_start + lk3rd_blks - 1;

    u32 full_ent_bytes = GPT_MAX_ENTRIES * esz;
    u32 full_ent_blocks = (full_ent_bytes + bsz - 1) / bsz;

    if (full_ent_blocks > ent_blocks)
    {
        free(ent_buf);
        ent_buf = malloc(full_ent_blocks * bsz);
        if (!ent_buf) goto out_free;
        if (dev->new_read_native(dev, ent_buf, elba, full_ent_blocks)) goto out_free;

        boot_e = (struct gpt_part_table *)((u8 *)ent_buf + boot_idx * esz);

        ent_blocks = full_ent_blocks;
    }

    for (int i = 0; i < GPT_MAX_ENTRIES; i++)
    {
        if (i == boot_idx) continue;

        struct gpt_part_table *e = (struct gpt_part_table *)((u8 *)ent_buf + i * esz);

        if (memcmp(e->part_type.b, zero_guid, 16) == 0) {
            free_idx = i;
            break;
        }
    }

    if (free_idx < 0)
    {
        printf("no free entry\n");
        goto out_free;
    }

    memcpy(&boot_type_guid, &boot_e->part_type,  sizeof(efi_guid_t));
    memcpy(&boot_part_guid, &boot_e->part_guid,  sizeof(efi_guid_t));
    memcpy(&boot_attributes, &boot_e->attributes, sizeof(gpt_table_attributes));

    new_boot_e = (struct gpt_part_table *)((u8 *)ent_buf + free_idx * esz);

    memset(new_boot_e, 0, esz);
    memcpy(&new_boot_e->part_type, &boot_type_guid, sizeof(efi_guid_t));
    memcpy(&new_boot_e->part_guid, &boot_part_guid, sizeof(efi_guid_t));

    new_boot_e->part_start_lba = new_boot_start;
    new_boot_e->part_end_lba   = new_boot_end;

    memcpy(&new_boot_e->attributes, &boot_attributes, sizeof(gpt_table_attributes));
    {
        u16 tmp[PT_NAME_SZ];
        memset(tmp, 0, sizeof(tmp));
        str_to_utf16("boot", tmp, PT_NAME_SZ);
        memcpy(new_boot_e->part_name, tmp, sizeof(tmp));
    }

    memset(boot_e, 0, esz);
    memcpy(&boot_e->part_type, &boot_type_guid, sizeof(efi_guid_t));

    memcpy(boot_e->part_guid.b, not_a_guid, 16);

    boot_e->part_guid.b[6] = (boot_e->part_guid.b[6] & 0x0f) | 0x40;
    boot_e->part_guid.b[8] = (boot_e->part_guid.b[8] & 0x3f) | 0x80;

    boot_e->part_start_lba = lk3rd_start;
    boot_e->part_end_lba = lk3rd_end;

    memcpy(&boot_e->attributes, &boot_attributes, sizeof(gpt_table_attributes));
    {
        u16 tmp[PT_NAME_SZ];
        memset(tmp, 0, sizeof(tmp));
        str_to_utf16("lk3rd", tmp, PT_NAME_SZ);
        memcpy(boot_e->part_name, tmp, sizeof(tmp));
    }

    gpt_fix_crcs(hdr, (struct gpt_part_table *)ent_buf);

    if (dev->new_write_native(dev, ent_buf, elba, ent_blocks))
        goto out_free;

    if (dev->new_write_native(dev, hdr_buf, 1, 1))
        goto out_free;

    alt_lba = hdr->gpt_back_header;
    bak_ent_lba = alt_lba - ent_blocks;

    if (dev->new_write_native(dev, ent_buf, bak_ent_lba, ent_blocks))
        goto out_free;

    bak_hdr_buf = malloc(bsz);
    if (!bak_hdr_buf) goto out_free;

    memcpy(bak_hdr_buf, hdr_buf, bsz);
    struct gpt_header *bak = (struct gpt_header *)bak_hdr_buf;
    bak->gpt_header = alt_lba;
    bak->gpt_back_header = 1;
    bak->part_table_lba = bak_ent_lba;

    gpt_fix_crcs(bak, (struct gpt_part_table *)ent_buf);

    if (dev->new_write_native(dev, bak_hdr_buf, alt_lba, 1)) goto out_free;

    mbr = malloc(bsz);
    if (!mbr) goto out_free;

    if (dev->new_read_native(dev, mbr, 0, 1)) goto out_free;

    mbr[446] = 0x00;
    mbr[447] = 0x00;
    mbr[448] = 0x02;
    mbr[449] = 0x00;
    mbr[450] = 0xEE;
    mbr[451] = 0xFF;
    mbr[452] = 0xFF;
    mbr[453] = 0xFF;

    mbr[454] = 0x01;
    mbr[455] = 0x00;
    mbr[456] = 0x00;
    mbr[457] = 0x00;

    u64 disk_blks = (u64)dev->block_count;
    u32 mbr_size = (disk_blks - 1 > 0xFFFFFFFF) ? 0xFFFFFFFF : (u32)(disk_blks - 1);

    mbr[458] = (u8)(mbr_size);
    mbr[459] = (u8)(mbr_size >> 8);
    mbr[460] = (u8)(mbr_size >> 16);
    mbr[461] = (u8)(mbr_size >> 24);

    memset(mbr + 462, 0, 3 * 16);

    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    if (dev->new_write_native(dev, mbr, 0, 1))
        goto out_free;

    show_repartition_success(0);

    out_free:
    if (hdr_buf) free(hdr_buf);
    if (ent_buf) free(ent_buf);
    if (mbr) free(mbr);
    if (bak_hdr_buf) free(bak_hdr_buf);
    out_close:
    bio_close(dev);
    return ret;
}
