# Rules for generating the final binary and any auxillary files generated as a result.

# use linker garbage collection, if requested
WITH_LINKER_GC ?= false
ifeq (true,$(call TOBOOL,$(WITH_LINKER_GC)))
GLOBAL_COMPILEFLAGS += -ffunction-sections -fdata-sections
GLOBAL_LDFLAGS += --gc-sections
GLOBAL_DEFINES += LINKER_GC=1
endif

ifneq (,$(EXTRA_BUILDRULES))
-include $(EXTRA_BUILDRULES)
endif

$(EXTRA_LINKER_SCRIPTS):

$(ANDROID_BOOT_IMAGE): $(OUTBIN_LK3RD)
	@echo lk3rd: creating an android boot image for $(PROJECT)
	mkbootimg --kernel $(OUTBIN_LK3RD) --ramdisk ./Resources/dummyramdisk $(MKBOOTIMG_ARGS) -o $@.tmp
	@echo lk3rd: Padding image...
	@pad_size=$$((2097152 - $$(stat -c "%s" $@.tmp))) && \
		fallocate -l $$pad_size $@.pad
	cat $@.tmp $@.pad > $@
	rm $@.tmp $@.pad
	@echo lk3rd: Writing default KASLR and Mainline Quirks settings...
	printf '\x01\x00\x00\x00\x01\x00\x00\x00' | dd of=$@ bs=1 seek=$$((0x175000)) conv=notrunc
	@echo lk3rd: all done! Image is at $@

$(OUTBIN_LK3RD) : $(OUTBIN)
	@echo lk3rd: building final image base: $(MEMBASE): $@
	rm lib/lk3rd/boot/bootshim.bin lib/lk3rd/boot/bootshim.elf -fv
	cd lib/lk3rd/boot/ && CREATE_FDT_POINTER=$(CREATE_FDT_POINTER) FDT_POINTER_ADDRESS=$(FDT_POINTER_ADDRESS) LK3RD_BASE=$(MEMBASE) LK3RD_SIZE=0x200000 make
	cat lib/lk3rd/boot/bootshim.bin $(OUTBIN) > $@
	@echo lk3rd: all done! image can be found at $@

$(OUTBIN): $(OUTELF)
	$(info generating image: $@)
	$(NOECHO)$(SIZE) $<
	$(NOECHO)$(OBJCOPY) -O binary $< $@

$(OUTELF).hex: $(OUTELF)
	$(info generating hex file: $@)
	$(NOECHO)$(OBJCOPY) -O ihex $< $@

$(OUTELF): $(ALLMODULE_OBJS) $(EXTRA_OBJS) $(LINKER_SCRIPT) $(EXTRA_LINKER_SCRIPTS)
	$(info linking $@)
	$(NOECHO)$(SIZE) -t --common $(sort $(ALLMODULE_OBJS)) $(EXTRA_OBJS)
	$(NOECHO)$(LD) $(GLOBAL_LDFLAGS) $(ARCH_LDFLAGS) -dT $(LINKER_SCRIPT) \
		$(addprefix -T,$(EXTRA_LINKER_SCRIPTS)) \
		$(ALLMODULE_OBJS) $(EXTRA_OBJS) $(LIBGCC) -Map=$(OUTELF).map -o $@

$(OUTELF).sym: $(OUTELF)
	$(info generating symbols: $@)
	$(NOECHO)$(OBJDUMP) -t $< | $(CPPFILT) > $@
	$(NOECHO)echo "# vim: ts=8 nolist nowrap" >> $@

$(OUTELF).sym.sorted: $(OUTELF)
	$(info generating sorted symbols: $@)
	$(NOECHO)$(OBJDUMP) -t $< | $(CPPFILT) | sort > $@
	$(NOECHO)echo "# vim: ts=8 nolist nowrap" >> $@

$(OUTELF).lst: $(OUTELF)
	$(info generating listing: $@)
	$(NOECHO)$(OBJDUMP) $(ARCH_OBJDUMP_FLAGS) -d $< | $(CPPFILT) > $@
	$(NOECHO)echo "# vim: ts=8 nolist nowrap" >> $@

$(OUTELF).debug.lst: $(OUTELF)
	$(info generating listing: $@)
	$(NOECHO)$(OBJDUMP) $(ARCH_OBJDUMP_FLAGS) -S $< | $(CPPFILT) > $@
	$(NOECHO)echo "# vim: ts=8 nolist nowrap" >> $@

$(OUTELF).dump: $(OUTELF)
	$(info generating objdump: $@)
	$(NOECHO)$(OBJDUMP) -x $< | $(CPPFILT) > $@
	$(NOECHO)echo "# vim: ts=8 nolist nowrap" >> $@

$(OUTELF).size: $(OUTELF)
	$(info generating size map: $@)
	$(NOECHO)$(NM) -S --size-sort $< | $(CPPFILT) > $@
	$(NOECHO)echo "# vim: ts=8 nolist nowrap" >> $@

# generate a list of source files that potentially participate in this build.
# header file detection is a bit sloppy: it simply searches for every .h file inside
# the combined include paths. May pick up files that are not strictly speaking used.
# Alternate strategy that may work: union all of the .d files together and collect all
# of the used headers used there.
$(BUILDDIR)/srcfiles.txt: $(OUTELF) $(BUILDDIR)/include_paths.txt
	@$(MKDIR)
	$(info generating $@)
	$(NOECHO)echo $(sort $(ALLSRCS)) | tr ' ' '\n' > $@
	@for i in `cat $(BUILDDIR)/include_paths.txt`; do if [ -d $$i ]; then find $$i -type f -name \*.h; fi; done >> $@

# generate a list of all the include directories used in this project
$(BUILDDIR)/include_paths.txt: $(OUTELF)
	@$(MKDIR)
	$(info generating $@)
	$(NOECHO)echo $(subst -I,,$(sort $(GLOBAL_INCLUDES))) | tr ' ' '\n' > $@

#include arch/$(ARCH)/compile.mk

