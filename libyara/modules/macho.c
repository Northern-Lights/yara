#include <yara/macho.h>
#include <yara/modules.h>
#include <yara/utils.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define MODULE_NAME macho

//This is our scanned data. For the header, we (should) be interested only in the 1st block.
//In the future, we may be interested in more if we want to get Obj-C class info, for example.
static uint8_t		*block = 0;
static YR_OBJECT	*module_object = 0;		//TODO: Find a better name for this

//Global pointers for headers.  Some may not exist.
static PFAT_HEADER fat_header = 0;
static PMACH_HEADER mach_header = 0;
static PMACH_HEADER_64 mach_header_64 = 0;

//TODO: Maybe this should just take a YR_OBJECT so that we don't use it in wrong places.
static bool set_constants() {
	if (!module_object) { return FALSE; }
	set_integer(FAT_MAGIC, module_object, "FAT_MAGIC");
	set_integer(FAT_CIGAM, module_object, "FAT_CIGAM");
	set_integer(MH_MAGIC, module_object, "MH_MAGIC");
	set_integer(MH_CIGAM, module_object, "MH_CIGAM");
	set_integer(MH_OBJECT, module_object, "MH_OBJECT");
	set_integer(MH_EXECUTE, module_object, "MH_EXECUTE");
	set_integer(MH_FVMLIB, module_object, "MH_FVMLIB");
	set_integer(MH_CORE, module_object, "MH_CORE");
	set_integer(MH_PRELOAD, module_object, "MH_PRELOAD");
	set_integer(MH_DYLIB, module_object, "MH_DYLIB");
	set_integer(MH_DYLINKER, module_object, "MH_DYLINKER");
	set_integer(MH_BUNDLE, module_object, "MH_BUNDLE");
	set_integer(MH_DYLIB_STUB, module_object, "MH_DYLIB_STUB");
	set_integer(MH_DSYM, module_object, "MH_DSYM");
	set_integer(MH_KEXT_BUNDLE, module_object, "MH_KEXT_BUNDLE");
	set_integer(MH_NOUNDEFS, module_object, "MH_NOUNDEFS");
	set_integer(MH_INCRLINK, module_object, "MH_INCRLINK");
	set_integer(MH_DYLDLINK, module_object, "MH_DYLDLINK");
	set_integer(MH_BINDATLOAD, module_object, "MH_BINDATLOAD");
	set_integer(MH_PREBOUND, module_object, "MH_PREBOUND");
	set_integer(MH_SPLIT_SEGS, module_object, "MH_SPLIT_SEGS");
	set_integer(MH_LAZY_INIT, module_object, "MH_LAZY_INIT");
	set_integer(MH_TWOLEVEL, module_object, "MH_TWOLEVEL");
	set_integer(MH_FORCE_FLAT, module_object, "MH_FORCE_FLAT");
	set_integer(MH_NOMULTIDEFS, module_object, "MH_NOMULTIDEFS");
	set_integer(MH_NOFIXPREBINDING, module_object, "MH_NOFIXPREBINDING");
	set_integer(MH_PREBINDABLE, module_object, "MH_PREBINDABLE");
	set_integer(MH_ALLMODSBOUND, module_object, "MH_ALLMODSBOUND");
	set_integer(MH_SUBSECTIONS_VIA_SYMBOLS, module_object, "MH_SUBSECTIONS_VIA_SYMBOLS");
	set_integer(MH_CANONICAL, module_object, "MH_CANONICAL");
	set_integer(MH_WEAK_DEFINES, module_object, "MH_WEAK_DEFINES");
	set_integer(MH_BINDS_TO_WEAK, module_object, "MH_BINDS_TO_WEAK");
	set_integer(MH_ALLOW_STACK_EXECUTION, module_object, "MH_ALLOW_STACK_EXECUTION");
	set_integer(MH_ROOT_SAFE, module_object, "MH_ROOT_SAFE");
	set_integer(MH_SETUID_SAFE, module_object, "MH_SETUID_SAFE");
	set_integer(MH_NO_REEXPORTED_DYLIBS, module_object, "MH_NO_REEXPORTED_DYLIBS");
	set_integer(MH_PIE, module_object, "MH_PIE");
	set_integer(MH_DEAD_STRIPPABLE_DYLIB, module_object, "MH_DEAD_STRIPPABLE_DYLIB");
	set_integer(MH_HAS_TLV_DESCRIPTORS, module_object, "MH_HAS_TLV_DESCRIPTORS");
	set_integer(MH_NO_HEAP_EXECUTION, module_object, "MH_NO_HEAP_EXECUTION");
	set_integer(MH_APP_EXTENSION_SAFE, module_object, "MH_APP_EXTENSION_SAFE");
	set_integer(LC_REQ_DYLD, module_object, "LC_REQ_DYLD");
	set_integer(LC_SEGMENT, module_object, "LC_SEGMENT");
	set_integer(LC_SYMTAB, module_object, "LC_SYMTAB");
	set_integer(LC_SYMSEG, module_object, "LC_SYMSEG");
	set_integer(LC_THREAD, module_object, "LC_THREAD");
	set_integer(LC_UNIXTHREAD, module_object, "LC_UNIXTHREAD");
	set_integer(LC_LOADFVMLIB, module_object, "LC_LOADFVMLIB");
	set_integer(LC_IDFVMLIB, module_object, "LC_IDFVMLIB");
	set_integer(LC_IDENT, module_object, "LC_IDENT");
	set_integer(LC_FVMFILE, module_object, "LC_FVMFILE");
	set_integer(LC_PREPAGE, module_object, "LC_PREPAGE");
	set_integer(LC_DYSYMTAB, module_object, "LC_DYSYMTAB");
	set_integer(LC_LOAD_DYLIB, module_object, "LC_LOAD_DYLIB");
	set_integer(LC_ID_DYLIB, module_object, "LC_ID_DYLIB");
	set_integer(LC_LOAD_DYLINKER, module_object, "LC_LOAD_DYLINKER");
	set_integer(LC_ID_DYLINKER, module_object, "LC_ID_DYLINKER");
	set_integer(LC_PREBOUND_DYLIB, module_object, "LC_PREBOUND_DYLIB");
	set_integer(LC_ROUTINES, module_object, "LC_ROUTINES");
	set_integer(LC_SUB_FRAMEWORK, module_object, "LC_SUB_FRAMEWORK");
	set_integer(LC_SUB_UMBRELLA, module_object, "LC_SUB_UMBRELLA");
	set_integer(LC_SUB_CLIENT, module_object, "LC_SUB_CLIENT");
	set_integer(LC_SUB_LIBRARY, module_object, "LC_SUB_LIBRARY");
	set_integer(LC_TWOLEVEL_HINTS, module_object, "LC_TWOLEVEL_HINTS");
	set_integer(LC_PREBIND_CKSUM, module_object, "LC_PREBIND_CKSUM");
	set_integer(LC_LOAD_WEAK_DYLIB, module_object, "LC_LOAD_WEAK_DYLIB");
	set_integer(LC_SEGMENT_64, module_object, "LC_SEGMENT_64");
	set_integer(LC_ROUTINES_64, module_object, "LC_ROUTINES_64");
	set_integer(LC_UUID, module_object, "LC_UUID");
	set_integer(LC_RPATH, module_object, "LC_RPATH");
	set_integer(LC_CODE_SIGNATURE, module_object, "LC_CODE_SIGNATURE");
	set_integer(LC_SEGMENT_SPLIT_INFO, module_object, "LC_SEGMENT_SPLIT_INFO");
	set_integer(LC_REEXPORT_DYLIB, module_object, "LC_REEXPORT_DYLIB");
	set_integer(LC_LAZY_LOAD_DYLIB, module_object, "LC_LAZY_LOAD_DYLIB");
	set_integer(LC_ENCRYPTION_INFO, module_object, "LC_ENCRYPTION_INFO");
	set_integer(LC_DYLD_INFO, module_object, "LC_DYLD_INFO");
	set_integer(LC_DYLD_INFO_ONLY, module_object, "LC_DYLD_INFO_ONLY");
	set_integer(LC_LOAD_UPWARD_DYLIB, module_object, "LC_LOAD_UPWARD_DYLIB");
	set_integer(LC_VERSION_MIN_MACOSX, module_object, "LC_VERSION_MIN_MACOSX");
	set_integer(LC_VERSION_MIN_IPHONEOS, module_object, "LC_VERSION_MIN_IPHONEOS");
	set_integer(LC_FUNCTION_STARTS, module_object, "LC_FUNCTION_STARTS");
	set_integer(LC_DYLD_ENVIRONMENT, module_object, "LC_DYLD_ENVIRONMENT");
	set_integer(LC_MAIN, module_object, "LC_MAIN");
	set_integer(LC_DATA_IN_CODE, module_object, "LC_DATA_IN_CODE");
	set_integer(LC_SOURCE_VERSION, module_object, "LC_SOURCE_VERSION");
	set_integer(LC_DYLIB_CODE_SIGN_DRS, module_object, "LC_DYLIB_CODE_SIGN_DRS");
	set_integer(LC_ENCRYPTION_INFO_64, module_object, "LC_ENCRYPTION_INFO_64");
	set_integer(LC_LINKER_OPTION, module_object, "LC_LINKER_OPTION");
	set_integer(LC_LINKER_OPTIMIZATION_HINT, module_object, "LC_LINKER_OPTIMIZATION_HINT");
	set_integer(SG_HIGHVM, module_object, "SG_HIGHVM");
	set_integer(SG_FVMLIB, module_object, "SG_FVMLIB");
	set_integer(SG_NORELOC, module_object, "SG_NORELOC");
	set_integer(SG_PROTECTED_VERSION_1, module_object, "SG_PROTECTED_VERSION_1");
	set_integer(SECTION_TYPE, module_object, "SECTION_TYPE");
	set_integer(S_REGULAR, module_object, "S_REGULAR");
	set_integer(S_ZEROFILL, module_object, "S_ZEROFILL");
	set_integer(S_CSTRING_LITERALS, module_object, "S_CSTRING_LITERALS");
	set_integer(S_4BYTE_LITERALS, module_object, "S_4BYTE_LITERALS");
	set_integer(S_8BYTE_LITERALS, module_object, "S_8BYTE_LITERALS");
	set_integer(S_LITERAL_POINTERS, module_object, "S_LITERAL_POINTERS");
	set_integer(S_NON_LAZY_SYMBOL_POINTERS, module_object, "S_NON_LAZY_SYMBOL_POINTERS");
	set_integer(S_LAZY_SYMBOL_POINTERS, module_object, "S_LAZY_SYMBOL_POINTERS");
	set_integer(S_SYMBOL_STUBS, module_object, "S_SYMBOL_STUBS");
	set_integer(S_MOD_INIT_FUNC_POINTERS, module_object, "S_MOD_INIT_FUNC_POINTERS");
	set_integer(S_MOD_TERM_FUNC_POINTERS, module_object, "S_MOD_TERM_FUNC_POINTERS");
	set_integer(S_COALESCED, module_object, "S_COALESCED");
	set_integer(S_GB_ZEROFILL, module_object, "S_GB_ZEROFILL");
	set_integer(S_INTERPOSING, module_object, "S_INTERPOSING");
	set_integer(S_16BYTE_LITERALS, module_object, "S_16BYTE_LITERALS");
	set_integer(S_DTRACE_DOF, module_object, "S_DTRACE_DOF");
	set_integer(S_LAZY_DYLIB_SYMBOL_POINTERS, module_object, "S_LAZY_DYLIB_SYMBOL_POINTERS");
	set_integer(S_THREAD_LOCAL_REGULAR, module_object, "S_THREAD_LOCAL_REGULAR");
	set_integer(S_THREAD_LOCAL_ZEROFILL, module_object, "S_THREAD_LOCAL_ZEROFILL");
	set_integer(S_THREAD_LOCAL_VARIABLES, module_object, "S_THREAD_LOCAL_VARIABLES");
	set_integer(S_THREAD_LOCAL_VARIABLE_POINTERS, module_object, "S_THREAD_LOCAL_VARIABLE_POINTERS");
	set_integer(S_THREAD_LOCAL_INIT_FUNCTION_POINTERS, module_object, "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS");
	set_integer(SECTION_ATTRIBUTES, module_object, "SECTION_ATTRIBUTES");
	set_integer(SECTION_ATTRIBUTES_USR, module_object, "SECTION_ATTRIBUTES_USR");
	set_integer(S_ATTR_PURE_INSTRUCTIONS, module_object, "S_ATTR_PURE_INSTRUCTIONS");
	set_integer(S_ATTR_NO_TOC, module_object, "S_ATTR_NO_TOC");
	set_integer(S_ATTR_STRIP_STATIC_SYMS, module_object, "S_ATTR_STRIP_STATIC_SYMS");
	set_integer(S_ATTR_NO_DEAD_STRIP, module_object, "S_ATTR_NO_DEAD_STRIP");
	set_integer(S_ATTR_LIVE_SUPPORT, module_object, "S_ATTR_LIVE_SUPPORT");
	set_integer(S_ATTR_SELF_MODIFYING_CODE, module_object, "S_ATTR_SELF_MODIFYING_CODE");
	set_integer(S_ATTR_DEBUG, module_object, "S_ATTR_DEBUG");
	set_integer(SECTION_ATTRIBUTES_SYS, module_object, "SECTION_ATTRIBUTES_SYS");
	set_integer(S_ATTR_SOME_INSTRUCTIONS, module_object, "S_ATTR_SOME_INSTRUCTIONS");
	set_integer(S_ATTR_EXT_RELOC, module_object, "S_ATTR_EXT_RELOC");
	set_integer(S_ATTR_LOC_RELOC, module_object, "S_ATTR_LOC_RELOC");
	set_string(SEG_PAGEZERO, module_object, "SEG_PAGEZERO");
	set_string(SEG_TEXT, module_object, "SEG_TEXT");
	set_string(SECT_TEXT, module_object, "SECT_TEXT");
	set_string(SECT_FVMLIB_INIT0, module_object, "SECT_FVMLIB_INIT0");
	set_string(SECT_FVMLIB_INIT1, module_object, "SECT_FVMLIB_INIT1");
	set_string(SEG_DATA, module_object, "SEG_DATA");
	set_string(SECT_DATA, module_object, "SECT_DATA");
	set_string(SECT_BSS, module_object, "SECT_BSS");
	set_string(SECT_COMMON, module_object, "SECT_COMMON");
	set_string(SEG_OBJC, module_object, "SEG_OBJC");
	set_string(SECT_OBJC_SYMBOLS, module_object, "SECT_OBJC_SYMBOLS");
	set_string(SECT_OBJC_MODULES, module_object, "SECT_OBJC_MODULES");
	set_string(SECT_OBJC_STRINGS, module_object, "SECT_OBJC_STRINGS");
	set_string(SECT_OBJC_REFS, module_object, "SECT_OBJC_REFS");
	set_string(SEG_ICON, module_object, "SEG_ICON");
	set_string(SECT_ICON_HEADER, module_object, "SECT_ICON_HEADER");
	set_string(SECT_ICON_TIFF, module_object, "SECT_ICON_TIFF");
	set_string(SEG_LINKEDIT, module_object, "SEG_LINKEDIT");
	set_string(SEG_UNIXSTACK, module_object, "SEG_UNIXSTACK");
	set_string(SEG_IMPORT, module_object, "SEG_IMPORT");
	return TRUE;
}

//Offset for fat_header for a file should always be 0.
//May be different if/when we start doing live memory scans.
static bool get_fat_header(uint64_t offset) {
	uint32_t magic = *((uint32_t *) (block + offset));
	if (magic != FAT_MAGIC && magic != FAT_CIGAM) {
		return FALSE;
	}

	set_integer(TRUE, module_object, "is_fat");

	fat_header = (PFAT_HEADER) block;
	if (magic == FAT_CIGAM) {
		fat_header->nfat_arch = swap_endianness_32(fat_header->nfat_arch);
	}
	set_integer(magic, module_object, "fh.magic");
	set_integer(fat_header->nfat_arch, module_object, "fh.nfat_arch");

	//Get the fat_arch structs
	for (int i = 0; i < fat_header->nfat_arch; i++) {
		PFAT_ARCH fat_arch = (PFAT_ARCH) (block + sizeof(FAT_HEADER) + (i * sizeof(FAT_ARCH)));
		if (magic == FAT_CIGAM) {
			fat_arch->cputype = swap_endianness_32(fat_arch->cputype);
			fat_arch->cpusubtype = swap_endianness_32(fat_arch->cpusubtype);
			fat_arch->offset = swap_endianness_32(fat_arch->offset);
			fat_arch->size = swap_endianness_32(fat_arch->size);
			fat_arch->align = swap_endianness_32(fat_arch->align);
		}
		set_integer(fat_arch->cputype,
					module_object, "fat_arch[%i].cputype", i);
		set_integer(fat_arch->cpusubtype,
					module_object, "fat_arch[%i].cpusubtype", i);
		set_integer(fat_arch->offset,
					module_object, "fat_arch[%i].offset", i);	//We will need this for mach_headers
		set_integer(fat_arch->size,
					module_object, "fat_arch[%i].size", i);

		//TODO: align is really 2^fat_arch->align. Not sure if we should
		//have a separate variable for the evaluated version...
		uint64_t align = 1;
		for (int j = 0; j < fat_arch->align; j++) {
			align *= 2;
		}
		set_integer(align,
					module_object, "fat_arch[%i].align", i);
	}

	//Get the mach_headers
	for (int i = 0; i < fat_header->nfat_arch; i++) {
		bool result;
		//TODO: Identifier name collisions? It's inside a for{} block...
		uint64_t offset = get_integer(module_object, "fat_arch[%i].offset", i);
		uint32_t magic = *((uint32_t *) (block + offset));

		if (magic == MH_MAGIC || magic == MH_CIGAM ||
				magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
		{
			result = get_mach_header(offset);

			//If we get a malformed mach header, return FALSE.
			if (result == FALSE) {
				return result;
			}
		}
	}

	return TRUE;
}

static bool get_mach_header(uint64_t offset) {

	mach_header = (PMACH_HEADER) (block + offset);
	char *mh_name;
	bool is_64_bit;
	PLOAD_COMMAND pLoad_command;

	switch (mach_header->magic) {
	case MH_MAGIC:
		set_integer(TRUE, module_object, "is_macho");
		mh_name = "mh";
		is_64_bit = FALSE;
		break;
	case MH_MAGIC_64:
		set_integer(TRUE, module_object, "is_macho_64");
		mh_name = "mh64";
		is_64_bit = TRUE;
		mach_header_64 = (PMACH_HEADER_64) mach_header;
		break;
	default:
		return FALSE;
	}

	//Use the same mach_header for both 32- and 64-bit since the sizes are the
	//same, except mach_header_64 structs have a "reserved" field at the end.
	char identifier[256];
	snprintf(identifier, sizeof(identifier), "%s.magic", mh_name);
	set_integer(mach_header->magic, module_object, identifier);
	snprintf(identifier, sizeof(identifier), "%s.cputype", mh_name);
	set_integer(mach_header->cputype, module_object, identifier);
	snprintf(identifier, sizeof(identifier), "%s.cpusubtype", mh_name);
	set_integer(mach_header->cpusubtype, module_object, identifier);
	snprintf(identifier, sizeof(identifier), "%s.filetype", mh_name);
	set_integer(mach_header->filetype, module_object, identifier);
	snprintf(identifier, sizeof(identifier), "%s.ncmds", mh_name);
	set_integer(mach_header->ncmds, module_object, identifier);
	snprintf(identifier, sizeof(identifier), "%s.sizeofcmds", mh_name);
	set_integer(mach_header->sizeofcmds, module_object, identifier);
	snprintf(identifier, sizeof(identifier), "%s.flags", mh_name);
	set_integer(mach_header->flags, module_object, identifier);

	//Compensate for 64-bit: extra field + advance its header size.
	if (mach_header->magic == MH_MAGIC_64) {
		snprintf(identifier, sizeof(identifier), "%s.reserved", mh_name);
		set_integer(mach_header_64->reserved, module_object, identifier);

		pLoad_command = (PLOAD_COMMAND) (mach_header_64 + 1);
	} else {
		pLoad_command = (PLOAD_COMMAND) (mach_header + 1);
	}

	for (int i = 0; i < mach_header->ncmds; i++) {
		//Fill in specific load commands
		switch (pLoad_command->cmd) {
		case LC_SEGMENT_64:
		case LC_SEGMENT:
			fill_segment_dict(pLoad_command); break;
		case LC_LOAD_DYLIB:
			fill_load_dylib_dict(pLoad_command, is_64_bit); break;
		default:
			break;
		}

		//Fill the general load command array
		set_integer(pLoad_command->cmd, module_object,
					"mh.lc[%i].cmd", i);
		set_integer(pLoad_command->cmdsize, module_object,
					"mh.lc[%i].cmdsize", i);

		uint8_t *pNext_load_command = (uint8_t *) pLoad_command;
		pNext_load_command += pLoad_command->cmdsize;
		pLoad_command = (PLOAD_COMMAND) pNext_load_command;
	}

	return TRUE;
}

static bool fill_segment_dict(PLOAD_COMMAND p) {
	PSEGMENT seg = (PSEGMENT) p;
	char *mh_name;

	switch (seg->cmd) {
	case LC_SEGMENT_64:
		mh_name = "mh64";
		break;
	case LC_SEGMENT:
		mh_name = "mh";
		break;
	default:
		return FALSE;
	}

	//Because the field is char[16], and some names are 16 chars w/o '\0'
	char segname[NAME_SIZE + 1];
	segname[NAME_SIZE] = '\0';
	memcpy(segname, seg->_32.segname, NAME_SIZE);

	//TODO: We should have a check here that there is no duplicate segment name
	char identifier[256];
	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].cmd",
		mh_name, segname);
	set_integer(seg->cmd, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].cmdsize",
		mh_name, segname);
	set_integer(seg->_32.cmdsize, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].segname",
		mh_name, segname);
	set_string(segname, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].vmaddr",
		mh_name, segname);
	set_integer(seg->cmd == LC_SEGMENT_64 ?
		seg->_64.vmaddr : seg->_32.vmaddr, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].fileoff",
		mh_name, segname);
	set_integer(seg->cmd == LC_SEGMENT_64 ?
		seg->_64.fileoff : seg->_32.fileoff, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].filesize",
		mh_name, segname);
	set_integer(seg->cmd == LC_SEGMENT_64 ?
		seg->_64.filesize : seg->_32.filesize, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].maxprot",
		mh_name, segname);
	set_integer(seg->cmd == LC_SEGMENT_64 ?
		seg->_64.maxprot : seg->_32.maxprot, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].initprot",
		mh_name, segname);
	set_integer(seg->cmd == LC_SEGMENT_64 ?
		seg->_64.initprot : seg->_32.initprot, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].nsects",
		mh_name, segname);
	set_integer(seg->cmd == LC_SEGMENT_64 ?
		seg->_64.nsects : seg->_32.nsects, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].flags",
		mh_name, segname);
	set_integer(seg->cmd == LC_SEGMENT_64 ?
		seg->_64.flags : seg->_32.flags, module_object, identifier);

	//Get the sections. Account for size of 32- or 64-bit section.
	PSECTION section;
	if (seg->cmd == LC_SEGMENT_64) {
		section = (PSECTION) (seg + 1);
	} else {
		section = (PSECTION) (((void *) seg) + sizeof(seg->_32));
	}

	uint32_t nsects = (seg->cmd == LC_SEGMENT_64) ? seg->_64.nsects : seg->_32.nsects;
	for (int i = 0; i < nsects; i++) {

		//Because the field is char[16], and some names are 16 chars w/o '\0'
		char sectname[NAME_SIZE + 1];
		sectname[NAME_SIZE] = '\0';
		memcpy(sectname, section->sectname, NAME_SIZE);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].sectname",
			mh_name, segname, sectname);
		set_string(sectname, module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].segname",
			mh_name, segname, sectname);
		set_string(section->_32.segname, module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].addr",
			mh_name, segname, sectname);
		set_integer(seg->cmd == LC_SEGMENT_64 ?
			section->_64.addr : section->_32.addr,
			module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].size",
			mh_name, segname, section->sectname);
		set_integer(seg->cmd == LC_SEGMENT_64 ?
			section->_64.size : section->_32.size,
			module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].offset",
			mh_name, segname, sectname);
		set_integer(seg->cmd == LC_SEGMENT_64 ?
			section->_64.offset : section->_32.offset,
			module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].align",
			mh_name, segname, sectname);
		set_integer(seg->cmd == LC_SEGMENT_64 ?
			section->_64.align : section->_32.align,
			module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].reloff",
			mh_name, segname, sectname);
		set_integer(seg->cmd == LC_SEGMENT_64 ?
			section->_64.reloff : section->_32.reloff,
			module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].nreloc",
			mh_name, segname, sectname);
		set_integer(seg->cmd == LC_SEGMENT_64 ?
			section->_64.nreloc : section->_32.nreloc,
			module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].flags",
			mh_name, segname, sectname);
		set_integer(seg->cmd == LC_SEGMENT_64 ?
			section->_64.flags : section->_32.flags,
			module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].reserved1",
			mh_name, segname, sectname);
		set_integer(seg->cmd == LC_SEGMENT_64 ?
			section->_64.reserved1 : section->_32.reserved1,
			module_object, identifier);

		snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].reserved2",
			mh_name, segname, sectname);
		set_integer(seg->cmd == LC_SEGMENT_64 ?
			section->_64.reserved2 : section->_32.reserved2,
			module_object, identifier);

		// //Set the extra field in the 64-bit section, and also increment section struct
		if (seg->cmd == LC_SEGMENT_64) {
			snprintf(identifier, sizeof(identifier), "%s.seg[\"%s\"].sec[\"%s\"].reserved3",
				mh_name, segname, sectname);
			set_integer(section->_64.reserved3, module_object, identifier);
			section++;
		} else {
			//Otherwise, just increment
			section = (PSECTION) (((void *) section) + sizeof(section->_32));
		}
	}

	return TRUE;
}

static bool fill_load_dylib_dict(PLOAD_COMMAND p, bool is_64_bit) {

	char *mh_name;
	if (is_64_bit)
		mh_name = "mh64";
	else
		mh_name = "mh";

	PDYLIB_COMMAND dylib_cmd	= (PDYLIB_COMMAND) p;
	PDYLIB dylib							= &dylib_cmd->dylib;

	//Path to dylib is stored after the load command
	char *path = (char *) dylib_cmd + dylib->name;
	char *basename = strrchr(path, (int) '/') + 1;

	//TODO: Also put the full path in the hash to check for collisions?
	//Fill in the dylib_command and dylib structures.
	char identifier[256];

	snprintf(identifier, sizeof(identifier), "%s.dylib[\"%s\"].cmd",
		mh_name, basename);
	set_integer(dylib_cmd->cmd, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.dylib[\"%s\"].cmdsize",
		mh_name, basename);
	set_integer(dylib_cmd->cmdsize, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.dylib[\"%s\"].name",
		mh_name, basename);
	set_string(basename, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.dylib[\"%s\"].timestamp",
		mh_name, basename);
	set_integer(dylib->timestamp, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.dylib[\"%s\"].current_version",
		mh_name, basename);
	set_integer(dylib->current_version, module_object, identifier);

	snprintf(identifier, sizeof(identifier), "%s.dylib[\"%s\"].compatibility_version",
		mh_name, basename);
	set_integer(dylib->compatibility_version, module_object, identifier);

	return TRUE;
}

begin_declarations;

//Constants
{
declare_integer("FAT_MAGIC");
declare_integer("FAT_CIGAM");
declare_integer("MH_MAGIC");
declare_integer("MH_CIGAM");
declare_integer("MH_OBJECT");
declare_integer("MH_EXECUTE");
declare_integer("MH_FVMLIB");
declare_integer("MH_CORE");
declare_integer("MH_PRELOAD");
declare_integer("MH_DYLIB");
declare_integer("MH_DYLINKER");
declare_integer("MH_BUNDLE");
declare_integer("MH_DYLIB_STUB");
declare_integer("MH_DSYM");
declare_integer("MH_KEXT_BUNDLE");
declare_integer("MH_NOUNDEFS");
declare_integer("MH_INCRLINK");
declare_integer("MH_DYLDLINK");
declare_integer("MH_BINDATLOAD");
declare_integer("MH_PREBOUND");
declare_integer("MH_SPLIT_SEGS");
declare_integer("MH_LAZY_INIT");
declare_integer("MH_TWOLEVEL");
declare_integer("MH_FORCE_FLAT");
declare_integer("MH_NOMULTIDEFS");
declare_integer("MH_NOFIXPREBINDING");
declare_integer("MH_PREBINDABLE");
declare_integer("MH_ALLMODSBOUND");
declare_integer("MH_SUBSECTIONS_VIA_SYMBOLS");
declare_integer("MH_CANONICAL");
declare_integer("MH_WEAK_DEFINES");
declare_integer("MH_BINDS_TO_WEAK");
declare_integer("MH_ALLOW_STACK_EXECUTION");
declare_integer("MH_ROOT_SAFE");
declare_integer("MH_SETUID_SAFE");
declare_integer("MH_NO_REEXPORTED_DYLIBS");
declare_integer("MH_PIE");
declare_integer("MH_DEAD_STRIPPABLE_DYLIB");
declare_integer("MH_HAS_TLV_DESCRIPTORS");
declare_integer("MH_NO_HEAP_EXECUTION");
declare_integer("MH_APP_EXTENSION_SAFE");
declare_integer("LC_REQ_DYLD");
declare_integer("LC_SEGMENT");
declare_integer("LC_SYMTAB");
declare_integer("LC_SYMSEG");
declare_integer("LC_THREAD");
declare_integer("LC_UNIXTHREAD");
declare_integer("LC_LOADFVMLIB");
declare_integer("LC_IDFVMLIB");
declare_integer("LC_IDENT");
declare_integer("LC_FVMFILE");
declare_integer("LC_PREPAGE");
declare_integer("LC_DYSYMTAB");
declare_integer("LC_LOAD_DYLIB");
declare_integer("LC_ID_DYLIB");
declare_integer("LC_LOAD_DYLINKER");
declare_integer("LC_ID_DYLINKER");
declare_integer("LC_PREBOUND_DYLIB");
declare_integer("LC_ROUTINES");
declare_integer("LC_SUB_FRAMEWORK");
declare_integer("LC_SUB_UMBRELLA");
declare_integer("LC_SUB_CLIENT");
declare_integer("LC_SUB_LIBRARY");
declare_integer("LC_TWOLEVEL_HINTS");
declare_integer("LC_PREBIND_CKSUM");
declare_integer("LC_LOAD_WEAK_DYLIB");
declare_integer("LC_SEGMENT_64");
declare_integer("LC_ROUTINES_64");
declare_integer("LC_UUID");
declare_integer("LC_RPATH");
declare_integer("LC_CODE_SIGNATURE");
declare_integer("LC_SEGMENT_SPLIT_INFO");
declare_integer("LC_REEXPORT_DYLIB");
declare_integer("LC_LAZY_LOAD_DYLIB");
declare_integer("LC_ENCRYPTION_INFO");
declare_integer("LC_DYLD_INFO");
declare_integer("LC_DYLD_INFO_ONLY");
declare_integer("LC_LOAD_UPWARD_DYLIB");
declare_integer("LC_VERSION_MIN_MACOSX");
declare_integer("LC_VERSION_MIN_IPHONEOS");
declare_integer("LC_FUNCTION_STARTS");
declare_integer("LC_DYLD_ENVIRONMENT");
declare_integer("LC_MAIN");
declare_integer("LC_DATA_IN_CODE");
declare_integer("LC_SOURCE_VERSION");
declare_integer("LC_DYLIB_CODE_SIGN_DRS");
declare_integer("LC_ENCRYPTION_INFO_64");
declare_integer("LC_LINKER_OPTION");
declare_integer("LC_LINKER_OPTIMIZATION_HINT");
declare_integer("SG_HIGHVM");
declare_integer("SG_FVMLIB");
declare_integer("SG_NORELOC");
declare_integer("SG_PROTECTED_VERSION_1");
declare_integer("SECTION_TYPE");
declare_integer("S_REGULAR");
declare_integer("S_ZEROFILL");
declare_integer("S_CSTRING_LITERALS");
declare_integer("S_4BYTE_LITERALS");
declare_integer("S_8BYTE_LITERALS");
declare_integer("S_LITERAL_POINTERS");
declare_integer("S_NON_LAZY_SYMBOL_POINTERS");
declare_integer("S_LAZY_SYMBOL_POINTERS");
declare_integer("S_SYMBOL_STUBS");
declare_integer("S_MOD_INIT_FUNC_POINTERS");
declare_integer("S_MOD_TERM_FUNC_POINTERS");
declare_integer("S_COALESCED");
declare_integer("S_GB_ZEROFILL");
declare_integer("S_INTERPOSING");
declare_integer("S_16BYTE_LITERALS");
declare_integer("S_DTRACE_DOF");
declare_integer("S_LAZY_DYLIB_SYMBOL_POINTERS");
declare_integer("S_THREAD_LOCAL_REGULAR");
declare_integer("S_THREAD_LOCAL_ZEROFILL");
declare_integer("S_THREAD_LOCAL_VARIABLES");
declare_integer("S_THREAD_LOCAL_VARIABLE_POINTERS");
declare_integer("S_THREAD_LOCAL_INIT_FUNCTION_POINTERS");
declare_integer("SECTION_ATTRIBUTES");
declare_integer("SECTION_ATTRIBUTES_USR");
declare_integer("S_ATTR_PURE_INSTRUCTIONS");
declare_integer("S_ATTR_NO_TOC");
declare_integer("S_ATTR_STRIP_STATIC_SYMS");
declare_integer("S_ATTR_NO_DEAD_STRIP");
declare_integer("S_ATTR_LIVE_SUPPORT");
declare_integer("S_ATTR_SELF_MODIFYING_CODE");
declare_integer("S_ATTR_DEBUG");
declare_integer("SECTION_ATTRIBUTES_SYS");
declare_integer("S_ATTR_SOME_INSTRUCTIONS");
declare_integer("S_ATTR_EXT_RELOC");
declare_integer("S_ATTR_LOC_RELOC");
declare_string("SEG_PAGEZERO");
declare_string("SEG_TEXT");
declare_string("SECT_TEXT");
declare_string("SECT_FVMLIB_INIT0");
declare_string("SECT_FVMLIB_INIT1");
declare_string("SEG_DATA");
declare_string("SECT_DATA");
declare_string("SECT_BSS");
declare_string("SECT_COMMON");
declare_string("SEG_OBJC");
declare_string("SECT_OBJC_SYMBOLS");
declare_string("SECT_OBJC_MODULES");
declare_string("SECT_OBJC_STRINGS");
declare_string("SECT_OBJC_REFS");
declare_string("SEG_ICON");
declare_string("SECT_ICON_HEADER");
declare_string("SECT_ICON_TIFF");
declare_string("SEG_LINKEDIT");
declare_string("SEG_UNIXSTACK");
declare_string("SEG_IMPORT");
}

//TODO: Constants for CPUTYPE and such would be great.

//Structs for headers and info about the binary
{
declare_integer("is_fat");
begin_struct("fh");
	declare_integer("magic");
	declare_integer("nfat_arch");
end_struct("fh");

begin_struct_array("fat_arch");
	declare_integer("cputype");
	declare_integer("cpusubtype");
	declare_integer("offset");
	declare_integer("size");
	declare_integer("align");
end_struct_array("fat_arch");

declare_integer("is_macho");
begin_struct("mh");
	declare_integer("magic");
	declare_integer("cputype");
	declare_integer("cpusubtype");
	declare_integer("filetype");
	declare_integer("ncmds");
	declare_integer("sizeofcmds");
	declare_integer("flags");
	begin_struct_array("lc");
		declare_integer("cmd");
		declare_integer("cmdsize");
	end_struct_array("lc");
	begin_struct_dictionary("seg");
		declare_integer("cmd");
		declare_integer("cmdsize");
		declare_string("segname");
		declare_integer("vmaddr");
		declare_integer("vmsize");
		declare_integer("fileoff");
		declare_integer("filesize");
		declare_integer("maxprot");
		declare_integer("initprot");
		declare_integer("nsects");
		declare_integer("flags");
		begin_struct_dictionary("sec");
			declare_string("sectname");
			declare_string("segname");
			declare_integer("addr");
			declare_integer("size");
			declare_integer("offset");
			declare_integer("align");
			declare_integer("reloff");
			declare_integer("nreloc");
			declare_integer("flags");
			declare_integer("reserved1");
			declare_integer("reserved2");
		end_struct_dictionary("sec");
	end_struct_dictionary("seg");
	begin_struct_dictionary("dylib");
		declare_integer("cmd");
		declare_integer("cmdsize");
		declare_string("name");
		declare_integer("timestamp");	//TODO: function to convert this to human-readable?
		declare_integer("current_version");		//TODO: And this
		declare_integer("compatibility_version");	//TODO: And this
	end_struct_dictionary("dylib");
end_struct("mh");

declare_integer("is_macho_64");
begin_struct("mh64");
	declare_integer("magic");
	declare_integer("cputype");
	declare_integer("cpusubtype");
	declare_integer("filetype");
	declare_integer("ncmds");
	declare_integer("sizeofcmds");
	declare_integer("flags");
	declare_integer("reserved");
	begin_struct_array("lc");
		declare_integer("cmd");
		declare_integer("cmdsize");
	end_struct_array("lc");
	begin_struct_dictionary("seg");
		declare_integer("cmd");
		declare_integer("cmdsize");
		declare_string("segname");
		declare_integer("vmaddr");
		declare_integer("vmsize");
		declare_integer("fileoff");
		declare_integer("filesize");
		declare_integer("maxprot");
		declare_integer("initprot");
		declare_integer("nsects");
		declare_integer("flags");
		begin_struct_dictionary("sec");
			declare_string("sectname");
			declare_string("segname");
			declare_integer("addr");
			declare_integer("size");
			declare_integer("offset");
			declare_integer("align");
			declare_integer("reloff");
			declare_integer("nreloc");
			declare_integer("flags");
			declare_integer("reserved1");
			declare_integer("reserved2");
			declare_integer("reserved3");
		end_struct_dictionary("sec");
	end_struct_dictionary("seg");
	begin_struct_dictionary("dylib");
		declare_integer("cmd");
		declare_integer("cmdsize");
		declare_string("name");
		declare_integer("timestamp");	//TODO: function to convert this to human-readable?
		declare_integer("current_version");		//TODO: And this
		declare_integer("compatibility_version");	//TODO: And this
	end_struct_dictionary("dylib");
end_struct("mh64");

begin_struct("fvmlib_command");
	declare_integer("cmd");
	declare_integer("cmdsize");
	begin_struct("fvmlib");
		declare_integer("name");	//TODO: Offset to the name; follows this struct.  Maybe just make the string part of this struct
		declare_integer("minor_version");
		declare_integer("header_addr");
	end_struct("fvmlib");
end_struct("fvmlib_command");
}

end_declarations;

/*
 * Yara Module functions
 */

int module_initialize(YR_MODULE* module) {
	return ERROR_SUCCESS;
}


int module_finalize(YR_MODULE* module) {
	return ERROR_SUCCESS;
}


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_obj,
    void* module_data,
    size_t module_data_size)
{
	//Make module_obj global
	module_object = module_obj;
	//Set helpful constants, like FAT_MAGIC, MACH_CIGAM, etc.
	if (!set_constants()) { return !ERROR_SUCCESS; }

	//Assume our headers fit in the first block
	YR_MEMORY_BLOCK *blk = first_memory_block(context);

	//Only files; no live memory scans for this iteration
	if (blk->base != 0) { return ERROR_COULD_NOT_ATTACH_TO_PROCESS; }

	//The block of data from the yara context is immutable. Copy it
	block = (uint8_t *) malloc(blk->size);
	if (!block) { return ERROR_INSUFICIENT_MEMORY; }	//Yes, the library constant has a type-o...
	memcpy(block, blk->data, blk->size);

	//Begin gathering our information.
	if (get_fat_header(0)) {		//Takes care of get_mach_header functions
		return ERROR_SUCCESS;
	}

	//If not fat, then start with mach.
	if (!get_mach_header(0)) {
		return !ERROR_SUCCESS;
	}

	//TODO: Any difference for PPC?

	return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object) {
	if(block) { free(block); }
	return ERROR_SUCCESS;
}
