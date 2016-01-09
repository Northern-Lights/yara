#include <yara/modules.h>
#include <yara/macho.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define MODULE_NAME macho

//#include <libkern/OSByteOrder.h>
//#include <mach-o/loader.h>
//#include <mach-o/fat.h>

//typedef struct fat_header fat_header;
//typedef struct fat_arch fat_arch;
//typedef struct mach_header mach_header;
//typedef struct mach_header_64 mach_header_64;

//This is our scanned data. For the header, we (should) be interested only in the 1st block.
//In the future, we may be interested in more if we want to get Obj-C class info, for example.
uint8_t		*block = 0;
YR_OBJECT	*module_object = 0;		//TODO: Find a better name for this

//Global pointers for headers.  Some may not exist.
PFAT_HEADER fat_header = 0;
PMACH_HEADER mach_header = 0;
PMACH_HEADER_64 mach_header_64 = 0;

//TODO: Maybe this should just take a YR_OBJECT so that we don't use it in wrong places.
bool set_constants() {
	if (!module_object) { return false; }
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
	return true;
}

//Offset for fat_header for a file should always be 0.
//May be different if/when we start doing live memory scans.
bool get_fat_header(uint64_t offset) {
	uint32_t magic = *((uint32_t *) (block + offset));
	if (magic != FAT_MAGIC && magic != FAT_CIGAM) {
		return false;
	}

	set_integer(true, module_object, "is_fat");

	fat_header = (PFAT_HEADER) block;
	if (magic == FAT_CIGAM) {
		fat_header->nfat_arch = swap_endianness_32(fat_header->nfat_arch);
	}
	set_integer(magic, module_object, "fat_header.magic");
	set_integer(fat_header->nfat_arch, module_object, "fat_header.nfat_arch");

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
		//TODO: Identifier name collisions? It's inside a for{} block...
		uint64_t offset = get_integer(module_object, "fat_arch[%i].offset", i);
		uint32_t magic = *((uint32_t *) (block + offset));

		if (magic == MH_MAGIC || magic == MH_CIGAM) {
			get_mach_header(offset);
		}
		else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
			get_mach_header_64(offset);
		}
	}

	return true;
}

bool get_mach_header(uint64_t offset) {
	uint32_t magic = *((uint32_t *) (block + offset));
	if (magic != MH_MAGIC && magic != MH_MAGIC_64) {
		return false;
	}

	set_integer(true, module_object, "is_macho");

	mach_header = (PMACH_HEADER) (block + offset);
	if (magic == MH_CIGAM) {
		//TODO: We probably need to swap everything
	}

	set_integer(mach_header->magic, module_object, "mach_header.magic");
	set_integer(mach_header->cputype, module_object, "mach_header.cputype");
	set_integer(mach_header->cpusubtype, module_object, "mach_header.cpusubtype");
	set_integer(mach_header->filetype, module_object, "mach_header.filetype");
	set_integer(mach_header->ncmds, module_object, "mach_header.ncmds");
	set_integer(mach_header->sizeofcmds, module_object, "mach_header.sizeofcmds");
	set_integer(mach_header->flags, module_object, "mach_header.flags");

	//TODO: we should probably do all the load commands and
	//seg/sections here since there will be the same items
	//for multiple architectures; we don't want those
	//structs to be global.
	//Make them mach_header.cmd[i], or something...
	PLOAD_COMMAND pLoad_command = (PLOAD_COMMAND) (mach_header + 1);
	for (int i = 0; i < mach_header->ncmds; i++) {

		//Fill in specific load commands
		switch (pLoad_command->cmd) {
			case LC_SEGMENT:
				fill_segment_dict(pLoad_command); break;
			case LC_LOAD_DYLIB:
				fill_load_dylib_dict(pLoad_command); break;
			default:
				break;
		}

		//Fill the general load command array
		set_integer(pLoad_command->cmd, module_object,
					"mach_header.load_command[%i].cmd", i);
		set_integer(pLoad_command->cmdsize, module_object,
					"mach_header.load_command[%i].cmdsize", i);

		uint8_t *pNext_load_command = (uint8_t *) pLoad_command;
		pNext_load_command += pLoad_command->cmdsize;
		pLoad_command = (PLOAD_COMMAND) pNext_load_command;
	}

	return true;
}

bool get_mach_header_64(uint64_t offset) {
	return false;
}

bool fill_segment_dict(PLOAD_COMMAND p) {
	PSEGMENT_COMMAND seg = (PSEGMENT_COMMAND) p;

	//TODO: Can we use an int?  What will an int return if it doesn't exist?
	//EDIT: No good - documentation says (char *), but compiler says (SIZED_STRING *)
	//Check if there is a duplicate segment name for this executable
//	char *already_exists = get_string(module_object,
//									  "mach_header.LC_SEGMENT[%s].cmd", seg->segname);
//	if (!strcmp(already_exists, seg->segname)) { return false; }

	//TODO: We should have a check here that there is no duplicate segment name
	set_integer(seg->cmd, module_object,
				"mach_header.LC_SEGMENT[%s].cmd", seg->segname);
	set_integer(seg->cmdsize, module_object,
				"mach_header.LC_SEGMENT[%s].cmdsize", seg->segname);
	set_string(seg->segname, module_object,
			   "mach_header.LC_SEGMENT[%s].segname", seg->segname);
	set_integer(seg->vmaddr, module_object,
				"mach_header.LC_SEGMENT[%s].vmaddr", seg->segname);
	set_integer(seg->fileoff, module_object,
				"mach_header.LC_SEGMENT[%s].fileoff", seg->segname);
	set_integer(seg->filesize, module_object,
				"mach_header.LC_SEGMENT[%s].filesize", seg->segname);
	set_integer(seg->maxprot, module_object,
				"mach_header.LC_SEGMENT[%s].maxprot", seg->segname);
	set_integer(seg->initprot, module_object,
				"mach_header.LC_SEGMENT[%s].initprot", seg->segname);
	set_integer(seg->nsects, module_object,
				"mach_header.LC_SEGMENT[%s].nsects", seg->segname);
	set_integer(seg->flags, module_object,
				"mach_header.LC_SEGMENT[%s].flags", seg->segname);

	//Get the sections
	PSECTION section = (PSECTION) (seg + 1);
	for (int i = 0; i < seg->nsects; i++) {
		set_string(section->sectname, module_object,
				   "mach_header.LC_SEGMENT[%s].section[%s].sectname",
				   seg->segname,
				   section->sectname);
		set_string(section->segname, module_object,
				   "mach_header.LC_SEGMENT[%s].section[%s].segname",
				   seg->segname,
				   section->sectname);
		set_integer(section->addr, module_object,
				   "mach_header.LC_SEGMENT[%s].section[%s].addr",
				   seg->segname,
				   section->sectname);
		set_integer(section->size, module_object,
					"mach_header.LC_SEGMENT[%s].section[%s].size",
					seg->segname,
					section->sectname);
		set_integer(section->offset, module_object,
					"mach_header.LC_SEGMENT[%s].section[%s].offset",
					seg->segname,
					section->sectname);
		set_integer(section->align, module_object,
					"mach_header.LC_SEGMENT[%s].section[%s].align",
					seg->segname,
					section->sectname);
		set_integer(section->reloff, module_object,
					"mach_header.LC_SEGMENT[%s].section[%s].reloff",
					seg->segname,
					section->sectname);
		set_integer(section->nreloc, module_object,
					"mach_header.LC_SEGMENT[%s].section[%s].nreloc",
					seg->segname,
					section->sectname);
		set_integer(section->flags, module_object,
					"mach_header.LC_SEGMENT[%s].section[%s].flags",
					seg->segname,
					section->sectname);
		set_integer(section->reserved1, module_object,
					"mach_header.LC_SEGMENT[%s].section[%s].reserved1",
					seg->segname,
					section->sectname);
		set_integer(section->reserved2, module_object,
					"mach_header.LC_SEGMENT[%s].section[%s].reserved2",
					seg->segname,
					section->sectname);
//		if (is_64_bit) {
//			set_integer(section->reserved3, module_object,
//						"mach_header.LC_SEGMENT[%s].section[%s].reserved3",
//						seg->segname,
//						section->sectname);
//		}
		section++;
	}

	return true;
}

bool fill_load_dylib_dict(PLOAD_COMMAND p) {
	PDYLIB_COMMAND	dylib_cmd	= (PDYLIB_COMMAND) p;
	PDYLIB			dylib		= &dylib_cmd->dylib;

	//Path to dylib is stored after the load command
	char *path = (char *) dylib_cmd + dylib->name;
	char *name = strrchr(path, (int) '/') + 1;

	//TODO: Also put the full path in the hash to check for collisions?
	//Fill in the dylib_command and dylib structures.
	set_integer(dylib_cmd->cmd, module_object,
				"mach_header.LC_LOAD_DYLIB[%s].cmd", name);
	set_integer(dylib_cmd->cmdsize, module_object,
				"mach_header.LC_LOAD_DYLIB[%s].cmdsize", name);
	set_string(name, module_object,
				"mach_header.LC_LOAD_DYLIB[%s].dylib.name", name);
	set_integer(dylib->timestamp, module_object,
				"mach_header.LC_LOAD_DYLIB[%s].dylib.timestamp", name);
	set_integer(dylib->current_version, module_object,
				"mach_header.LC_LOAD_DYLIB[%s].dylib.current_version", name);
	set_integer(dylib->compatibility_version, module_object,
				"mach_header.LC_LOAD_DYLIB[%s].dylib.compatibility_version", name);
	return true;
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
begin_struct("fat_header");
	declare_integer("magic");
	declare_integer("nfat_arch");
end_struct("fat_header");

begin_struct_array("fat_arch");
	declare_integer("cputype");
	declare_integer("cpusubtype");
	declare_integer("offset");
	declare_integer("size");
	declare_integer("align");
end_struct_array("fat_arch");

declare_integer("is_macho");
begin_struct("mach_header");
	declare_integer("magic");
	declare_integer("cputype");
	declare_integer("cpusubtype");
	declare_integer("filetype");
	declare_integer("ncmds");
	declare_integer("sizeofcmds");
	declare_integer("flags");
	begin_struct_array("load_command");
		declare_integer("cmd");
		declare_integer("cmdsize");
	end_struct_array("load_command");
	begin_struct_dictionary("LC_SEGMENT");
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
		//Can we use both string and int keys? It would be nice to be able to use as an array, too.
		begin_struct_dictionary("section");
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
		end_struct_dictionary("section");
	end_struct_dictionary("LC_SEGMENT");
	begin_struct_dictionary("LC_LOAD_DYLIB");
		declare_integer("cmd");
		declare_integer("cmdsize");
		begin_struct("dylib");				//TODO: just ditch the embedded struct?
			declare_string("name");
			declare_integer("timestamp");	//TODO: function to convert this to human-readable?
			declare_integer("current_version");		//TODO: And this
			declare_integer("compatibility_version");	//TODO: And this
		end_struct("dylib");
	end_struct_dictionary("LC_LOAD_DYLIB");
end_struct("mach_header");

declare_integer("is_macho_64");
begin_struct("mach_header_64");
	declare_integer("magic");
	declare_integer("cputype");
	declare_integer("cpusubtype");
	declare_integer("filetype");
	declare_integer("ncmds");
	declare_integer("sizeofcmds");
	declare_integer("flags");
	declare_integer("reserved");
end_struct("mach_header_64");

//begin_struct("load_command");		//TODO: Struct array in macho headers/objects
//	declare_integer("cmd");
//	declare_integer("cmdsize");
//end_struct("load_command");

begin_struct("segment_command");	//TODO: Struct array? Maybe a dict to get by name? Put in macho_header?
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
end_struct("segment_command");

begin_struct("segment_command_64");	//TODO: Struct array? Maybe a dict to get by name? Put in macho_header_64?
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
end_struct("segment_command_64");

begin_struct("section");			//TODO: Put this in segment_command?
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
end_struct("section");

begin_struct("section_64");			//TODO: Put this in segment_command_64?
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
end_struct("section_64");

//begin_struct("fvmlib");
//	declare_integer("name");	//TODO: Offset to the name; follows this struct.  Maybe just make the string part of this struct
//	declare_integer("minor_version");
//	declare_integer("header_addr");
//end_struct("fvmlib");

begin_struct("fvmlib_command");
	declare_integer("cmd");
	declare_integer("cmdsize");
	begin_struct("fvmlib");
		declare_integer("name");	//TODO: Offset to the name; follows this struct.  Maybe just make the string part of this struct
		declare_integer("minor_version");
		declare_integer("header_addr");
	end_struct("fvmlib");
end_struct("fvmlib_command");

begin_struct("dylib_command");
	declare_integer("cmd");
	declare_integer("cmdsize");
	begin_struct("dylib");
		declare_integer("name");	//TODO: Offset to the name; follows this struct.  Maybe just make the string part of this struct
		declare_integer("timestamp");
		declare_integer("current_version");
		declare_integer("compatibility_version");
	end_struct("dylib");
end_struct("dylib_command");
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

	//Then these assume one or the other; if we can't get 32, try 64.
	if (!get_mach_header(0)) {
		get_mach_header_64(0);
	}

	//TODO: Any difference for PPC?

	return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object) {
	if(block) {
		free(block);
	}
	return ERROR_SUCCESS;
}
