#include <inttypes.h>

/*
 * Helper functions/items for the module
 */

typedef enum bool {false, true} bool;

//Change from little- to big-endian and vice-versa
uint32_t swap_endianness_32(uint32_t n) {
	uint32_t swapped;
	((uint8_t *) &swapped)[3] = ((uint8_t *) &n)[0];
	((uint8_t *) &swapped)[2] = ((uint8_t *) &n)[1];
	((uint8_t *) &swapped)[1] = ((uint8_t *) &n)[2];
	((uint8_t *) &swapped)[0] = ((uint8_t *) &n)[3];
	return swapped;

}

/*
 * fat_header-related items
 */
#define FAT_MAGIC	0xcafebabe
#define FAT_CIGAM	0xbebafeca

typedef struct fat_header {
	uint32_t magic;
	uint32_t nfat_arch;
} FAT_HEADER, *PFAT_HEADER;

typedef struct fat_arch {
	uint32_t		cputype;		//officially cpu_type_t
	uint32_t		cpusubtype;		//officially cpu_subtype_t
	uint32_t		offset;
	uint32_t		size;
	uint32_t		align;
} FAT_ARCH, *PFAT_ARCH;

/*
 * macho_header-related items
 */

#define MH_MAGIC	0xfeedface
#define MH_CIGAM	0xcefaedfe

typedef struct mach_header {
	uint32_t		magic;
	uint32_t		cputype;
	uint32_t		cpusubtype;
	uint32_t		filetype;
	uint32_t		ncmds;
	uint32_t		sizeofcmds;
	uint32_t		flags;
} MACH_HEADER, *PMACH_HEADER;

#define MH_MAGIC_64	0xfeedfacf
#define MH_CIGAM_64	0xcffaedfe

typedef struct mach_header_64 {
	uint32_t		magic;
	uint32_t		cputype;
	uint32_t		cpusubtype;
	uint32_t		filetype;
	uint32_t		ncmds;
	uint32_t		sizeofcmds;
	uint32_t		flags;
	uint32_t		reserved;
} MACH_HEADER_64, *PMACH_HEADER_64;

//filetype constants
#define MH_OBJECT		1
#define MH_EXECUTE		2
#define MH_FVMLIB		3
#define MH_CORE			4
#define MH_PRELOAD		5
#define MH_DYLIB		6
#define MH_DYLINKER		7
#define MH_BUNDLE		8
#define MH_DYLIB_STUB	9
#define MH_DSYM			0x0a
#define MH_KEXT_BUNDLE	0x0b

//flags constants for mach_headers
#define MH_NOUNDEFS					1
#define MH_INCRLINK					2
#define MH_DYLDLINK					4
#define MH_BINDATLOAD				8
#define MH_PREBOUND					0x10
#define MH_SPLIT_SEGS				0x20
#define MH_LAZY_INIT				0x40
#define MH_TWOLEVEL					0x80
#define MH_FORCE_FLAT				0x100
#define MH_NOMULTIDEFS				0x200
#define MH_NOFIXPREBINDING			0x400
#define MH_PREBINDABLE				0x800
#define MH_ALLMODSBOUND				0x1000
#define MH_SUBSECTIONS_VIA_SYMBOLS	0x2000
#define MH_CANONICAL				0x4000
#define MH_WEAK_DEFINES				0x8000
#define MH_BINDS_TO_WEAK			0x10000
#define MH_ALLOW_STACK_EXECUTION	0x20000
#define MH_ROOT_SAFE				0x40000
#define MH_SETUID_SAFE				0x80000
#define MH_NO_REEXPORTED_DYLIBS		0x100000
#define MH_PIE						0x200000
#define MH_DEAD_STRIPPABLE_DYLIB	0x400000
#define MH_HAS_TLV_DESCRIPTORS		0x800000
#define MH_NO_HEAP_EXECUTION		0x1000000
#define MH_APP_EXTENSION_SAFE		0x02000000

/*
 * load_command-related items
 */
typedef struct load_command {
	uint32_t cmd;
	uint32_t cmdsize;
} LOAD_COMMAND, *PLOAD_COMMAND;

//Flag for newer load commands
#define LC_REQ_DYLD 0x80000000

//cmd constants
#define LC_SEGMENT					1
#define LC_SYMTAB					2
#define LC_SYMSEG					3
#define LC_THREAD					4
#define LC_UNIXTHREAD				5
#define LC_LOADFVMLIB				6
#define LC_IDFVMLIB					7
#define LC_IDENT					8
#define LC_FVMFILE					9
#define LC_PREPAGE					0x0a
#define LC_DYSYMTAB					0x0b
#define LC_LOAD_DYLIB				0x0c
#define LC_ID_DYLIB					0x0d
#define LC_LOAD_DYLINKER			0x0e
#define LC_ID_DYLINKER				0x0f
#define LC_PREBOUND_DYLIB			0x10
#define LC_ROUTINES					0x11
#define LC_SUB_FRAMEWORK			0x12
#define LC_SUB_UMBRELLA				0x13
#define LC_SUB_CLIENT				0x14
#define LC_SUB_LIBRARY				0x15
#define LC_TWOLEVEL_HINTS			0x16
#define LC_PREBIND_CKSUM			0x17
#define LC_LOAD_WEAK_DYLIB			(0x18 | LC_REQ_DYLD)
#define LC_SEGMENT_64				0x19
#define LC_ROUTINES_64				0x1a
#define LC_UUID						0x1b
#define LC_RPATH					(0x1c | LC_REQ_DYLD)
#define LC_CODE_SIGNATURE			0x1d
#define LC_SEGMENT_SPLIT_INFO		0x1e
#define LC_REEXPORT_DYLIB			(0x1f | LC_REQ_DYLD)
#define LC_LAZY_LOAD_DYLIB			0x20
#define LC_ENCRYPTION_INFO			0x21
#define LC_DYLD_INFO				0x22
#define LC_DYLD_INFO_ONLY			(0x22 | LC_REQ_DYLD)
#define LC_LOAD_UPWARD_DYLIB		(0x23 | LC_REQ_DYLD)
#define LC_VERSION_MIN_MACOSX		0x24
#define LC_VERSION_MIN_IPHONEOS		0x25
#define LC_FUNCTION_STARTS			0x26
#define LC_DYLD_ENVIRONMENT			0x27
#define LC_MAIN						(0x28 | LC_REQ_DYLD)
#define LC_DATA_IN_CODE				0x29
#define LC_SOURCE_VERSION			0x2A
#define LC_DYLIB_CODE_SIGN_DRS		0x2B
#define LC_ENCRYPTION_INFO_64		0x2C
#define LC_LINKER_OPTION			0x2D
#define LC_LINKER_OPTIMIZATION_HINT	0x2E

//TODO: This thing points to a string in a dylib command
//union lc_str {
//	uint32_t        offset; /* offset to the string */
//#ifndef __LP64__
//	char            *ptr;   /* pointer to the string */
//#endif
//};

//Doesn't work if larger; casting issue.
typedef uint8_t lc_str;

typedef struct segment_command {
	uint32_t	cmd;
	uint32_t	cmdsize;
	char		segname[16];
	uint32_t	vmaddr;
	uint32_t	vmsize;
	uint32_t	fileoff;
	uint32_t	filesize;
	uint32_t	maxprot;
	uint32_t	initprot;
	uint32_t	nsects;
	uint32_t	flags;
} SEGMENT_COMMAND, *PSEGMENT_COMMAND;

typedef struct segment_command_64 {
	uint32_t	cmd;
	uint32_t	cmdsize;
	char		segname[16];
	uint64_t	vmaddr;
	uint64_t	vmsize;
	uint64_t	fileoff;
	uint64_t	filesize;
	uint32_t	maxprot;
	uint32_t	initprot;
	uint32_t	nsects;
	uint32_t	flags;
} SEGMENT_COMMAND_64, *PSEGMENT_COMMAND_64;

typedef union segment {
	uint32_t						cmd;
	SEGMENT_COMMAND			_32;
	SEGMENT_COMMAND_64	_64;
} SEGMENT, *PSEGMENT;

//flags constants for segment_commands
#define SG_HIGHVM				0x1
#define SG_FVMLIB				0x2
#define SG_NORELOC				0x4
#define SG_PROTECTED_VERSION_1	0x8

typedef struct _section {
	char			sectname[16];
	char			segname[16];
	uint32_t	addr;
	uint32_t	size;
	uint32_t	offset;
	uint32_t	align;
	uint32_t	reloff;
	uint32_t	nreloc;
	uint32_t	flags;
	uint32_t	reserved1;
	uint32_t	reserved2;
} _SECTION, *_PSECTION;

typedef struct _section_64 {
	char			sectname[16];
	char			segname[16];
	uint64_t	addr;
	uint64_t	size;
	uint32_t	offset;
	uint32_t	align;
	uint32_t	reloff;
	uint32_t	nreloc;
	uint32_t	flags;
	uint32_t	reserved1;
	uint32_t	reserved2;
	uint32_t	reserved3;
} _SECTION_64, *_PSECTION_64;

typedef union section {
	char				sectname[16];
	_SECTION		_32;
	_SECTION_64	_64;
} SECTION, *PSECTION;

//flags constants for section type: mask and flags
#define SECTION_TYPE							0x000000ff	//mask
#define S_REGULAR								0
#define S_ZEROFILL								1
#define S_CSTRING_LITERALS						2
#define S_4BYTE_LITERALS						3
#define S_8BYTE_LITERALS						4
#define S_LITERAL_POINTERS						5
#define S_NON_LAZY_SYMBOL_POINTERS				6
#define S_LAZY_SYMBOL_POINTERS					7
#define S_SYMBOL_STUBS							8
#define S_MOD_INIT_FUNC_POINTERS				9
#define S_MOD_TERM_FUNC_POINTERS				0x0a
#define S_COALESCED								0x0b
#define S_GB_ZEROFILL							0x0c
#define S_INTERPOSING							0x0d
#define S_16BYTE_LITERALS						0x0e
#define S_DTRACE_DOF							0x0f
#define S_LAZY_DYLIB_SYMBOL_POINTERS			0x10
#define S_THREAD_LOCAL_REGULAR					0x11
#define S_THREAD_LOCAL_ZEROFILL					0x12
#define S_THREAD_LOCAL_VARIABLES				0x13
#define S_THREAD_LOCAL_VARIABLE_POINTERS		0x14
#define S_THREAD_LOCAL_INIT_FUNCTION_POINTERS	0x15

//flags constants for section attributes: mask and flags
#define SECTION_ATTRIBUTES			0xffffff00		//mask
#define SECTION_ATTRIBUTES_USR		0xff000000
#define S_ATTR_PURE_INSTRUCTIONS	0x80000000
#define S_ATTR_NO_TOC				0x40000000
#define S_ATTR_STRIP_STATIC_SYMS	0x20000000
#define S_ATTR_NO_DEAD_STRIP		0x10000000
#define S_ATTR_LIVE_SUPPORT			0x08000000
#define S_ATTR_SELF_MODIFYING_CODE	0x04000000
#define S_ATTR_DEBUG				0x02000000
#define SECTION_ATTRIBUTES_SYS		0x00ffff00
#define S_ATTR_SOME_INSTRUCTIONS	0x00000400
#define S_ATTR_EXT_RELOC			0x00000200
#define S_ATTR_LOC_RELOC			0x00000100

//Segment and section name constants
#define SEG_PAGEZERO		"__PAGEZERO"
#define SEG_TEXT			"__TEXT"
#define SECT_TEXT			"__text"
#define SECT_FVMLIB_INIT0	"__fvmlib_init0"
#define SECT_FVMLIB_INIT1	"__fvmlib_init1"
#define SEG_DATA			"__DATA"
#define SECT_DATA			"__data"
#define SECT_BSS			"__bss"
#define SECT_COMMON			"__common"
#define SEG_OBJC			"__OBJC"
#define SECT_OBJC_SYMBOLS	"__symbol_table"
#define SECT_OBJC_MODULES	"__module_info"
#define SECT_OBJC_STRINGS	"__selector_strs"
#define SECT_OBJC_REFS		"__selector_refs"
#define SEG_ICON			"__ICON"
#define SECT_ICON_HEADER	"__header"
#define SECT_ICON_TIFF		"__tiff"
#define SEG_LINKEDIT		"__LINKEDIT"
#define SEG_UNIXSTACK		"__UNIXSTACK"
#define SEG_IMPORT			"__IMPORT"

/*
 * Fixed Virtual Memory shared library items
 */
typedef struct fvmlib {
//	union lc_str	name;				//TODO: lc_str
	lc_str			name;
	uint32_t		minor_version;
	uint32_t		header_addr;
} FVMLIB, *PFVMLIB;

typedef struct fvmlib_command {
	uint32_t	cmd;
	uint32_t	cmdsize;
	FVMLIB		fvmlib;
} FVMLIB_COMMAND, *PFVMLIB_COMMAND;

/*
 * Dylib-related items
 */
typedef struct dylib {
//	union lc_str  name;					//TODO: lc_str: name exists @dylib + lc_str/offset
	lc_str			name;
	uint32_t	timestamp;
	uint32_t	current_version;
	uint32_t	compatibility_version;
} DYLIB, *PDYLIB;

typedef struct dylib_command {
	uint32_t	cmd;
	uint32_t	cmdsize;
//	struct dylib    dylib;				//TODO: does this become DYLIB, or *PDYLIB?
	DYLIB		dylib;
} DYLIB_COMMAND, *PDYLIB_COMMAND;

/*
 * Function prototypes for parsing routines and other module necessities
 */

//Set the constants so that we can access macho.FAT_MAGIC
//to get 0xbebafeca, for example
bool set_constants();

bool get_fat_header(uint64_t offset);
bool get_mach_header(uint64_t offset);
bool get_mach_header_64(uint64_t offset);

//Fill a mach header's segment dictionary
bool fill_segment_dict(PLOAD_COMMAND);
bool fill_segment_64_dict(PLOAD_COMMAND);

bool fill_load_dylib_dict(PLOAD_COMMAND);
