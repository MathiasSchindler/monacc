#include "mc.h"

// Minimal readelf-like inspector.
// Supported flags: -h, -l, -S, -s
// Usage: readelf [-h] [-l] [-S] [-s] FILE

#define EI_NIDENT 16
#define EI_CLASS 4
#define EI_DATA 5

#define ELFCLASS32 1
#define ELFCLASS64 2

#define ELFDATA2LSB 1

#define ET_NONE 0
#define ET_REL 1
#define ET_EXEC 2
#define ET_DYN 3

#define PT_LOAD 1

#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_HASH 5
#define SHT_DYNAMIC 6
#define SHT_NOTE 7
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_DYNSYM 11

#define SHN_UNDEF 0

struct elf64_ehdr {
	mc_u8 e_ident[EI_NIDENT];
	mc_u16 e_type;
	mc_u16 e_machine;
	mc_u32 e_version;
	mc_u64 e_entry;
	mc_u64 e_phoff;
	mc_u64 e_shoff;
	mc_u32 e_flags;
	mc_u16 e_ehsize;
	mc_u16 e_phentsize;
	mc_u16 e_phnum;
	mc_u16 e_shentsize;
	mc_u16 e_shnum;
	mc_u16 e_shstrndx;
};

struct elf64_phdr {
	mc_u32 p_type;
	mc_u32 p_flags;
	mc_u64 p_offset;
	mc_u64 p_vaddr;
	mc_u64 p_paddr;
	mc_u64 p_filesz;
	mc_u64 p_memsz;
	mc_u64 p_align;
};

struct elf64_shdr {
	mc_u32 sh_name;
	mc_u32 sh_type;
	mc_u64 sh_flags;
	mc_u64 sh_addr;
	mc_u64 sh_offset;
	mc_u64 sh_size;
	mc_u32 sh_link;
	mc_u32 sh_info;
	mc_u64 sh_addralign;
	mc_u64 sh_entsize;
};

struct elf64_sym {
	mc_u32 st_name;
	mc_u8 st_info;
	mc_u8 st_other;
	mc_u16 st_shndx;
	mc_u64 st_value;
	mc_u64 st_size;
};

static mc_u8 hex_digit(mc_u8 v) {
	v &= 0xF;
	return (v < 10) ? (mc_u8)('0' + v) : (mc_u8)('a' + (v - 10));
}

static void write_hex_u64_fixed(mc_i32 fd, mc_u64 v, mc_u32 digits) {
	char out[16];
	if (digits > 16) digits = 16;
	for (mc_u32 i = 0; i < digits; i++) out[i] = '0';
	for (mc_i32 i = (mc_i32)digits - 1; i >= 0; i--) {
		out[i] = (char)hex_digit((mc_u8)v);
		v >>= 4;
	}
	(void)mc_write_all(fd, out, digits);
}

static void write_cstr_n(mc_i32 fd, const char *s, mc_usize n) {
	(void)mc_write_all(fd, s, n);
}

static const char *etype_str(mc_u16 t) {
	if (t == ET_REL) return "REL";
	if (t == ET_EXEC) return "EXEC";
	if (t == ET_DYN) return "DYN";
	return "OTHER";
}

static const char *sh_type_str(mc_u32 t) {
	if (t == SHT_NULL) return "NULL";
	if (t == SHT_PROGBITS) return "PROGBITS";
	if (t == SHT_SYMTAB) return "SYMTAB";
	if (t == SHT_STRTAB) return "STRTAB";
	if (t == SHT_RELA) return "RELA";
	if (t == SHT_REL) return "REL";
	if (t == SHT_NOBITS) return "NOBITS";
	if (t == SHT_DYNSYM) return "DYNSYM";
	return "OTHER";
}

static const char *sym_bind_str(mc_u8 b) {
	if (b == 0) return "LOCAL";
	if (b == 1) return "GLOBAL";
	if (b == 2) return "WEAK";
	return "OTHER";
}

static const char *sym_type_str(mc_u8 t) {
	if (t == 0) return "NOTYPE";
	if (t == 1) return "OBJECT";
	if (t == 2) return "FUNC";
	if (t == 3) return "SECTION";
	if (t == 4) return "FILE";
	return "OTHER";
}

static int bounds_ok(mc_usize sz, mc_u64 off, mc_u64 need) {
	mc_u64 usz = (mc_u64)sz;
	if (off > usz) return 0;
	// Avoid overflow in off+need by using subtraction.
	if (need > usz - off) return 0;
	return 1;
}

#define PROT_READ 1
#define MAP_PRIVATE 2

static const mc_u8 *map_file_ro(const char *argv0, const char *path, mc_usize *out_sz) {
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) mc_die_errno(argv0, path, fd);
	struct mc_stat st;
	mc_i64 sr = mc_sys_fstat((mc_i32)fd, &st);
	if (sr < 0) mc_die_errno(argv0, "fstat", sr);
	if (st.st_size < 0) mc_die_errno(argv0, "fstat size", (mc_i64)-MC_EINVAL);
	mc_usize sz = (mc_usize)st.st_size;
	mc_i64 addr = mc_sys_mmap(MC_NULL, sz, PROT_READ, MAP_PRIVATE, (mc_i32)fd, 0);
	(void)mc_sys_close((mc_i32)fd);
	if (addr < 0) mc_die_errno(argv0, "mmap", addr);
	*out_sz = sz;
	return (const mc_u8 *)addr;
}

static void unmap_file_ro(const mc_u8 *p, mc_usize sz) {
	(void)mc_sys_munmap((void *)p, sz);
}

static const struct elf64_shdr *elf64_shdr_at(const mc_u8 *base, mc_usize sz, const struct elf64_ehdr *eh, mc_u32 i) {
	if (!eh || i >= (mc_u32)eh->e_shnum) return MC_NULL;
	mc_u64 off = eh->e_shoff + (mc_u64)i * (mc_u64)eh->e_shentsize;
	if (!bounds_ok(sz, off, sizeof(struct elf64_shdr))) return MC_NULL;
	return (const struct elf64_shdr *)(base + (mc_usize)off);
}

static const char *elf64_section_name(const mc_u8 *base, mc_usize sz, const struct elf64_ehdr *eh, const struct elf64_shdr *sh) {
	if (!eh || !sh) return MC_NULL;
	const struct elf64_shdr *shstr = elf64_shdr_at(base, sz, eh, (mc_u32)eh->e_shstrndx);
	if (!shstr) return MC_NULL;
	if (shstr->sh_type != SHT_STRTAB) return MC_NULL;
	if (!bounds_ok(sz, shstr->sh_offset, shstr->sh_size)) return MC_NULL;
	if (sh->sh_name >= shstr->sh_size) return MC_NULL;
	const char *p = (const char *)(base + (mc_usize)shstr->sh_offset + (mc_usize)sh->sh_name);
	// Ensure NUL termination within bounds.
	mc_u64 max = shstr->sh_size - (mc_u64)sh->sh_name;
	for (mc_u64 i = 0; i < max; i++) {
		if (p[i] == 0) return p;
	}
	return MC_NULL;
}

static void print_header(const char *argv0, const char *path, const struct elf64_ehdr *eh) {
	(void)argv0;
	(void)mc_write_str(1, "ELF Header: ");
	(void)mc_write_str(1, path);
	(void)mc_write_str(1, "\n");
	(void)mc_write_str(1, "  Class: ");
	if (eh->e_ident[EI_CLASS] == ELFCLASS64) (void)mc_write_str(1, "ELF64\n");
	else if (eh->e_ident[EI_CLASS] == ELFCLASS32) (void)mc_write_str(1, "ELF32\n");
	else (void)mc_write_str(1, "UNKNOWN\n");
	(void)mc_write_str(1, "  Data: ");
	if (eh->e_ident[EI_DATA] == ELFDATA2LSB) (void)mc_write_str(1, "2's complement, little endian\n");
	else (void)mc_write_str(1, "UNKNOWN\n");
	(void)mc_write_str(1, "  Type: ");
	(void)mc_write_str(1, etype_str(eh->e_type));
	(void)mc_write_str(1, "\n");
	(void)mc_write_str(1, "  Machine: ");
	mc_write_u64_dec(1, (mc_u64)eh->e_machine);
	(void)mc_write_str(1, "\n");
	(void)mc_write_str(1, "  Entry point: 0x");
	write_hex_u64_fixed(1, eh->e_entry, 16);
	(void)mc_write_str(1, "\n");
	(void)mc_write_str(1, "  Program header offset: ");
	mc_write_u64_dec(1, eh->e_phoff);
	(void)mc_write_str(1, "\n");
	(void)mc_write_str(1, "  Section header offset: ");
	mc_write_u64_dec(1, eh->e_shoff);
	(void)mc_write_str(1, "\n");
	(void)mc_write_str(1, "  PH num/entsize: ");
	mc_write_u64_dec(1, (mc_u64)eh->e_phnum);
	(void)mc_write_str(1, "/");
	mc_write_u64_dec(1, (mc_u64)eh->e_phentsize);
	(void)mc_write_str(1, "\n");
	(void)mc_write_str(1, "  SH num/entsize: ");
	mc_write_u64_dec(1, (mc_u64)eh->e_shnum);
	(void)mc_write_str(1, "/");
	mc_write_u64_dec(1, (mc_u64)eh->e_shentsize);
	(void)mc_write_str(1, "\n");
}

static void print_phdrs(const char *argv0, const mc_u8 *base, mc_usize sz, const struct elf64_ehdr *eh) {
	(void)argv0;
	(void)mc_write_str(1, "Program Headers:\n");
	(void)mc_write_str(1, "  Type   Offset             VirtAddr           FileSiz  MemSiz   Flags Align\n");
	for (mc_u32 i = 0; i < (mc_u32)eh->e_phnum; i++) {
		mc_u64 off = eh->e_phoff + (mc_u64)i * (mc_u64)eh->e_phentsize;
		if (!bounds_ok(sz, off, sizeof(struct elf64_phdr))) {
			mc_die_errno(argv0, "invalid phdr table", (mc_i64)-MC_EINVAL);
		}
		const struct elf64_phdr *ph = (const struct elf64_phdr *)(base + (mc_usize)off);
		if (ph->p_type == PT_LOAD) (void)mc_write_str(1, "  LOAD  ");
		else {
			(void)mc_write_str(1, "  ");
			mc_write_u64_dec(1, (mc_u64)ph->p_type);
			(void)mc_write_str(1, "    ");
		}
		(void)mc_write_str(1, "0x");
		write_hex_u64_fixed(1, ph->p_offset, 16);
		(void)mc_write_str(1, " 0x");
		write_hex_u64_fixed(1, ph->p_vaddr, 16);
		(void)mc_write_str(1, " ");
		write_hex_u64_fixed(1, ph->p_filesz, 8);
		(void)mc_write_str(1, " ");
		write_hex_u64_fixed(1, ph->p_memsz, 8);
		(void)mc_write_str(1, "  ");
		// flags: R W X
		(void)mc_write_str(1, (ph->p_flags & 4u) ? "R" : "-");
		(void)mc_write_str(1, (ph->p_flags & 2u) ? "W" : "-");
		(void)mc_write_str(1, (ph->p_flags & 1u) ? "X" : "-");
		(void)mc_write_str(1, "   ");
		write_hex_u64_fixed(1, ph->p_align, 8);
		(void)mc_write_str(1, "\n");
	}
}

static void print_shdrs(const char *argv0, const mc_u8 *base, mc_usize sz, const struct elf64_ehdr *eh) {
	(void)argv0;
	(void)mc_write_str(1, "Section Headers:\n");
	(void)mc_write_str(1, "  [Nr] Name              Type      Address           Off    Size   ES Flg Lk Inf Al\n");
	for (mc_u32 i = 0; i < (mc_u32)eh->e_shnum; i++) {
		const struct elf64_shdr *sh = elf64_shdr_at(base, sz, eh, i);
		if (!sh) mc_die_errno(argv0, "invalid shdr table", (mc_i64)-MC_EINVAL);
		const char *name = elf64_section_name(base, sz, eh, sh);
		(void)mc_write_str(1, "  [");
		mc_write_u64_dec(1, (mc_u64)i);
		(void)mc_write_str(1, "] ");
		if (name) {
			mc_usize n = mc_strlen(name);
			if (n > 17) n = 17;
			write_cstr_n(1, name, n);
		} else {
			(void)mc_write_str(1, "<noname>");
		}
		// pad to 18
		{
			mc_usize used = name ? mc_strlen(name) : 8;
			if (used > 17) used = 17;
			for (mc_usize k = used; k < 18; k++) (void)mc_write_all(1, " ", 1);
		}
		(void)mc_write_str(1, " ");
		(void)mc_write_str(1, sh_type_str(sh->sh_type));
		// pad type to 8
		{
			mc_usize tl = mc_strlen(sh_type_str(sh->sh_type));
			for (mc_usize k = tl; k < 8; k++) (void)mc_write_all(1, " ", 1);
		}
		(void)mc_write_str(1, " 0x");
		write_hex_u64_fixed(1, sh->sh_addr, 16);
		(void)mc_write_str(1, " 0x");
		write_hex_u64_fixed(1, sh->sh_offset, 6);
		(void)mc_write_str(1, " ");
		write_hex_u64_fixed(1, sh->sh_size, 6);
		(void)mc_write_str(1, " ");
		write_hex_u64_fixed(1, sh->sh_entsize, 2);
		(void)mc_write_str(1, " ");
		// flags: WAX (very minimal)
		(void)mc_write_str(1, (sh->sh_flags & 0x1u) ? "W" : " ");
		(void)mc_write_str(1, (sh->sh_flags & 0x2u) ? "A" : " ");
		(void)mc_write_str(1, (sh->sh_flags & 0x4u) ? "X" : " ");
		(void)mc_write_str(1, " ");
		mc_write_u64_dec(1, (mc_u64)sh->sh_link);
		(void)mc_write_str(1, " ");
		mc_write_u64_dec(1, (mc_u64)sh->sh_info);
		(void)mc_write_str(1, " ");
		mc_write_u64_dec(1, (mc_u64)sh->sh_addralign);
		(void)mc_write_str(1, "\n");
	}
}

static const char *elf64_strtab_at(const mc_u8 *base, mc_usize sz, const struct elf64_shdr *str_sh, mc_u32 off) {
	if (!str_sh) return MC_NULL;
	if (str_sh->sh_type != SHT_STRTAB) return MC_NULL;
	if (off >= str_sh->sh_size) return MC_NULL;
	if (!bounds_ok(sz, str_sh->sh_offset, str_sh->sh_size)) return MC_NULL;
	const char *p = (const char *)(base + (mc_usize)str_sh->sh_offset + (mc_usize)off);
	mc_u64 max = str_sh->sh_size - off;
	for (mc_u64 i = 0; i < max; i++) {
		if (p[i] == 0) return p;
	}
	return MC_NULL;
}

static void print_symbols_one(const char *argv0, const mc_u8 *base, mc_usize sz, const struct elf64_ehdr *eh, const struct elf64_shdr *symsh, const char *label) {
	(void)mc_write_str(1, label);
	(void)mc_write_str(1, ":\n");
	(void)mc_write_str(1, "  Num: Value             Size Type    Bind    Shndx Name\n");
	if (symsh->sh_entsize == 0) mc_die_errno(argv0, "symtab entsize=0", (mc_i64)-MC_EINVAL);
	if (!bounds_ok(sz, symsh->sh_offset, symsh->sh_size)) mc_die_errno(argv0, "symtab bounds", (mc_i64)-MC_EINVAL);
	mc_u64 count64 = symsh->sh_size / symsh->sh_entsize;
	if (count64 > 1000000u) mc_die_errno(argv0, "symtab too large", (mc_i64)-MC_EINVAL);
	const struct elf64_shdr *strsh = elf64_shdr_at(base, sz, eh, symsh->sh_link);
	if (!strsh) mc_die_errno(argv0, "symtab strtab", (mc_i64)-MC_EINVAL);

	for (mc_u64 i = 0; i < count64; i++) {
		mc_u64 off = symsh->sh_offset + i * symsh->sh_entsize;
		if (!bounds_ok(sz, off, sizeof(struct elf64_sym))) mc_die_errno(argv0, "sym bounds", (mc_i64)-MC_EINVAL);
		const struct elf64_sym *s = (const struct elf64_sym *)(base + (mc_usize)off);
		mc_u8 bind = (mc_u8)(s->st_info >> 4);
		mc_u8 type = (mc_u8)(s->st_info & 0xF);
		(void)mc_write_str(1, "  ");
		mc_write_u64_dec(1, i);
		(void)mc_write_str(1, ": 0x");
		write_hex_u64_fixed(1, s->st_value, 16);
		(void)mc_write_str(1, " ");
		write_hex_u64_fixed(1, s->st_size, 8);
		(void)mc_write_str(1, " ");
		(void)mc_write_str(1, sym_type_str(type));
		// pad to 7
		{
			mc_usize tl = mc_strlen(sym_type_str(type));
			for (mc_usize k = tl; k < 7; k++) (void)mc_write_all(1, " ", 1);
		}
		(void)mc_write_str(1, " ");
		(void)mc_write_str(1, sym_bind_str(bind));
		{
			mc_usize bl = mc_strlen(sym_bind_str(bind));
			for (mc_usize k = bl; k < 7; k++) (void)mc_write_all(1, " ", 1);
		}
		(void)mc_write_str(1, " ");
		if (s->st_shndx == SHN_UNDEF) {
			(void)mc_write_str(1, "UND  ");
		} else {
			mc_write_u64_dec(1, (mc_u64)s->st_shndx);
			(void)mc_write_str(1, "   ");
		}
		const char *nm = elf64_strtab_at(base, sz, strsh, s->st_name);
		if (nm) (void)mc_write_str(1, nm);
		(void)mc_write_str(1, "\n");
	}
}

static void print_symbols(const char *argv0, const mc_u8 *base, mc_usize sz, const struct elf64_ehdr *eh) {
	for (mc_u32 i = 0; i < (mc_u32)eh->e_shnum; i++) {
		const struct elf64_shdr *sh = elf64_shdr_at(base, sz, eh, i);
		if (!sh) mc_die_errno(argv0, "invalid shdr table", (mc_i64)-MC_EINVAL);
		if (sh->sh_type == SHT_SYMTAB) {
			print_symbols_one(argv0, base, sz, eh, sh, "Symbol table (SYMTAB)");
		}
		if (sh->sh_type == SHT_DYNSYM) {
			print_symbols_one(argv0, base, sz, eh, sh, "Symbol table (DYNSYM)");
		}
	}
}

static void readelf_one(const char *argv0, const char *path, int want_h, int want_l, int want_S, int want_s) {
	mc_usize sz = 0;
	const mc_u8 *base = map_file_ro(argv0, path, &sz);
	if (sz < sizeof(struct elf64_ehdr)) mc_die_errno(argv0, "file too small", (mc_i64)-MC_EINVAL);
	const struct elf64_ehdr *eh = (const struct elf64_ehdr *)base;
	if (!(eh->e_ident[0] == 0x7f && eh->e_ident[1] == 'E' && eh->e_ident[2] == 'L' && eh->e_ident[3] == 'F')) {
		mc_die_errno(argv0, "not an ELF file", (mc_i64)-MC_EINVAL);
	}
	if (eh->e_ident[EI_CLASS] != ELFCLASS64) {
		mc_die_errno(argv0, "only ELF64 supported", (mc_i64)-MC_EINVAL);
	}
	if (eh->e_ident[EI_DATA] != ELFDATA2LSB) {
		mc_die_errno(argv0, "only little-endian supported", (mc_i64)-MC_EINVAL);
	}
	if (eh->e_ehsize != sizeof(struct elf64_ehdr)) {
		// Be tolerant, but still require tables in-bounds.
	}
	if (eh->e_phnum && !bounds_ok(sz, eh->e_phoff, (mc_u64)eh->e_phnum * (mc_u64)eh->e_phentsize)) {
		mc_die_errno(argv0, "phdr table out of bounds", (mc_i64)-MC_EINVAL);
	}
	if (eh->e_shnum && !bounds_ok(sz, eh->e_shoff, (mc_u64)eh->e_shnum * (mc_u64)eh->e_shentsize)) {
		mc_die_errno(argv0, "shdr table out of bounds", (mc_i64)-MC_EINVAL);
	}

	if (want_h) print_header(argv0, path, eh);
	if (want_l) print_phdrs(argv0, base, sz, eh);
	if (want_S) print_shdrs(argv0, base, sz, eh);
	if (want_s) print_symbols(argv0, base, sz, eh);

	unmap_file_ro(base, sz);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "readelf";

	int want_h = 0, want_l = 0, want_S = 0, want_s = 0;
	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-') break;
		if (mc_streq(a, "-h")) want_h = 1;
		else if (mc_streq(a, "-l")) want_l = 1;
		else if (mc_streq(a, "-S")) want_S = 1;
		else if (mc_streq(a, "-s")) want_s = 1;
		else mc_die_usage(argv0, "readelf [-h] [-l] [-S] [-s] FILE");
	}
	if (!want_h && !want_l && !want_S && !want_s) want_h = 1;
	if (i >= argc) mc_die_usage(argv0, "readelf [-h] [-l] [-S] [-s] FILE");
	const char *path = argv[i];
	if (!path) mc_die_usage(argv0, "readelf [-h] [-l] [-S] [-s] FILE");

	readelf_one(argv0, path, want_h, want_l, want_S, want_s);
	return 0;
}
