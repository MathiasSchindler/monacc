#include "mc.h"

// Minimal objdump-like inspector.
// Supported flags: -h (sections), -t (symbols)
// Usage: objdump [-h] [-t] FILE

// Implementation reuses a minimal ELF64 parser (ET_REL/ET_EXEC/ET_DYN).

#define EI_NIDENT 16
#define EI_CLASS 4
#define EI_DATA 5

#define ELFCLASS64 2
#define ELFDATA2LSB 1

#define SHT_STRTAB 3
#define SHT_SYMTAB 2
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

static mc_u32 read_u32_le(const mc_u8 *p) {
	return (mc_u32)p[0] |
		   ((mc_u32)p[1] << 8) |
		   ((mc_u32)p[2] << 16) |
		   ((mc_u32)p[3] << 24);
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

static const struct elf64_shdr *shdr_at(const mc_u8 *base, mc_usize sz, const struct elf64_ehdr *eh, mc_u32 idx) {
	(void)sz;
	if (!eh || idx >= (mc_u32)eh->e_shnum) return MC_NULL;
	mc_u64 off = eh->e_shoff + (mc_u64)idx * (mc_u64)eh->e_shentsize;
	if (!bounds_ok(sz, off, sizeof(struct elf64_shdr))) return MC_NULL;
	return (const struct elf64_shdr *)(base + (mc_usize)off);
}


static mc_usize write_strtab_name(mc_i32 fd, const mc_u8 *base, mc_usize sz, const struct elf64_shdr *str_sh, mc_u32 off, mc_usize cap) {
	if (!str_sh) return 0;
	if (str_sh->sh_type != SHT_STRTAB) return 0;
	if (!bounds_ok(sz, str_sh->sh_offset, str_sh->sh_size)) return 0;
	if ((mc_u64)off >= str_sh->sh_size) return 0;
	const char *p = (const char *)(base + (mc_usize)str_sh->sh_offset + (mc_usize)off);
	mc_u64 max = str_sh->sh_size - (mc_u64)off;
	mc_usize n = 0;
	while ((mc_u64)n < max && n < cap) {
		if (p[n] == 0) break;
		n++;
	}
	// If we consumed the entire remaining strtab without finding a NUL, treat as invalid.
	if ((mc_u64)n == max) return 0;
	if (n) (void)mc_write_all(fd, p, n);
	return n;
}

static const char *sym_type_str(mc_u8 t) {
	if (t == 0) return "NOTYPE";
	if (t == 1) return "OBJECT";
	if (t == 2) return "FUNC";
	if (t == 3) return "SECTION";
	if (t == 4) return "FILE";
	return "OTHER";
}

static void dump_sections(const char *argv0, const mc_u8 *base, mc_usize sz, const struct elf64_ehdr *eh) {
	(void)argv0;
	(void)mc_write_str(1, "Sections:\n");
	(void)mc_write_str(1, "Idx Name              Size      VMA               FileOff   Flags\n");
	const struct elf64_shdr *shstr = shdr_at(base, sz, eh, (mc_u32)eh->e_shstrndx);
	for (mc_u32 i = 0; i < (mc_u32)eh->e_shnum; i++) {
		const struct elf64_shdr *sh = shdr_at(base, sz, eh, i);
		if (!sh) mc_die_errno(argv0, "invalid shdr table", (mc_i64)-MC_EINVAL);
		(void)mc_write_str(1, "");
		mc_write_u64_dec(1, (mc_u64)i);
		(void)mc_write_str(1, "  ");
		mc_usize n = 0;
		if (i != 0 && shstr) n = write_strtab_name(1, base, sz, shstr, sh->sh_name, 17);
		// Pad to 18.
		for (mc_usize k = n; k < 18; k++) (void)mc_write_all(1, " ", 1);
		write_hex_u64_fixed(1, sh->sh_size, 8);
		(void)mc_write_str(1, " 0x");
		write_hex_u64_fixed(1, sh->sh_addr, 16);
		(void)mc_write_str(1, " 0x");
		write_hex_u64_fixed(1, sh->sh_offset, 8);
		(void)mc_write_str(1, " ");
		// Minimal flag decode: WAX
		(void)mc_write_str(1, (sh->sh_flags & 0x1u) ? "W" : "-");
		(void)mc_write_str(1, (sh->sh_flags & 0x2u) ? "A" : "-");
		(void)mc_write_str(1, (sh->sh_flags & 0x4u) ? "X" : "-");
		(void)mc_write_str(1, "\n");
	}
}

static void dump_symbols(const char *argv0, const mc_u8 *base, mc_usize sz, const struct elf64_ehdr *eh) {
	(void)mc_write_str(1, "Symbols:\n");
	(void)mc_write_str(1, "Value             Size Type    Shndx Name\n");

	for (mc_u32 si = 0; si < (mc_u32)eh->e_shnum; si++) {
		const struct elf64_shdr *sh = shdr_at(base, sz, eh, si);
		if (!sh) mc_die_errno(argv0, "invalid shdr table", (mc_i64)-MC_EINVAL);
		if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM) continue;
		if (sh->sh_entsize == 0) continue;
		if (!bounds_ok(sz, sh->sh_offset, sh->sh_size)) mc_die_errno(argv0, "symtab bounds", (mc_i64)-MC_EINVAL);
		mc_u64 cnt = sh->sh_size / sh->sh_entsize;
		const struct elf64_shdr *strsh = shdr_at(base, sz, eh, sh->sh_link);
		if (!strsh) continue;
		for (mc_u64 i = 0; i < cnt; i++) {
			mc_u64 off = sh->sh_offset + i * sh->sh_entsize;
			if (!bounds_ok(sz, off, sizeof(struct elf64_sym))) break;
			const struct elf64_sym *s = (const struct elf64_sym *)(base + (mc_usize)off);
			mc_u8 type = (mc_u8)(s->st_info & 0xF);
			(void)mc_write_str(1, "0x");
			write_hex_u64_fixed(1, s->st_value, 16);
			(void)mc_write_str(1, " ");
			write_hex_u64_fixed(1, s->st_size, 8);
			(void)mc_write_str(1, " ");
			(void)mc_write_str(1, sym_type_str(type));
			{
				mc_usize tl = mc_strlen(sym_type_str(type));
				for (mc_usize k = tl; k < 7; k++) (void)mc_write_all(1, " ", 1);
			}
			(void)mc_write_str(1, " ");
			if (s->st_shndx == SHN_UNDEF) (void)mc_write_str(1, "UND  ");
			else { mc_write_u64_dec(1, (mc_u64)s->st_shndx); (void)mc_write_str(1, "   "); }
			{
				(void)write_strtab_name(1, base, sz, strsh, s->st_name, 256);
			}
			(void)mc_write_str(1, "\n");
		}
	}
}

static void objdump_one(const char *argv0, const char *path, int want_h, int want_t) {
	mc_usize sz = 0;
	const mc_u8 *base = map_file_ro(argv0, path, &sz);
	if (sz < sizeof(struct elf64_ehdr)) mc_die_errno(argv0, "file too small", (mc_i64)-MC_EINVAL);
	const struct elf64_ehdr *eh = (const struct elf64_ehdr *)base;
	if (!(eh->e_ident[0] == 0x7f && eh->e_ident[1] == 'E' && eh->e_ident[2] == 'L' && eh->e_ident[3] == 'F')) {
		mc_die_errno(argv0, "not an ELF file", (mc_i64)-MC_EINVAL);
	}
	if (eh->e_ident[EI_CLASS] != ELFCLASS64) mc_die_errno(argv0, "only ELF64 supported", (mc_i64)-MC_EINVAL);
	if (eh->e_ident[EI_DATA] != ELFDATA2LSB) mc_die_errno(argv0, "only little-endian supported", (mc_i64)-MC_EINVAL);
	if (eh->e_shnum && !bounds_ok(sz, eh->e_shoff, (mc_u64)eh->e_shnum * (mc_u64)eh->e_shentsize)) {
		mc_die_errno(argv0, "shdr table out of bounds", (mc_i64)-MC_EINVAL);
	}

	(void)mc_write_str(1, path);
	(void)mc_write_str(1, ": file format elf64-x86-64\n");
	if (want_h) dump_sections(argv0, base, sz, eh);
	if (want_t) dump_symbols(argv0, base, sz, eh);
	unmap_file_ro(base, sz);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "objdump";
	int want_h = 0;
	int want_t = 0;
	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) { i++; break; }
		if (a[0] != '-') break;
		if (mc_streq(a, "-h")) want_h = 1;
		else if (mc_streq(a, "-t")) want_t = 1;
		else mc_die_usage(argv0, "objdump [-h] [-t] FILE");
	}
	if (!want_h && !want_t) want_h = 1;
	if (i >= argc) mc_die_usage(argv0, "objdump [-h] [-t] FILE");
	const char *path = argv[i];
	if (!path) mc_die_usage(argv0, "objdump [-h] [-t] FILE");
	objdump_one(argv0, path, want_h, want_t);
	return 0;
}
