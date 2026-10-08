// macOS stand-in for glibc's <link.h>. Guest modules stay ELF images on macOS (mapped by core/macos/loader),
// so the code that walks ELF program headers keeps working; the loader implements these entry points.
#ifndef PRX_LIBC_INCLUDE_SPECIFICS_MACOS_SHIM_LINK_H
#define PRX_LIBC_INCLUDE_SPECIFICS_MACOS_SHIM_LINK_H
// Same declarations as specifics/linux/ElfTypes.hpp, which becomes empty when both are included.
#define PRX_LIBC_INCLUDE_SPECIFICS_LINUX_ELFTYPES_HPP

#include <cstddef>
#include <cstdint>
#include <dlfcn.h>

struct Elf64_Phdr {
    std::uint32_t p_type;
    std::uint32_t p_flags;
    std::uint64_t p_offset;
    std::uint64_t p_vaddr;
    std::uint64_t p_paddr;
    std::uint64_t p_filesz;
    std::uint64_t p_memsz;
    std::uint64_t p_align;
};

struct Elf64_Dyn {
    std::int64_t d_tag;
    union {
        std::uint64_t d_val;
        std::uint64_t d_ptr;
    } d_un;
};

#define ElfW(type) Elf64_##type

struct dl_phdr_info {
    std::uintptr_t dlpi_addr;
    const char* dlpi_name;
    const Elf64_Phdr* dlpi_phdr;
    std::uint16_t dlpi_phnum;
    unsigned long long dlpi_adds;
    unsigned long long dlpi_subs;
    std::size_t dlpi_tls_modid;
    void* dlpi_tls_data;
};

struct link_map {
    std::uintptr_t l_addr;
    char* l_name;
    Elf64_Dyn* l_ld;
    link_map* l_next;
    link_map* l_prev;
};

static constexpr std::uint32_t PT_LOAD = 1;
static constexpr std::uint32_t PT_DYNAMIC = 2;
static constexpr std::uint32_t PT_TLS = 7;
static constexpr std::uint32_t PT_GNU_EH_FRAME = 0x6474e550;
static constexpr std::uint32_t PF_X = 1;
static constexpr std::uint32_t PF_W = 2;
static constexpr std::uint32_t PF_R = 4;
static constexpr std::int64_t DT_NULL = 0;
static constexpr std::int64_t DT_INIT = 12;
static constexpr std::int64_t DT_FINI = 13;
static constexpr int RTLD_DL_LINKMAP = 2;

extern "C" {
// Reports the guest modules only; native system libraries are Mach-O images and are not listed. Same symbol
// as specifics/linux/ElfTypes.hpp declares on macOS (libc/src/specifics/macos/GuestImages.cpp).
int dl_iterate_phdr(int (*callback)(dl_phdr_info*, std::size_t, void*), void* data) __asm__("_dl_iterate_phdr_nid_no_patch");
// Guest modules only: fails for an address inside a native image.
int dladdr1(const void* address, Dl_info* info, void** extra, int flags);
}

#endif
