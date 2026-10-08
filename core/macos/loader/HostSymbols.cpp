#include "HostSymbols.hpp"

#include <nid/NidResolver.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/mman.h>

namespace HostSymbols {

namespace {

// Export name as the guest imports it (a NID, or a plain name for unpatched exports) to its address.
// The first library to provide a name wins, as with the ELF global lookup order.
std::unordered_map<std::string, void*> exports;
std::unordered_set<const mach_header*> scanned;
std::vector<std::string> missingLibraries;
std::unordered_map<std::string, void*> traps;
std::vector<std::string> trapNames;
std::uint8_t* trapPage = nullptr;
std::size_t trapPageUsed = 0;
constexpr std::size_t TrapPageBytes = 0x10000, TrapBytes = 24;
bool verbose = std::getenv("APS5_LOADER_VERBOSE") != nullptr;

[[noreturn]] void Unresolved(std::uint64_t index) {
    std::fprintf(stderr, "aps5-run: guest called unresolved import %s\n", trapNames[index].c_str());
    std::_Exit(70);
}

// mov edi, index; movabs rax, Unresolved; jmp rax
void* CreateTrap(const std::string& name) {
    if (trapPage == nullptr || trapPageUsed + TrapBytes > TrapPageBytes) {
        trapPage = static_cast<std::uint8_t*>(mmap(nullptr, TrapPageBytes, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0));
        if (trapPage == MAP_FAILED) {
            std::fprintf(stderr, "aps5-run: cannot allocate import traps\n");
            std::exit(1);
        }
        trapPageUsed = 0;
    }
    auto* code = trapPage + trapPageUsed;
    trapPageUsed += TrapBytes;
    const auto index = static_cast<std::uint32_t>(trapNames.size());
    trapNames.push_back(name);
    const auto target = reinterpret_cast<std::uint64_t>(&Unresolved);
    code[0] = 0xbf;
    std::memcpy(code + 1, &index, 4);
    code[5] = 0x48;
    code[6] = 0xb8;
    std::memcpy(code + 7, &target, 8);
    code[15] = 0xff;
    code[16] = 0xe0;
    return code;
}

// The native libraries export source-level names (function_nid_postfix and friends). On Linux and Windows a
// build step renames them to NIDs inside the binary; here the same rules are applied to the loaded image's
// symbol table, so the Mach-O files need no patching.
void ScanImage(const mach_header* header, std::intptr_t slide, const std::string& libraryName) {
    if (header->magic != MH_MAGIC_64 || !scanned.insert(header).second) return;
    const symtab_command* table = nullptr;
    const segment_command_64* linkedit = nullptr;
    const auto* command = reinterpret_cast<const load_command*>(reinterpret_cast<const mach_header_64*>(header) + 1);
    for (std::uint32_t i = 0; i < header->ncmds; ++i) {
        if (command->cmd == LC_SYMTAB) table = reinterpret_cast<const symtab_command*>(command);
        if (command->cmd == LC_SEGMENT_64 && std::strcmp(reinterpret_cast<const segment_command_64*>(command)->segname, SEG_LINKEDIT) == 0) linkedit = reinterpret_cast<const segment_command_64*>(command);
        command = reinterpret_cast<const load_command*>(reinterpret_cast<const char*>(command) + command->cmdsize);
    }
    if (table == nullptr || linkedit == nullptr) return;
    const auto* file = reinterpret_cast<const char*>(linkedit->vmaddr + slide - linkedit->fileoff);
    const auto* symbols = reinterpret_cast<const nlist_64*>(file + table->symoff);
    const auto* strings = file + table->stroff;
    std::vector<std::string> names;
    std::unordered_map<std::string, void*> addresses;
    for (std::uint32_t i = 0; i < table->nsyms; ++i) {
        const auto& symbol = symbols[i];
        if ((symbol.n_type & N_STAB) != 0 || (symbol.n_type & N_EXT) == 0 || (symbol.n_type & N_TYPE) != N_SECT) continue;
        const char* name = strings + symbol.n_un.n_strx;
        if (name[0] != '_') continue;
        if (addresses.emplace(name + 1, reinterpret_cast<void*>(symbol.n_value + slide)).second) names.emplace_back(name + 1);
    }
    std::size_t added = 0;
    for (const auto& [name, exported] : Nid::ResolveNids(names, libraryName, {}))
        if (exports.emplace(exported, addresses.at(name)).second) ++added;
    if (verbose) std::fprintf(stderr, "aps5-run: %s: %zu exports, %zu newly bound names\n", libraryName.c_str(), names.size(), added);
}

}

void LoadLibrary(const std::filesystem::path& directory, const std::string& name) {
    const auto path = directory / name;
    if (dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL) == nullptr) {
        if (verbose) std::fprintf(stderr, "aps5-run: %s\n", dlerror());
        missingLibraries.push_back(name);
        return;
    }
    std::error_code error;
    const auto resolved = std::filesystem::canonical(directory, error);
    // The requested library first, then whatever it pulled in.
    for (int pass = 0; pass < 2; ++pass)
        for (std::uint32_t i = 0; i < _dyld_image_count(); ++i) {
            const std::filesystem::path image = _dyld_get_image_name(i);
            if (image.parent_path() != directory && image.parent_path() != resolved) continue;
            if (image.extension() != ".prx") continue;
            if ((pass == 0) != (image.filename() == name)) continue;
            auto library = image.filename().string();
            if (const auto extension = library.rfind(".prx"); extension != std::string::npos) library.resize(extension);
            ScanImage(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i), library);
        }
}

void* Resolve(const std::string& name) {
    if (const auto found = exports.find(name); found != exports.end()) return found->second;
    if (const auto found = traps.find(name); found != traps.end()) return found->second;
    return traps.emplace(name, CreateTrap(name)).first->second;
}

std::size_t TrapCount() { return trapNames.size(); }

}
