// In-process loader for relinker Linux ELF output on macOS (x86-64, runs under Rosetta on Apple Silicon).
// It does what ld.so does on Linux: maps the executable and its bundled guest modules, applies relocations,
// binds imports and transfers control to the entry stub. Guest code is not translated or emulated here.
//
// macOS cannot set the FS segment base, and guest code reads its thread pointer through FS. Each such
// instruction is rewritten in place to read a pthread TSD slot through GS, which macOS already uses for
// thread-specific data.
#include "HostSymbols.hpp"

#include <codegen/x86/X64InstructionDecoder.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/ucontext.h>
#include <pthread/introspection.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {

struct ElfHeader {
    std::uint8_t ident[16];
    std::uint16_t type, machine;
    std::uint32_t version;
    std::uint64_t entry, phoff, shoff;
    std::uint32_t flags;
    std::uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct ProgramHeader {
    std::uint32_t type, flags;
    std::uint64_t offset, vaddr, paddr, filesz, memsz, align;
};
struct Dynamic {
    std::int64_t tag;
    std::uint64_t value;
};
struct Symbol {
    std::uint32_t name;
    std::uint8_t info, other;
    std::uint16_t shndx;
    std::uint64_t value, size;
};
struct Rela {
    std::uint64_t offset, info;
    std::int64_t addend;
};
struct TlsIndex {
    std::uint64_t module, offset;
};

constexpr std::uint32_t PtLoad = 1, PtDynamic = 2, PtTls = 7;
constexpr std::int64_t DtNeeded = 1, DtPltRelSz = 2, DtStrTab = 5, DtSymTab = 6, DtRela = 7, DtRelaSz = 8, DtInit = 12, DtJmpRel = 23;
constexpr std::uint32_t R64 = 1, RGlobDat = 6, RJumpSlot = 7, RRelative = 8, RDtpMod64 = 16, RDtpOff64 = 17, RTpOff64 = 18;
constexpr std::size_t ThreadControlBlockBytes = 0x1000;
constexpr std::size_t GuestStackGuardSlot = 0x28;

struct Module {
    std::filesystem::path path;
    std::uint8_t* base = nullptr;
    std::size_t span = 0;
    std::vector<ProgramHeader> headers;
    std::uint64_t entry = 0;
    const Symbol* symbols = nullptr;
    const char* strings = nullptr;
    std::size_t symbolCount = 0;
    std::vector<Dynamic> dynamic;
    std::unordered_map<std::string, std::uint64_t> exports;
    const std::uint8_t* tlsImage = nullptr;
    std::size_t tlsFileBytes = 0, tlsMemoryBytes = 0, tlsAlign = 1, tlsOffset = 0;
    std::size_t tlsModuleId = 0;

    std::uint64_t Tag(std::int64_t tag) const {
        for (const auto& entry : dynamic)
            if (entry.tag == tag) return entry.value;
        return 0;
    }
};

std::vector<std::unique_ptr<Module>> modules;
std::size_t staticTlsBytes = 0;
pthread_key_t threadPointerKey, stackGuardKey, scratchKey;
bool verbose = false;

[[noreturn]] void Fail(const std::string& message) {
    std::fprintf(stderr, "aps5-run: %s\n", message.c_str());
    std::exit(1);
}

std::size_t AlignUp(std::size_t value, std::size_t align) { return (value + align - 1) & ~(align - 1); }

// Thread block layout (TLS variant II): module TLS images end at the thread pointer, the control block follows.
void* CreateThreadBlock() {
    const auto tlsBytes = AlignUp(staticTlsBytes, 0x1000);
    auto* memory = static_cast<std::uint8_t*>(mmap(nullptr, tlsBytes + ThreadControlBlockBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    if (memory == MAP_FAILED) Fail("cannot allocate a guest thread block");
    auto* threadPointer = memory + tlsBytes;
    for (const auto& module : modules)
        if (module->tlsMemoryBytes != 0) std::memcpy(threadPointer - module->tlsOffset, module->tlsImage, module->tlsFileBytes);
    *reinterpret_cast<void**>(threadPointer) = threadPointer;
    return threadPointer;
}

void AttachThread() {
    if (pthread_getspecific(threadPointerKey) != nullptr) return;
    pthread_setspecific(threadPointerKey, CreateThreadBlock());
    pthread_setspecific(stackGuardKey, nullptr);
}

void ProfileTrackThread(pthread_t thread, bool alive);

pthread_introspection_hook_t previousThreadHook = nullptr;
void ThreadHook(unsigned event, pthread_t thread, void* address, std::size_t size) {
    if (event == PTHREAD_INTROSPECTION_THREAD_START && pthread_equal(thread, pthread_self())) {
        AttachThread();
        ProfileTrackThread(thread, true);
    }
    if (event == PTHREAD_INTROSPECTION_THREAD_TERMINATE) ProfileTrackThread(thread, false);
    if (previousThreadHook != nullptr) previousThreadHook(event, thread, address, size);
}

void* GuestTlsGetAddr(TlsIndex* index) {
    auto* threadPointer = static_cast<std::uint8_t*>(pthread_getspecific(threadPointerKey));
    for (const auto& module : modules)
        if (module->tlsModuleId == index->module) return threadPointer - module->tlsOffset + index->offset;
    Fail("__tls_get_addr for an unknown TLS module");
}

std::uint32_t TsdOffset(pthread_key_t key) {
    const auto offset = static_cast<std::uint64_t>(key) * 8;
    const void* marker = &key;
    pthread_setspecific(key, marker);
    void* seen = nullptr;
    __asm__ volatile("movq %%gs:(%1), %0" : "=r"(seen) : "r"(offset));
    pthread_setspecific(key, nullptr);
    if (seen != marker) Fail("pthread TSD slots are not addressable through GS on this system");
    return static_cast<std::uint32_t>(offset);
}

// mov %fs:0, %reg         64 [48|4c] 8b /r(mod=00 rm=100) 25 00000000   -> same load from the TSD slot via GS
// movl $imm32, %fs:0x28   64 c7 04 25 28000000 imm32                    -> same store into a second TSD slot
std::size_t RewriteThreadPointerAccesses(std::uint8_t* code, std::size_t bytes) {
    // APS5_LOADER_NO_FS_REWRITE=1 leaves every access to the fault fallback, which is how that path is tested.
    static const bool disabled = std::getenv("APS5_LOADER_NO_FS_REWRITE") != nullptr;
    if (disabled) return 0;
    const auto threadPointerOffset = TsdOffset(threadPointerKey);
    const auto stackGuardOffset = TsdOffset(stackGuardKey);
    std::size_t rewritten = 0;
    for (std::size_t i = 0; i + 12 <= bytes; ++i) {
        if (code[i] != 0x64) continue;
        if ((code[i + 1] == 0x48 || code[i + 1] == 0x4c) && code[i + 2] == 0x8b && (code[i + 3] & 0xc7) == 0x04 && code[i + 4] == 0x25 && std::memcmp(code + i + 5, "\0\0\0\0", 4) == 0) {
            code[i] = 0x65;
            std::memcpy(code + i + 5, &threadPointerOffset, 4);
            ++rewritten;
            i += 8;
        } else if (code[i + 1] == 0xc7 && code[i + 2] == 0x04 && code[i + 3] == 0x25 && std::memcmp(code + i + 4, "\x28\0\0\0", 4) == 0) {
            code[i] = 0x65;
            std::memcpy(code + i + 4, &stackGuardOffset, 4);
            ++rewritten;
            i += 11;
        }
    }
    return rewritten;
}

// Fallback for FS-relative instructions the load-time rewrite does not know. With no FS base the instruction
// faults; the handler decodes it at the faulting address, where the instruction boundary is certain, and
// continues in a thunk that performs the same operation relative to the thread pointer:
//
//     mov %r11, %gs:scratch      ; r10 when the instruction itself uses r11
//     mov %gs:threadPointer, %r11
//     <instruction with fs:disp32 replaced by disp32(%r11)>
//     mov %gs:scratch, %r11
//     jmp *next(%rip)
//
// The site keeps faulting on every execution, which is slow but always correct; each new site is reported
// once so its form can be added to RewriteThreadPointerAccesses.
constexpr std::size_t FsThunkBytes = 64, FsThunkCapacity = 4096;
struct FsThunk {
    std::atomic<std::uintptr_t> site{0};
    std::uint8_t* code = nullptr;
};
FsThunk fsThunks[FsThunkCapacity];
std::uint8_t* fsThunkPool = nullptr;
std::atomic<std::size_t> fsThunkCount{0};
std::atomic_flag fsThunkLock = ATOMIC_FLAG_INIT;
struct sigaction previousSegv, previousBus;

const Module* GuestCodeAt(std::uintptr_t address) {
    for (const auto& module : modules) {
        const auto base = reinterpret_cast<std::uintptr_t>(module->base);
        if (address < base || address >= base + module->span) continue;
        for (const auto& segment : module->headers)
            if (segment.type == PtLoad && (segment.flags & 1) != 0 && address - base >= segment.vaddr && address - base < segment.vaddr + segment.filesz) return module.get();
    }
    return nullptr;
}

// Returns the thunk for the FS-relative instruction at site, or null when it has no form handled here.
std::uint8_t* FsThunkFor(std::uintptr_t site) {
    for (std::size_t i = 0, count = fsThunkCount.load(std::memory_order_acquire); i < count; ++i)
        if (fsThunks[i].site.load(std::memory_order_acquire) == site) return fsThunks[i].code;
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(site);
    Codegen::DecodedInstructionInfo info{};
    try {
        info = Codegen::X64InstructionDecoder().DecodeInstruction(bytes, 15);
    } catch (...) {
        return nullptr;
    }
    const auto modrmIndex = info.OpcodeOffset + (info.IsTwoByteOpcode ? 2 : 1);
    if (info.SegmentPrefix != 0x64 || !info.HasModRm || info.Length < modrmIndex + 6 || info.Length > 15) return nullptr;
    const auto modrm = bytes[modrmIndex];
    // Absolute fs:disp32 only: mod=00, rm=100 with SIB 0x25 (no base, no index).
    if ((modrm & 0xc7) != 0x04 || bytes[modrmIndex + 1] != 0x25) return nullptr;
    const auto rex = info.RexPrefix;
    // Adding a REX prefix would turn AH/CH/DH/BH operands into SPL/BPL/SIL/DIL.
    const bool byteOperand = !info.IsTwoByteOpcode && (bytes[info.OpcodeOffset] & 1) == 0 && bytes[info.OpcodeOffset] < 0xc0;
    if (rex == 0 && byteOperand && ((modrm >> 3) & 7) >= 4) return nullptr;
    const unsigned operandRegister = ((modrm >> 3) & 7) | ((rex & 4) != 0 ? 8u : 0u);
    const std::uint8_t scratch = operandRegister == 11 ? 2 : 3;  // low three bits of r10 or r11

    while (fsThunkLock.test_and_set(std::memory_order_acquire)) {}
    const auto index = fsThunkCount.load(std::memory_order_relaxed);
    if (index == FsThunkCapacity) {
        fsThunkLock.clear(std::memory_order_release);
        return nullptr;
    }
    auto* code = fsThunkPool + index * FsThunkBytes;
    auto* out = code;
    const auto emit = [&](std::initializer_list<std::uint8_t> values) { for (const auto value : values) *out++ = value; };
    const auto emit32 = [&](std::uint32_t value) { std::memcpy(out, &value, 4); out += 4; };
    const auto gsAccess = [&](std::uint8_t opcode, pthread_key_t key) {
        emit({0x65, 0x4c, opcode, static_cast<std::uint8_t>(0x04 | (scratch << 3)), 0x25});
        emit32(static_cast<std::uint32_t>(key) * 8);
    };
    gsAccess(0x89, scratchKey);
    gsAccess(0x8b, threadPointerKey);
    const auto prefixEnd = info.OpcodeOffset - (rex != 0 ? 1 : 0);
    for (std::size_t i = 0; i < prefixEnd; ++i)
        if (bytes[i] != 0x64) *out++ = bytes[i];
    *out++ = static_cast<std::uint8_t>((rex != 0 ? rex : 0x40) | 0x01);
    for (std::size_t i = info.OpcodeOffset; i < modrmIndex; ++i) *out++ = bytes[i];
    *out++ = static_cast<std::uint8_t>(0x80 | (modrm & 0x38) | scratch);
    for (std::size_t i = modrmIndex + 2; i < info.Length; ++i) *out++ = bytes[i];
    gsAccess(0x8b, scratchKey);
    emit({0xff, 0x25, 0, 0, 0, 0});
    const std::uint64_t next = site + info.Length;
    std::memcpy(out, &next, 8);
    fsThunks[index].code = code;
    fsThunks[index].site.store(site, std::memory_order_release);
    fsThunkCount.store(index + 1, std::memory_order_release);
    fsThunkLock.clear(std::memory_order_release);

    char text[160];
    int length = std::snprintf(text, sizeof(text), "aps5-run: FS access not rewritten at load, emulated on each use: %s+0x%zx:", GuestCodeAt(site)->path.filename().c_str(), static_cast<std::size_t>(site - reinterpret_cast<std::uintptr_t>(GuestCodeAt(site)->base)));
    for (std::size_t i = 0; i < info.Length && length < static_cast<int>(sizeof(text)) - 4; ++i) length += std::snprintf(text + length, sizeof(text) - length, " %02x", bytes[i]);
    text[length++] = '\n';
    write(STDERR_FILENO, text, length);
    return code;
}

void GuestFault(int signal, siginfo_t* info, void* context) {
    auto& state = static_cast<ucontext_t*>(context)->uc_mcontext->__ss;
    if (GuestCodeAt(state.__rip) != nullptr)
        if (auto* thunk = FsThunkFor(state.__rip)) {
            state.__rip = reinterpret_cast<std::uintptr_t>(thunk);
            return;
        }
    const auto& previous = signal == SIGBUS ? previousBus : previousSegv;
    if ((previous.sa_flags & SA_SIGINFO) != 0 && previous.sa_sigaction != nullptr) return previous.sa_sigaction(signal, info, context);
    ::signal(signal, SIG_DFL);
}

void InstallGuestFaultHandler() {
    fsThunkPool = static_cast<std::uint8_t*>(mmap(nullptr, FsThunkBytes * FsThunkCapacity, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0));
    if (fsThunkPool == MAP_FAILED) Fail("cannot allocate FS access thunks");
    struct sigaction action {};
    action.sa_sigaction = &GuestFault;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, &previousSegv) != 0 || sigaction(SIGBUS, &action, &previousBus) != 0) Fail("cannot install the guest fault handler");
}

Module* Load(const std::filesystem::path& path) {
    for (const auto& module : modules)
        if (module->path == path) return module.get();
    std::ifstream stream(path, std::ios::binary);
    if (!stream) Fail("cannot open " + path.string());
    const std::vector<char> file((std::istreambuf_iterator<char>(stream)), {});
    const auto need = [&](std::size_t offset, std::size_t bytes) {
        if (offset > file.size() || bytes > file.size() - offset) Fail("truncated ELF " + path.string());
    };
    need(0, sizeof(ElfHeader));
    const auto* header = reinterpret_cast<const ElfHeader*>(file.data());
    if (std::memcmp(header->ident, "\x7f" "ELF\x02\x01", 6) != 0 || header->machine != 62 || header->phentsize != sizeof(ProgramHeader)) Fail("not an x86-64 ELF: " + path.string());
    need(header->phoff, std::size_t{header->phnum} * sizeof(ProgramHeader));

    auto module = std::make_unique<Module>();
    module->path = path;
    module->headers.assign(reinterpret_cast<const ProgramHeader*>(file.data() + header->phoff), reinterpret_cast<const ProgramHeader*>(file.data() + header->phoff) + header->phnum);
    std::uint64_t low = UINT64_MAX, high = 0;
    for (const auto& segment : module->headers)
        if (segment.type == PtLoad) {
            low = std::min(low, segment.vaddr & ~std::uint64_t{0xfff});
            high = std::max<std::uint64_t>(high, AlignUp(segment.vaddr + segment.memsz, 0x1000));
        }
    if (low != 0) Fail("ELF is not position independent with a zero base: " + path.string());
    module->span = high;
    // Guest code assumes the console's 16 KiB pages: the base must honour the segment alignment, which is
    // larger than the host page.
    std::uint64_t alignment = 0x1000;
    for (const auto& segment : module->headers)
        if (segment.type == PtLoad) alignment = std::max<std::uint64_t>(alignment, segment.align);
    auto* reservation = static_cast<std::uint8_t*>(mmap(nullptr, module->span + alignment, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0));
    if (reservation == MAP_FAILED) Fail("cannot reserve address space for " + path.string());
    module->base = reinterpret_cast<std::uint8_t*>(AlignUp(reinterpret_cast<std::uintptr_t>(reservation), alignment));
    if (module->base != reservation) munmap(reservation, module->base - reservation);
    munmap(module->base + module->span, reservation + module->span + alignment - (module->base + module->span));
    for (const auto& segment : module->headers) {
        if (segment.type != PtLoad) continue;
        need(segment.offset, segment.filesz);
        const auto start = segment.vaddr & ~std::uint64_t{0xfff};
        const auto end = AlignUp(segment.vaddr + segment.memsz, 0x1000);
        // Writable while relocations and rewrites are applied; final protections are set in Protect().
        if (mprotect(module->base + start, end - start, PROT_READ | PROT_WRITE) != 0) Fail("cannot map a segment of " + path.string());
        std::memcpy(module->base + segment.vaddr, file.data() + segment.offset, segment.filesz);
    }
    module->entry = header->entry;
    for (const auto& segment : module->headers) {
        if (segment.type == PtDynamic) {
            const auto* entry = reinterpret_cast<const Dynamic*>(module->base + segment.vaddr);
            for (std::size_t i = 0; i < segment.memsz / sizeof(Dynamic) && entry[i].tag != 0; ++i) module->dynamic.push_back(entry[i]);
        } else if (segment.type == PtTls && segment.memsz != 0) {
            module->tlsImage = module->base + segment.vaddr;
            module->tlsFileBytes = segment.filesz;
            module->tlsMemoryBytes = segment.memsz;
            module->tlsAlign = std::max<std::size_t>(segment.align, 1);
        }
    }
    module->strings = reinterpret_cast<const char*>(module->base + module->Tag(DtStrTab));
    module->symbols = reinterpret_cast<const Symbol*>(module->base + module->Tag(DtSymTab));
    // The relinker places the string table directly after the symbol table's users; the symbol count is not
    // recorded, so it is bounded by the highest index a relocation uses plus the defined symbols before it.
    const auto scan = [&](std::int64_t table, std::int64_t size) {
        const auto* rela = reinterpret_cast<const Rela*>(module->base + module->Tag(table));
        for (std::size_t i = 0; i < module->Tag(size) / sizeof(Rela); ++i) module->symbolCount = std::max<std::size_t>(module->symbolCount, (rela[i].info >> 32) + 1);
    };
    if (module->Tag(DtRela) != 0) scan(DtRela, DtRelaSz);
    if (module->Tag(DtJmpRel) != 0) scan(DtJmpRel, DtPltRelSz);
    if (module->Tag(DtStrTab) > module->Tag(DtSymTab)) module->symbolCount = std::max<std::size_t>(module->symbolCount, (module->Tag(DtStrTab) - module->Tag(DtSymTab)) / sizeof(Symbol));
    for (std::size_t i = 1; i < module->symbolCount; ++i)
        if (module->symbols[i].shndx != 0 && module->symbols[i].name != 0) module->exports.emplace(module->strings + module->symbols[i].name, module->symbols[i].value);
    if (module->tlsMemoryBytes != 0) {
        staticTlsBytes = AlignUp(staticTlsBytes + module->tlsMemoryBytes, module->tlsAlign);
        module->tlsOffset = staticTlsBytes;
        module->tlsModuleId = modules.size() + 1;
    }
    auto* loaded = module.get();
    modules.push_back(std::move(module));
    if (verbose && !loaded->exports.empty()) std::fprintf(stderr, "aps5-run: first export %s\n", loaded->exports.begin()->first.c_str());
    if (verbose) std::fprintf(stderr, "aps5-run: mapped %s at %p (+0x%zx), %zu symbols, %zu exports, tls %zu bytes\n", path.filename().c_str(), static_cast<void*>(loaded->base), loaded->span, loaded->symbolCount, loaded->exports.size(), loaded->tlsMemoryBytes);

    const auto origin = modules.front()->path.parent_path();
    for (const auto& entry : loaded->dynamic) {
        if (entry.tag != DtNeeded) continue;
        const std::string name = loaded->strings + entry.value;
        if (name.rfind("$ORIGIN/", 0) == 0) Load(origin / name.substr(8));
        else if (name.find("ld-linux") == std::string::npos) HostSymbols::LoadLibrary(origin / "libs", name);
    }
    return loaded;
}

void* Resolve(const Module& module, const std::string& name) {
    // Same order as the ELF global scope: bundled guest modules first, then the native system libraries.
    for (const auto& other : modules)
        if (other.get() != &module)
            if (const auto found = other->exports.find(name); found != other->exports.end()) return other->base + found->second;
    if (name == "__tls_get_addr") return reinterpret_cast<void*>(&GuestTlsGetAddr);
    return HostSymbols::Resolve(name);
}

void Relocate(Module& module) {
    const auto apply = [&](std::int64_t table, std::int64_t size) {
        const auto* rela = reinterpret_cast<const Rela*>(module.base + module.Tag(table));
        for (std::size_t i = 0; i < module.Tag(size) / sizeof(Rela); ++i) {
            const auto type = static_cast<std::uint32_t>(rela[i].info);
            const auto index = rela[i].info >> 32;
            auto* target = reinterpret_cast<std::uint64_t*>(module.base + rela[i].offset);
            std::uint64_t value = 0;
            if (index != 0) {
                const auto& symbol = module.symbols[index];
                value = symbol.shndx != 0 ? reinterpret_cast<std::uint64_t>(module.base + symbol.value) : reinterpret_cast<std::uint64_t>(Resolve(module, module.strings + symbol.name));
            }
            switch (type) {
                case RRelative: *target = reinterpret_cast<std::uint64_t>(module.base) + rela[i].addend; break;
                case R64: *target = value + rela[i].addend; break;
                case RGlobDat:
                case RJumpSlot: *target = value; break;
                case RDtpMod64: *target = module.tlsModuleId; break;
                case RDtpOff64: *target = (index != 0 ? module.symbols[index].value : 0) + rela[i].addend; break;
                case RTpOff64: *target = (index != 0 ? module.symbols[index].value : 0) + rela[i].addend - module.tlsOffset; break;
                default: Fail("unsupported relocation type " + std::to_string(type) + " in " + module.path.string());
            }
        }
    };
    if (module.Tag(DtRela) != 0) apply(DtRela, DtRelaSz);
    if (module.Tag(DtJmpRel) != 0) apply(DtJmpRel, DtPltRelSz);
}

void Protect(Module& module) {
    std::size_t rewritten = 0;
    for (const auto& segment : module.headers)
        if (segment.type == PtLoad && (segment.flags & 1) != 0) rewritten += RewriteThreadPointerAccesses(module.base + segment.vaddr, segment.filesz);
    for (const auto& segment : module.headers) {
        if (segment.type != PtLoad) continue;
        const auto start = segment.vaddr & ~std::uint64_t{0xfff};
        const auto end = AlignUp(segment.vaddr + segment.memsz, 0x1000);
        const int protection = ((segment.flags & 4) != 0 ? PROT_READ : 0) | ((segment.flags & 2) != 0 ? PROT_WRITE : 0) | ((segment.flags & 1) != 0 ? PROT_EXEC : 0);
        if (mprotect(module.base + start, end - start, protection) != 0) Fail("cannot set segment protection in " + module.path.string() + ": " + std::strerror(errno));
    }
    if (verbose) std::fprintf(stderr, "aps5-run: %s: %zu thread pointer accesses rewritten\n", module.path.filename().c_str(), rewritten);
}

[[noreturn]] void Enter(void* entry, char** arguments, int count) {
    // The entry stub takes the address of a System V process stack image (argc, argv, envp, auxv) in RSP.
    // The image lives on this thread's own stack, so the guest keeps running within the stack bounds the
    // native libraries query for the thread.
    alignas(16) std::uint64_t image[64] = {};
    if (count > 56) Fail("too many arguments");
    image[0] = static_cast<std::uint64_t>(count);
    for (int i = 0; i < count; ++i) image[1 + i] = reinterpret_cast<std::uint64_t>(arguments[i]);
    __asm__ volatile("movq %0, %%rsp\n xorl %%ebp, %%ebp\n jmpq *%1" : : "r"(&image[0]), "r"(entry) : "memory");
    __builtin_unreachable();
}

// AppKit only accepts window and event work on the process main thread, and the guest creates its window
// from a thread of its own. The guest therefore runs on a second thread and the main thread serves the
// tasks the native libraries hand it.
struct MainThreadTask {
    void (*function)(void*);
    void* context;
};
pthread_mutex_t mainThreadMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t mainThreadChanged = PTHREAD_COND_INITIALIZER;
std::vector<MainThreadTask> mainThreadTasks;

struct GuestStart {
    Module* executable;
    char** arguments;
    int count;
};

void* GuestMain(void* data) {
    const auto start = *static_cast<GuestStart*>(data);
    for (std::size_t i = modules.size(); i-- > 1;)
        if (const auto initializer = modules[i]->Tag(DtInit); initializer != 0) reinterpret_cast<void (*)()>(modules[i]->base + initializer)();
    if (verbose) std::fprintf(stderr, "aps5-run: entering %s at %p\n", start.executable->path.filename().c_str(), static_cast<void*>(start.executable->base + start.executable->entry));
    Enter(start.executable->base + start.executable->entry, start.arguments, start.count);
}

}

// glibc entry points the native system libraries call to inspect guest modules. Native Mach-O images are
// not reported: only the ELF modules mapped here have program headers.
namespace {
struct LinkMap {
    std::uintptr_t address;
    char* name;
    void* dynamic;
    LinkMap* next;
    LinkMap* previous;
};
struct ProgramHeaderInfo {
    std::uintptr_t address;
    const char* name;
    const ProgramHeader* headers;
    std::uint16_t count;
    unsigned long long adds, subs;
    std::size_t tlsModule;
    void* tlsData;
};
}

extern "C" {

// Queues a task for the process main thread and returns immediately. A task may run for the rest of the
// process lifetime (the presentation loop does).
__attribute__((visibility("default"))) void Aps5MacRunOnMainThread(void (*function)(void*), void* context) {
    pthread_mutex_lock(&mainThreadMutex);
    mainThreadTasks.push_back({function, context});
    pthread_cond_signal(&mainThreadChanged);
    pthread_mutex_unlock(&mainThreadMutex);
}

// Called by the system libraries' dl_iterate_phdr (libc/src/specifics/macos/GuestImages.cpp).
__attribute__((visibility("default"))) int Aps5LoaderIteratePhdr(int (*callback)(ProgramHeaderInfo*, std::size_t, void*), void* data) {
    for (const auto& module : modules) {
        // glibc reports the main executable with an empty name; callers rely on that to find it.
        ProgramHeaderInfo info{reinterpret_cast<std::uintptr_t>(module->base), module == modules.front() ? "" : module->path.c_str(), module->headers.data(), static_cast<std::uint16_t>(module->headers.size()), modules.size(), 0, module->tlsModuleId, nullptr};
        if (const int result = callback(&info, sizeof(info), data); result != 0) return result;
    }
    return 0;
}

__attribute__((visibility("default"))) int dladdr1(const void* address, Dl_info* info, void** extra, int) {
    static std::unordered_map<const Module*, LinkMap> maps;
    for (const auto& module : modules) {
        const auto* pointer = static_cast<const std::uint8_t*>(address);
        if (pointer < module->base || pointer >= module->base + module->span) continue;
        if (info != nullptr) *info = Dl_info{module->path.c_str(), module->base, nullptr, nullptr};
        if (extra != nullptr) {
            auto& map = maps[module.get()];
            map.address = reinterpret_cast<std::uintptr_t>(module->base);
            map.name = const_cast<char*>(module->path.c_str());
            for (const auto& segment : module->headers)
                if (segment.type == PtDynamic) map.dynamic = module->base + segment.vaddr;
            *extra = &map;
        }
        return 1;
    }
    return 0;
}

}

namespace {
// An exception that reaches guest frames cannot be unwound further by the system runtime, so it ends here
// with the native part of the stack still intact.
[[noreturn]] void ReportTermination() {
    if (const auto current = std::current_exception()) {
        try {
            std::rethrow_exception(current);
        } catch (const std::exception& error) {
            std::fprintf(stderr, "aps5-run: unhandled native exception: %s\n", error.what());
        } catch (...) {
            std::fprintf(stderr, "aps5-run: unhandled native exception of unknown type\n");
        }
    }
    void* frames[48];
    const int depth = backtrace(frames, 48);
    for (int i = 0; i < depth; ++i) {
        Dl_info info{};
        const Module* guest = nullptr;
        for (const auto& module : modules)
            if (static_cast<std::uint8_t*>(frames[i]) >= module->base && static_cast<std::uint8_t*>(frames[i]) < module->base + module->span) guest = module.get();
        if (guest != nullptr) std::fprintf(stderr, "  #%d guest %s+0x%tx\n", i, guest->path.filename().c_str(), static_cast<std::uint8_t*>(frames[i]) - guest->base);
        else if (dladdr(frames[i], &info) != 0 && info.dli_sname != nullptr) std::fprintf(stderr, "  #%d %s %s+0x%tx\n", i, std::filesystem::path(info.dli_fname).filename().c_str(), info.dli_sname, static_cast<char*>(frames[i]) - static_cast<char*>(info.dli_saddr));
        else std::fprintf(stderr, "  #%d %p\n", i, frames[i]);
    }
    std::_Exit(134);
}
}

namespace {
// APS5_LOADER_PROFILE=<seconds>: wall-clock sampling profiler. A sampler thread signals every thread in turn
// and the handler records where it was, so blocking calls show up as well as computation. External samplers
// cannot walk a Rosetta-translated process.
constexpr std::size_t ProfileCapacity = 1 << 19;
struct ProfileSample {
    std::uintptr_t pc;
    pthread_t thread;
};
ProfileSample profileSamples[ProfileCapacity];
std::atomic<std::size_t> profileCount{0};
pthread_mutex_t profileThreadsMutex = PTHREAD_MUTEX_INITIALIZER;
std::vector<pthread_t> profileThreads;
std::atomic<bool> profiling{false};

void ProfileSignal(int, siginfo_t*, void* context) {
    const auto index = profileCount.fetch_add(1, std::memory_order_relaxed);
    if (index < ProfileCapacity) profileSamples[index] = {static_cast<ucontext_t*>(context)->uc_mcontext->__ss.__rip, pthread_self()};
}

void ProfileTrackThread(pthread_t thread, bool alive) {
    if (!profiling.load(std::memory_order_relaxed)) return;
    pthread_mutex_lock(&profileThreadsMutex);
    if (alive) profileThreads.push_back(thread);
    else profileThreads.erase(std::remove(profileThreads.begin(), profileThreads.end(), thread), profileThreads.end());
    pthread_mutex_unlock(&profileThreadsMutex);
}

std::string ProfileSymbol(std::uintptr_t pc) {
    for (const auto& module : modules)
        if (pc >= reinterpret_cast<std::uintptr_t>(module->base) && pc < reinterpret_cast<std::uintptr_t>(module->base) + module->span) {
            char text[32];
            std::snprintf(text, sizeof(text), "+0x%zx", static_cast<std::size_t>((pc - reinterpret_cast<std::uintptr_t>(module->base)) & ~std::uintptr_t{0xfff}));
            return "guest " + module->path.filename().string() + text;
        }
    Dl_info info{};
    if (dladdr(reinterpret_cast<void*>(pc), &info) != 0) return std::filesystem::path(info.dli_fname).filename().string() + " " + (info.dli_sname != nullptr ? info.dli_sname : "?");
    return "?";
}

void* ProfileSampler(void* data) {
    const auto seconds = static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(data));
    const auto self = pthread_self();
    for (unsigned tick = 0; tick < seconds * 500; ++tick) {
        usleep(2000);
        pthread_mutex_lock(&profileThreadsMutex);
        for (const auto thread : profileThreads)
            if (!pthread_equal(thread, self)) pthread_kill(thread, SIGPROF);
        pthread_mutex_unlock(&profileThreadsMutex);
    }
    profiling = false;
    usleep(50000);
    const auto total = std::min(profileCount.load(), ProfileCapacity);
    std::unordered_map<pthread_t, std::unordered_map<std::string, std::size_t>> byThread;
    std::unordered_map<pthread_t, std::size_t> threadTotals;
    for (std::size_t i = 0; i < total; ++i) {
        ++byThread[profileSamples[i].thread][ProfileSymbol(profileSamples[i].pc)];
        ++threadTotals[profileSamples[i].thread];
    }
    std::fprintf(stderr, "aps5-run profile: %zu samples, %zu threads\n", total, byThread.size());
    for (const auto& [thread, counts] : byThread) {
        std::vector<std::pair<std::size_t, std::string>> sorted;
        for (const auto& [name, hits] : counts) sorted.emplace_back(hits, name);
        std::sort(sorted.rbegin(), sorted.rend());
        // A thread that only ever waits in one place is not interesting.
        if (sorted.empty() || sorted[0].first * 100 >= threadTotals[thread] * 97) continue;
        char name[64] = "";
        pthread_getname_np(thread, name, sizeof(name));
        std::fprintf(stderr, " thread %p \"%s\" (%zu samples)\n", static_cast<void*>(thread), name, threadTotals[thread]);
        for (std::size_t i = 0; i < std::min<std::size_t>(14, sorted.size()); ++i) std::fprintf(stderr, "  %5.1f%%  %s\n", 100.0 * sorted[i].first / threadTotals[thread], sorted[i].second.c_str());
    }
    return nullptr;
}

void StartProfile(unsigned seconds) {
    struct sigaction action {};
    action.sa_sigaction = &ProfileSignal;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGPROF, &action, nullptr);
    profiling = true;
    ProfileTrackThread(pthread_self(), true);
    pthread_t sampler;
    pthread_create(&sampler, nullptr, &ProfileSampler, reinterpret_cast<void*>(static_cast<std::uintptr_t>(seconds)));
}
}

int main(int count, char** arguments) {
    verbose = std::getenv("APS5_LOADER_VERBOSE") != nullptr;
    std::set_terminate(&ReportTermination);
    if (count < 2) Fail("usage: aps5-run <relinked app.elf> [arguments]");
    if (pthread_key_create(&threadPointerKey, nullptr) != 0 || pthread_key_create(&stackGuardKey, nullptr) != 0 || pthread_key_create(&scratchKey, nullptr) != 0) Fail("cannot create thread-specific slots");
    // Before the system libraries load: their write watch installs its own handler and passes on what it
    // does not own.
    InstallGuestFaultHandler();
    // SDL and the graphics driver load the Vulkan implementation named here. MoltenVK ships beside the system
    // libraries; an explicit setting wins.
    if (const auto bundled = std::filesystem::absolute(arguments[1]).parent_path() / "libs" / "libMoltenVK.dylib"; std::filesystem::exists(bundled)) setenv("SDL_VULKAN_LIBRARY", bundled.c_str(), 0);
    auto* executable = Load(std::filesystem::absolute(arguments[1]));
    for (auto& module : modules) Relocate(*module);
    for (auto& module : modules) Protect(*module);
    AttachThread();
    previousThreadHook = pthread_introspection_hook_install(&ThreadHook);
    if (verbose) std::fprintf(stderr, "aps5-run: %zu imports have no native implementation\n", HostSymbols::TrapCount());

    if (const char* seconds = std::getenv("APS5_LOADER_PROFILE")) StartProfile(static_cast<unsigned>(std::max(1, std::atoi(seconds))));
    static GuestStart start;
    start = {executable, arguments + 1, count - 1};
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setstacksize(&attributes, std::size_t{64} << 20);
    pthread_t guest;
    if (pthread_create(&guest, &attributes, &GuestMain, &start) != 0) Fail("cannot create the guest main thread");
    pthread_setname_np("aps5-run host main");
    for (;;) {
        pthread_mutex_lock(&mainThreadMutex);
        while (mainThreadTasks.empty()) pthread_cond_wait(&mainThreadChanged, &mainThreadMutex);
        const auto task = mainThreadTasks.front();
        mainThreadTasks.erase(mainThreadTasks.begin());
        pthread_mutex_unlock(&mainThreadMutex);
        task.function(task.context);
    }
}
