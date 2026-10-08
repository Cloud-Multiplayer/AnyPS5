#if defined(__APPLE__)

#include <sys/mman.h>
#undef mmap
#undef mprotect
#undef munmap
#undef fcntl

#include <cstdarg>

#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include <dirent.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

extern "C" ssize_t __getdirentries64(int, void*, std::size_t, off_t*);

extern "C" {

int pthread_getattr_np(pthread_t thread, pthread_attr_t* attributes) {
    if (const int result = pthread_attr_init(attributes); result != 0) return result;
    // pthread_get_stackaddr_np returns the high end of the stack.
    const auto size = pthread_get_stacksize_np(thread);
    auto* high = static_cast<char*>(pthread_get_stackaddr_np(thread));
    return pthread_attr_setstack(attributes, high - size, size);
}

int sched_getcpu(void) { return 0; }

int Aps5MacMunmap(void* address, std::size_t bytes) {
    const int result = ::munmap(address, bytes);
    if (result == 0) Aps5MacWatchProtectionChanged(address, bytes, PROT_NONE);
    return result;
}

int Aps5MacMprotect(void* address, std::size_t bytes, int protection) {
    const int result = ::mprotect(address, bytes, protection);
    if (result == 0) Aps5MacWatchProtectionChanged(address, bytes, protection);
    return result;
}

void* Aps5MacMmap(void* address, std::size_t bytes, int protection, int flags, int descriptor, off_t offset) {
    if ((flags & MAP_FIXED_NOREPLACE) == 0) {
        void* result = ::mmap(address, bytes, protection, flags, descriptor, offset);
        // A new mapping replaces whatever the watch knew about these addresses, including its protection.
        if (result != MAP_FAILED) Aps5MacWatchProtectionChanged(result, bytes, protection);
        return result;
    }
    void* result = ::mmap(address, bytes, protection, flags & ~(MAP_FIXED_NOREPLACE | MAP_FIXED), descriptor, offset);
    if (result == address) {
        // New pages at an address the watch may still know from an earlier mapping.
        Aps5MacWatchProtectionChanged(result, bytes, protection);
        return result;
    }
    if (result == MAP_FAILED) return result;
    ::munmap(result, bytes);
    errno = EEXIST;
    return MAP_FAILED;
}

int Aps5MacFcntl(int descriptor, int command, ...) {
    if (command == F_ADD_SEALS) return 0;
    va_list arguments;
    va_start(arguments, command);
    void* argument = va_arg(arguments, void*);
    va_end(arguments);
    return ::fcntl(descriptor, command, argument);
}

int memfd_create(const char*, unsigned int) {
    char path[] = "/tmp/aps5-memfd-XXXXXX";
    const int descriptor = ::mkstemp(path);
    if (descriptor < 0) return -1;
    ::unlink(path);
    ::fcntl(descriptor, F_SETFD, FD_CLOEXEC);
    return descriptor;
}

long Aps5MacGetdents64(int descriptor, void* buffer, std::size_t bytes) {
    // A converted record is never larger than the host record it comes from (19-byte header against 21), so
    // reading at most as many host bytes as the caller has room for means every entry read is delivered.
    // That matters because macOS does not report a usable seek offset per entry (d_seekoff is zero on APFS):
    // the only position that can be resumed from is the end of what was read, and that is what d_off holds
    // for every entry.
    char host[8192];
    const std::size_t request = bytes < sizeof(host) ? bytes : sizeof(host);
    off_t start = 0;
    const auto read = __getdirentries64(descriptor, host, request, &start);
    if (read <= 0) return read;
    const auto resume = ::lseek(descriptor, 0, SEEK_CUR);
    std::size_t written = 0;
    for (ssize_t offset = 0; offset < read;) {
        const auto* entry = reinterpret_cast<const struct dirent*>(host + offset);
        if (entry->d_reclen == 0) break;
        const std::size_t length = (offsetof(dirent64, d_name) + entry->d_namlen + 1 + 7) & ~std::size_t{7};
        if (written + length > bytes) {
            errno = EINVAL;
            return -1;
        }
        auto* out = reinterpret_cast<dirent64*>(static_cast<char*>(buffer) + written);
        out->d_ino = entry->d_ino;
        out->d_off = static_cast<std::int64_t>(resume);
        out->d_reclen = static_cast<unsigned short>(length);
        out->d_type = entry->d_type;
        std::memcpy(out->d_name, entry->d_name, entry->d_namlen);
        out->d_name[entry->d_namlen] = '\0';
        written += length;
        offset += entry->d_reclen;
    }
    return static_cast<long>(written);
}

const char* Aps5MacVulkanLibrary(void) {
    const char* configured = std::getenv("SDL_VULKAN_LIBRARY");
    return configured != nullptr && configured[0] != '\0' ? configured : "libMoltenVK.dylib";
}

const char* Aps5MacProcSelfMaps(void) {
    static std::mutex mutex;
    static std::string path;
    const std::lock_guard lock(mutex);
    if (path.empty()) path = "/tmp/aps5-maps-" + std::to_string(::getpid());
    std::FILE* file = std::fopen(path.c_str(), "w");
    if (file == nullptr) return path.c_str();
    mach_vm_address_t address = 0;
    for (;;) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        if (mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info), &count, &object) != KERN_SUCCESS) break;
        // Watched pages are listed with the protection the guest set, not the watch's write protection.
        for (std::uintptr_t cursor = address, last = address + size; cursor < last;) {
            std::uintptr_t runEnd = last;
            const int watched = Aps5MacWatchLogicalProtection(cursor, last, &runEnd);
            const int protection = watched >= 0 ? watched : ((info.protection & VM_PROT_READ) ? 1 : 0) | ((info.protection & VM_PROT_WRITE) ? 2 : 0) | ((info.protection & VM_PROT_EXECUTE) ? 4 : 0);
            std::fprintf(file, "%llx-%llx %c%c%c%c %08llx 00:00 0\n", static_cast<unsigned long long>(cursor), static_cast<unsigned long long>(runEnd),
                         (protection & 1) ? 'r' : '-', (protection & 2) ? 'w' : '-', (protection & 4) ? 'x' : '-', info.shared ? 's' : 'p', static_cast<unsigned long long>(info.offset));
            cursor = runEnd;
        }
        address += size;
    }
    std::fclose(file);
    return path.c_str();
}

}

#endif
