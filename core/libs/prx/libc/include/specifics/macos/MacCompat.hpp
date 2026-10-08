// Force-included into every system library translation unit on macOS. Supplies the glibc/libstdc++ pieces
// the POSIX code paths were written against, so those paths compile unchanged.
#ifndef PRX_LIBC_INCLUDE_SPECIFICS_MACOS_MACCOMPAT_HPP
#define PRX_LIBC_INCLUDE_SPECIFICS_MACOS_MACCOMPAT_HPP
#if defined(__APPLE__) && defined(__cplusplus)

#include <cstddef>
#include <cstdint>
#include <cxxabi.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <typeinfo>

extern "C" {

// glibc: stack of a running thread as a pthread attribute.
int pthread_getattr_np(pthread_t thread, pthread_attr_t* attributes);
// macOS does not expose the current processor; reports 0.
int sched_getcpu(void);

// Linux getdents64 record layout, filled from getdirentries by Aps5MacGetdents64.
struct dirent64 {
    std::uint64_t d_ino;
    std::int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
};
long Aps5MacGetdents64(int descriptor, void* buffer, std::size_t bytes);

// Linux mmap flag: map at exactly this address or fail, never replacing an existing mapping. Emulated by
// mapping with the address as a hint and rejecting any other placement.
#define MAP_FIXED_NOREPLACE 0x40000000
void* Aps5MacMmap(void* address, std::size_t bytes, int protection, int flags, int descriptor, off_t offset);

int Aps5MacMprotect(void* address, std::size_t bytes, int protection);
int Aps5MacMunmap(void* address, std::size_t bytes);
// Write watch hooks (libc/src/specifics/macos/MacWriteWatch.inl). A watched page is write-protected, and a
// system call writing into it would fail with EFAULT instead of faulting: GuestArena::HostWrite brackets
// such calls with Begin/EndHostWrite.
void Aps5MacWatchProtectionChanged(void* address, std::size_t bytes, int protection);
void Aps5MacBeginHostWrite(void* address, std::size_t bytes);
void Aps5MacEndHostWrite(void* address, std::size_t bytes);
// Protection the guest set on a watched page (PROT_* bits), or -1 when the address is not watched. A watched
// page is really read-only between a collection and the next write, so code that asks the kernel for a
// page's protection has to ask here first. runEnd receives the end of the run sharing the answer, at most
// limit: equal protection when watched, the next watched page when not.
int Aps5MacWatchLogicalProtection(std::uintptr_t address, std::uintptr_t limit, std::uintptr_t* runEnd);

// Linux anonymous memory file. Backed by an unlinked temporary file.
#define MFD_CLOEXEC 1u
// File sealing does not exist on macOS. The flag and the seal request are accepted and do nothing: the
// seals only guard the backing file against resizing by other holders of the descriptor, and nothing else
// holds it here.
#define MFD_ALLOW_SEALING 2u
#define F_ADD_SEALS 0x7fff0409
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
int Aps5MacFcntl(int descriptor, int command, ...);
int memfd_create(const char* name, unsigned int flags);

// Provided by core/macos/loader: queues a task for the process main thread, the only thread AppKit accepts
// window and event work on. Returns immediately.
void Aps5MacRunOnMainThread(void (*function)(void*), void* context);

// Vulkan implementation to load: SDL_VULKAN_LIBRARY when set (the loader points it at the MoltenVK beside the
// system libraries), otherwise the MoltenVK dylib by name.
const char* Aps5MacVulkanLibrary(void);

// Writes the address space in /proc/self/maps format to a temporary file and returns its path.
const char* Aps5MacProcSelfMaps(void);

}

#define mmap Aps5MacMmap
#define fcntl Aps5MacFcntl
#define mprotect Aps5MacMprotect
#define munmap Aps5MacMunmap

// Per-thread usage is not available through getrusage on macOS; process usage is reported instead.
#ifndef RUSAGE_THREAD
#define RUSAGE_THREAD RUSAGE_SELF
#endif

// libc++ does not implement std::atomic<std::shared_ptr<T>> (C++20). A small lock per object gives the same
// observable behaviour; libstdc++ also locks internally.
#include <atomic>
#include <memory>
#if defined(_LIBCPP_VERSION) && !defined(__cpp_lib_atomic_shared_ptr)
namespace std {
template <class T>
struct atomic<shared_ptr<T>> {
    constexpr atomic() noexcept = default;
    atomic(shared_ptr<T> desired) noexcept : _value(std::move(desired)) {}
    atomic(const atomic&) = delete;
    void operator=(const atomic&) = delete;
    bool is_lock_free() const noexcept { return false; }
    shared_ptr<T> load(memory_order = memory_order_seq_cst) const noexcept {
        Guard guard(_lock);
        return _value;
    }
    operator shared_ptr<T>() const noexcept { return load(); }
    void store(shared_ptr<T> desired, memory_order = memory_order_seq_cst) noexcept {
        Guard guard(_lock);
        _value.swap(desired);
    }
    void operator=(shared_ptr<T> desired) noexcept { store(std::move(desired)); }
    shared_ptr<T> exchange(shared_ptr<T> desired, memory_order = memory_order_seq_cst) noexcept {
        Guard guard(_lock);
        _value.swap(desired);
        return desired;
    }
    bool compare_exchange_strong(shared_ptr<T>& expected, shared_ptr<T> desired, memory_order = memory_order_seq_cst, memory_order = memory_order_seq_cst) noexcept {
        Guard guard(_lock);
        if (_value == expected && !_value.owner_before(expected) && !expected.owner_before(_value)) {
            _value.swap(desired);
            return true;
        }
        expected = _value;
        return false;
    }
    bool compare_exchange_weak(shared_ptr<T>& expected, shared_ptr<T> desired, memory_order success = memory_order_seq_cst, memory_order failure = memory_order_seq_cst) noexcept {
        return compare_exchange_strong(expected, std::move(desired), success, failure);
    }

private:
    struct Guard {
        explicit Guard(atomic_flag& flag) noexcept : _flag(flag) {
            while (_flag.test_and_set(memory_order_acquire)) {}
        }
        ~Guard() { _flag.clear(memory_order_release); }
        atomic_flag& _flag;
    };
    mutable atomic_flag _lock = ATOMIC_FLAG_INIT;
    shared_ptr<T> _value;
};
}
#endif

#endif
#endif
