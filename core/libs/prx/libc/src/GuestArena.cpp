#include "prx/libc/include/GuestArena.hpp"
#include "prx/libc/include/WindowsMappings.hpp"
#include <algorithm>
#include <cerrno>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace GuestArena {
namespace {

#ifdef _WIN32
std::atomic<std::uint64_t> commitGeneration{1};
std::atomic<void (*)(std::uintptr_t, std::size_t, std::uint64_t)> privateMappingObserver{nullptr};
#endif

constexpr std::uintptr_t DefaultArenaStart = 0x0000000200000000ull;
// Upstream #652 reserves through the application map area end (1008 GiB).
// The size is that end minus the 8 GiB base. APS5_GUEST_ARENA_* can shrink
// and shift the window: the qualified iPad profile is base 0x7400000000,
// size 4 GiB, chunk 256 MiB, lazy. iOS extended virtual addressing is about
// 512 GiB and cannot hold the full span. Fixed mappings outside the
// configured window fail. Windows startup stacks stay below 0x200000000
// (the PE clears HIGH_ENTROPY_VA), which is also below a shifted iPad base.
constexpr std::uintptr_t ApplicationAreaEnd = 0x000000FC00000000ull;
constexpr std::size_t DefaultArenaSize = static_cast<std::size_t>(ApplicationAreaEnd - DefaultArenaStart);
constexpr std::size_t DefaultChunk = 0x0000000010000000ull;
constexpr std::uintptr_t SystemReservedStart = 0x00000007FFFFC000ull;
constexpr std::uintptr_t SystemReservedEnd = 0x0000001000000000ull;

std::uintptr_t alignUp(std::uintptr_t value, std::size_t alignment) {
    if (value > std::numeric_limits<std::uintptr_t>::max() - (alignment - 1))
        throw std::overflow_error("guest arena alignment overflows");
    return (value + alignment - 1) & ~(static_cast<std::uintptr_t>(alignment) - 1);
}

std::uint64_t parseUnsigned(const char* text, const char* what) {
    if (!text || !*text || *text == '-' || *text == '+' || std::strchr(" \t\r\n", *text)) throw std::invalid_argument(what);
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 0);
    if (end == text || *end || errno == ERANGE) throw std::invalid_argument(what);
    return static_cast<std::uint64_t>(value);
}

struct ArenaLimits {
    std::uintptr_t base;
    std::size_t size;
    std::size_t chunk;
    bool lazy;
};

// APS5_GUEST_ARENA_BASE / _SIZE / _CHUNK override the default window.
// APS5_GUEST_ARENA_LAZY=1 reserves host VA in chunks on first use instead of
// the whole span at startup.
ArenaLimits ReadArenaLimits() {
    ArenaLimits limits{DefaultArenaStart, DefaultArenaSize, DefaultChunk, false};
    if (const char* base = std::getenv("APS5_GUEST_ARENA_BASE")) {
        const auto value = parseUnsigned(base, "invalid APS5_GUEST_ARENA_BASE");
        if (value == 0) throw std::invalid_argument("invalid APS5_GUEST_ARENA_BASE");
        limits.base = static_cast<std::uintptr_t>(value);
    }
    if (const char* size = std::getenv("APS5_GUEST_ARENA_SIZE")) {
        const auto value = parseUnsigned(size, "invalid APS5_GUEST_ARENA_SIZE");
        if (value == 0) throw std::invalid_argument("invalid APS5_GUEST_ARENA_SIZE");
        limits.size = static_cast<std::size_t>(value);
    }
    if (const char* chunk = std::getenv("APS5_GUEST_ARENA_CHUNK")) {
        const auto value = parseUnsigned(chunk, "invalid APS5_GUEST_ARENA_CHUNK");
        if (value < 0x10000 || (value & (value - 1)) != 0) throw std::invalid_argument("APS5_GUEST_ARENA_CHUNK must be a power of two and at least 64 KiB");
        limits.chunk = static_cast<std::size_t>(value);
    }
    if (const char* lazy = std::getenv("APS5_GUEST_ARENA_LAZY")) limits.lazy = std::strcmp(lazy, "1") == 0;
    if ((limits.base & (limits.chunk - 1)) != 0 || (limits.size & (limits.chunk - 1)) != 0)
        throw std::invalid_argument("guest arena base and size must be multiples of the chunk");
    if (limits.size > std::numeric_limits<std::uintptr_t>::max() - limits.base) throw std::invalid_argument("guest arena range overflows");
    return limits;
}

class Arena {
public:
    static Arena& Get() {
        static Arena arena;
        return arena;
    }

    bool Available() const {
        return _base != 0;
    }

    bool Contains(const void* pointer, std::size_t bytes) const {
        const auto address = reinterpret_cast<std::uintptr_t>(pointer);
        return _base != 0 && address >= _base && bytes <= _end - _base && address - _base <= (_end - _base) - bytes;
    }

    void* Allocate(std::size_t bytes, std::size_t alignment) {
        return AllocateAtOrAbove(0, bytes, alignment);
    }

    void* AllocateAtOrAbove(std::uintptr_t hint, std::size_t bytes, std::size_t alignment) {
        if (_base == 0) throw std::runtime_error("guest address space arena is unavailable");
        if (bytes == 0) throw std::invalid_argument("zero-sized guest arena allocation");
        if (alignment == 0 || (alignment & (alignment - 1)) != 0) throw std::invalid_argument("invalid guest arena alignment");
        std::lock_guard lock(_lock);
        if (hint >= _end) throw std::runtime_error("mapping address hint is above the guest address space arena");
        std::uintptr_t candidate = alignUp(std::max(_base, hint), alignment);
        auto it = _used.upper_bound(candidate);
        if (it != _used.begin() && std::prev(it)->second > candidate) --it;
        for (; it != _used.end(); ++it) {
            const auto& [start, end] = *it;
            if (candidate <= _end && bytes <= _end - candidate && candidate + bytes <= start) break;
            candidate = std::max(candidate, alignUp(end, alignment));
        }
        if (candidate > _end || bytes > _end - candidate) throw std::runtime_error("guest address space arena exhausted");
        const auto inserted = _used.emplace(candidate, candidate + bytes);
        if (!inserted.second) throw std::runtime_error("guest arena allocation overlaps an existing range");
        try {
            ensureReservedLocked(candidate, bytes);
        } catch (...) {
            _used.erase(inserted.first);
            throw;
        }
        return reinterpret_cast<void*>(candidate);
    }

    void MarkUsed(const void* pointer, std::size_t bytes) {
        if (bytes == 0 || !Contains(pointer, bytes)) throw std::invalid_argument("fixed guest mapping outside the arena");
        std::lock_guard lock(_lock);
        const auto start = reinterpret_cast<std::uintptr_t>(pointer);
        const auto next = _used.lower_bound(start);
        if ((next != _used.end() && next->first < start + bytes) || (next != _used.begin() && std::prev(next)->second > start)) {
            char message[160];
            std::snprintf(message, sizeof(message), "fixed guest mapping 0x%llx+0x%zx overlaps %s", static_cast<unsigned long long>(start), bytes, OverlapsHostRegion(start, bytes) ? "a host region in the guest arena" : "a guest arena range");
            throw std::runtime_error(message);
        }
        const auto inserted = _used.emplace(start, start + bytes);
        try {
            ensureReservedLocked(start, bytes);
        } catch (...) {
            _used.erase(inserted.first);
            throw;
        }
    }

    void Release(const void* pointer, std::size_t bytes) {
        if (bytes == 0 || !Contains(pointer, bytes)) throw std::invalid_argument("release outside the guest arena");
        std::lock_guard lock(_lock);
        const auto start = reinterpret_cast<std::uintptr_t>(pointer);
        const auto end = start + bytes;
        auto it = _used.upper_bound(start);
        if (it != _used.begin()) --it;
        while (it != _used.end() && it->first < end) {
            const auto rangeStart = it->first;
            const auto rangeEnd = it->second;
            if (rangeEnd <= start) {
                ++it;
                continue;
            }
            it = _used.erase(it);
            if (rangeStart < start) _used.emplace(rangeStart, start);
            if (rangeEnd > end) _used.emplace(end, rangeEnd);
        }
        for (const auto& [holeStart, holeEnd] : _holes) {
            if (holeStart < end && start < holeEnd) _used.emplace(holeStart, holeEnd);
        }
    }

    void ensureReservedLocked(std::uintptr_t address, std::size_t bytes) {
#ifdef _WIN32
        if (!_lazy || bytes == 0) return;
        if (!Contains(reinterpret_cast<void*>(address), bytes)) throw std::invalid_argument("lazy guest reservation outside the arena");
        auto cursor = address & ~(_chunk - 1);
        const auto last = address + bytes;
        std::vector<std::uintptr_t> acquired;
        acquired.reserve((last - cursor - 1) / _chunk + 1);
        try {
            for (; cursor < last; cursor += _chunk) {
                if (_reserved.count(cursor) != 0) continue;
                const auto size = std::min(_chunk, static_cast<std::size_t>(_end - cursor));
                // Allocate the tracking node before changing the host map.
                const auto inserted = _reserved.insert(cursor);
                void* reserved;
                try {
                    reserved = WindowsMappings::Get().Reserve(reinterpret_cast<void*>(cursor), size);
                } catch (...) {
                    _reserved.erase(inserted.first);
                    throw;
                }
                if (reserved != reinterpret_cast<void*>(cursor)) {
                    const auto error = GetLastError();
                    _reserved.erase(inserted.first);
                    if (reserved) VirtualFree(reserved, 0, MEM_RELEASE);
                    char message[160];
                    std::snprintf(message, sizeof(message), "reserve fixed guest arena chunk 0x%llx+0x%llx",
                                  static_cast<unsigned long long>(cursor), static_cast<unsigned long long>(size));
                    throw std::system_error(static_cast<int>(error), std::system_category(), message);
                }
                acquired.push_back(cursor);
            }
        } catch (...) {
            for (auto it = acquired.rbegin(); it != acquired.rend(); ++it) {
                if (VirtualFree(reinterpret_cast<void*>(*it), 0, MEM_RELEASE)) _reserved.erase(*it);
                else std::fprintf(stderr, "guest arena rollback retained placeholder 0x%llx error=%lu\n",
                                  static_cast<unsigned long long>(*it), static_cast<unsigned long>(GetLastError()));
            }
            throw;
        }
#else
        (void)address;
        (void)bytes;
#endif
    }

private:
    Arena() {
#ifdef _WIN32
        const ArenaLimits limits = ReadArenaLimits();
        _lazy = limits.lazy;
        _chunk = limits.chunk;
        _writeWatched = std::getenv("APS5_NO_WRITE_WATCH") == nullptr;
        const std::uintptr_t arenaStart = limits.base;
        const std::uintptr_t end = arenaStart + limits.size;
        {
            SYSTEM_INFO system{};
            GetSystemInfo(&system);
            const std::uintptr_t granularity = system.dwAllocationGranularity;
            for (std::uintptr_t cursor = arenaStart; cursor < end;) {
                MEMORY_BASIC_INFORMATION info{};
                if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) == 0) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "query the guest arena range");
                const auto regionBase = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
                if (regionBase > cursor || info.RegionSize == 0 || info.RegionSize > std::numeric_limits<std::uintptr_t>::max() - regionBase || regionBase + info.RegionSize <= cursor)
                    throw std::runtime_error("invalid host region in guest arena census");
                const auto regionEnd = std::min(end, regionBase + info.RegionSize);
                if (_lazy) {
                    if (info.State != MEM_FREE) {
                        _hostRegions.emplace_back(cursor, regionEnd);
                        // Lazy reservations own whole chunks. Even a small host
                        // mapping excludes its entire chunk from allocation.
                        _holes.emplace_back(cursor & ~(_chunk - 1), std::min(end, alignUp(regionEnd, _chunk)));
                    }
                    cursor = regionEnd;
                    continue;
                }
                const auto first = info.State == MEM_FREE ? std::min(regionEnd, alignUp(cursor, granularity)) : regionEnd;
                const auto last = std::max(first, regionEnd & ~(granularity - 1));
                if (first < last && WindowsMappings::Get().Reserve(reinterpret_cast<void*>(first), last - first) == nullptr) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "reserve the guest arena range");
                if (cursor < first) _holes.emplace_back(cursor, first);
                if (last < regionEnd) _holes.emplace_back(last, regionEnd);
                cursor = regionEnd;
            }
            if (!_lazy) _hostRegions = _holes;
        }
        const auto holeStart = std::max(SystemReservedStart, arenaStart);
        const auto holeEnd = std::min(SystemReservedEnd, end);
        if (holeStart < holeEnd) _holes.emplace_back(holeStart, holeEnd);
        std::sort(_holes.begin(), _holes.end());
        std::vector<std::pair<std::uintptr_t, std::uintptr_t>> merged;
        for (const auto& hole : _holes) {
            if (!merged.empty() && hole.first <= merged.back().second) merged.back().second = std::max(merged.back().second, hole.second);
            else merged.push_back(hole);
        }
        _holes = std::move(merged);
        for (const auto& [usedStart, usedEnd] : _holes) _used.emplace(usedStart, usedEnd);
        _base = arenaStart;
        _end = end;
#endif
    }

    std::mutex _lock;
    std::map<std::uintptr_t, std::uintptr_t> _used;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> _holes;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> _hostRegions;
    std::uintptr_t _base = 0;
    std::uintptr_t _end = 0;
    std::size_t _chunk = DefaultChunk;
    bool _lazy = false;
    bool _writeWatched = false;
    std::set<std::uintptr_t> _reserved;

public:
    std::uintptr_t Base() const { return _base; }
    std::size_t Size() const { return _end - _base; }
    bool WriteWatched() const { return _writeWatched; }
    bool OverlapsHostRegion(std::uintptr_t start, std::size_t bytes) const {
        if (bytes > std::numeric_limits<std::uintptr_t>::max() - start) throw std::invalid_argument("host overlap range overflows");
        for (const auto& [regionStart, regionEnd] : _hostRegions) {
            if (regionStart < start + bytes && start < regionEnd) return true;
        }
        return false;
    }

    void EnsureReserved(std::uintptr_t address, std::size_t bytes) {
        std::lock_guard lock(_lock);
        ensureReservedLocked(address, bytes);
    }
};

const bool g_reserved = (Arena::Get(), true);

}

bool GuestArenaAvailable_nid_postfix() {
    return Arena::Get().Available();
}

bool GuestArenaContains_nid_postfix(const void* pointer, std::size_t bytes) {
    return Arena::Get().Contains(pointer, bytes);
}

void* GuestArenaAllocate_nid_postfix(std::size_t bytes, std::size_t alignment) {
    return Arena::Get().Allocate(bytes, alignment);
}

void* GuestArenaAllocateAtOrAbove_nid_postfix(std::uintptr_t hint, std::size_t bytes, std::size_t alignment) {
    return Arena::Get().AllocateAtOrAbove(hint, bytes, alignment);
}

void GuestArenaMarkUsed_nid_postfix(const void* pointer, std::size_t bytes) {
    Arena::Get().MarkUsed(pointer, bytes);
}

void GuestArenaRelease_nid_postfix(const void* pointer, std::size_t bytes) {
    Arena::Get().Release(pointer, bytes);
}

void GuestArenaRange_nid_postfix(std::uintptr_t* base, std::size_t* bytes) {
    *base = Arena::Get().Base();
    *bytes = Arena::Get().Size();
}

#ifdef _WIN32
void GuestArenaSetProtection_nid_postfix(std::uintptr_t address, std::size_t bytes, std::uint32_t protection) {
    WindowsMappings::Get().SetProtection(address, bytes, protection);
}

bool GuestArenaHandleWrite_nid_postfix(std::uintptr_t address) {
    return WindowsMappings::Get().HandleWrite(address);
}

void GuestArenaPinWritable_nid_postfix(const void* pointer, std::size_t bytes) {
    if (!Arena::Get().Contains(pointer, bytes)) return;
    WindowsMappings::Get().Pin(reinterpret_cast<std::uintptr_t>(pointer), bytes);
}

void GuestArenaUnpinWritable_nid_postfix(const void* pointer, std::size_t bytes) {
    if (!Arena::Get().Contains(pointer, bytes)) return;
    WindowsMappings::Get().Unpin(reinterpret_cast<std::uintptr_t>(pointer), bytes);
}

bool GuestArenaProtection_nid_postfix(std::uintptr_t address, std::uint32_t* protection) {
    return WindowsMappings::Get().Protection(address, protection);
}

bool GuestArenaCollectWrites_nid_postfix(std::uintptr_t address, std::size_t bytes, void** pages, std::size_t* count, bool clear) {
    return WindowsMappings::Get().Collect(address, bytes, pages, count, clear);
}

bool GuestArenaHostRegionOverlaps_nid_postfix(std::uintptr_t address, std::size_t bytes) {
    return Arena::Get().OverlapsHostRegion(address, bytes);
}

namespace {

std::invalid_argument OutsideArena(const char* operation, const void* pointer, std::size_t bytes) {
    char message[128];
    std::snprintf(message, sizeof(message), "%s 0x%llx+0x%zx outside the guest arena", operation, static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(pointer)), bytes);
    return std::invalid_argument(message);
}

}

std::uint64_t GuestArenaCommitGeneration_nid_postfix() {
    return commitGeneration.load(std::memory_order_acquire);
}

void GuestArenaSetPrivateMappingObserver_nid_postfix(void (*callback)(std::uintptr_t, std::size_t, std::uint64_t)) {
    privateMappingObserver.store(callback, std::memory_order_release);
}

void GuestArenaCommit_nid_postfix(void* pointer, std::size_t bytes, std::uint32_t protection, std::size_t granule) {
    if (!Arena::Get().Contains(pointer, bytes)) throw OutsideArena("commit", pointer, bytes);
    Arena::Get().EnsureReserved(reinterpret_cast<std::uintptr_t>(pointer), bytes);
    const auto generation = commitGeneration.fetch_add(1, std::memory_order_acq_rel) + 1;
    const auto created = WindowsMappings::Get().Commit(pointer, bytes, protection, granule, Arena::Get().WriteWatched());
    if (const auto callback = privateMappingObserver.load(std::memory_order_acquire)) {
        for (const auto& [address, size] : created) callback(address, size, generation);
    }
}

void GuestArenaReset_nid_postfix(void* pointer, std::size_t bytes) {
    if (!Arena::Get().Contains(pointer, bytes)) throw OutsideArena("reset", pointer, bytes);
    WindowsMappings::Get().Reset(pointer, bytes);
}

void GuestArenaMap_nid_postfix(void* pointer, std::size_t bytes, void* section, std::uint64_t offset, std::uint32_t protection) {
    if (!Arena::Get().Contains(pointer, bytes)) throw OutsideArena("shared mapping", pointer, bytes);
    Arena::Get().EnsureReserved(reinterpret_cast<std::uintptr_t>(pointer), bytes);
    WindowsMappings::Get().Map(pointer, bytes, section, offset, protection);
}

void* GuestArenaMapAlias_nid_postfix(std::uintptr_t address, std::size_t bytes) {
    return WindowsMappings::Get().MapAlias(address, bytes);
}

void GuestArenaUnmapAlias_nid_postfix(void* alias) {
    WindowsMappings::Get().UnmapAlias(alias);
}
#endif

bool GuestArenaWriteWatched_nid_postfix() {
    return Arena::Get().WriteWatched();
}

bool GuestArenaBeginHostWrite_nid_postfix(void* pointer, std::size_t bytes) {
#ifdef _WIN32
    return WindowsMappings::Get().BeginHostWrite(reinterpret_cast<std::uintptr_t>(pointer), bytes);
#elif defined(__APPLE__)
    Aps5MacBeginHostWrite(pointer, bytes);
    return true;
#else
    (void)pointer;
    (void)bytes;
    return true;
#endif
}

void GuestArenaEndHostWrite_nid_postfix(void* pointer, std::size_t bytes) {
#ifdef _WIN32
    WindowsMappings::Get().EndHostWrite(reinterpret_cast<std::uintptr_t>(pointer), bytes);
#elif defined(__APPLE__)
    Aps5MacEndHostWrite(pointer, bytes);
#else
    (void)pointer;
    (void)bytes;
#endif
}

#ifndef _WIN32
namespace {

std::atomic<SharedBackingResolver> sharedBackingResolver{nullptr};

}

void GuestArenaSetSharedBacking_nid_postfix(SharedBackingResolver resolver) {
    sharedBackingResolver.store(resolver, std::memory_order_release);
}

bool GuestArenaSharedBacking_nid_postfix(std::uintptr_t address, std::size_t bytes, int* file, std::uint64_t* offset) {
    const auto resolver = sharedBackingResolver.load(std::memory_order_acquire);
    return resolver != nullptr && resolver(address, bytes, file, offset);
}
#endif

}
