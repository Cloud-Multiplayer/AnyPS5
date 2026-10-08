// macOS write watch, included by GuestWriteWatch.cpp inside namespace GuestWriteWatch.
//
// macOS has no asynchronous write-protect facility like userfaultfd or MEM_WRITE_WATCH. Watched pages are
// write-protected instead; the first write to a page faults, the handler records the page as written and
// restores its protection, and the write is retried. Collect() reports the recorded pages and protects them
// again.
//
// Two things follow from using real page protection:
// - A system call that writes into a protected page fails with EFAULT instead of faulting. GuestArena::HostWrite,
//   which already brackets such calls for the Windows write watch, lifts the protection for their duration.
// - mprotect and mmap on watched pages would silently drop or fight the protection. MacCompat routes both
//   through Aps5MacWatchProtectionChanged so the watch knows the protection the guest asked for.

#undef mprotect
#undef mmap
#undef munmap

constexpr std::uintptr_t PageBytes = 4096;

class Watch {
public:
    static Watch& Get() {
        static Watch watch;
        return watch;
    }

    bool Available() const { return _available; }

    void Register(std::uintptr_t begin, std::uintptr_t end) {
        begin &= ~(PageBytes - 1);
        end = (end + PageBytes - 1) & ~(PageBytes - 1);
        if (!_available || end <= begin) return;
        // Protections are read before taking the lock: the fault handler shares it and must never wait on
        // a kernel call that can itself take long.
        std::vector<std::uint8_t> pages((end - begin) / PageBytes, Dirty);
        for (auto cursor = begin; cursor < end;) {
            mach_vm_address_t address = cursor;
            mach_vm_size_t size = 0;
            vm_region_basic_info_data_64_t info{};
            mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t object = MACH_PORT_NULL;
            if (mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info), &count, &object) != KERN_SUCCESS || address >= end) break;
            const auto first = std::max<std::uintptr_t>(cursor, address);
            const auto last = std::min<std::uintptr_t>(end, address + size);
            const std::uint8_t protection = ((info.protection & VM_PROT_READ) ? PROT_READ : 0) | ((info.protection & VM_PROT_WRITE) ? PROT_WRITE : 0) | ((info.protection & VM_PROT_EXECUTE) ? PROT_EXEC : 0);
            for (auto page = first; page < last; page += PageBytes) pages[(page - begin) / PageBytes] = Dirty | protection;
            cursor = last;
        }
        const Lock lock(_lock);
        // A page that is already watched may be write-protected by this watch right now, so the region
        // lookup above saw it read-only. Its real protection is the one recorded for it.
        forEachPage(begin, end, [&](std::uintptr_t page, std::uint8_t& state) {
            pages[(page - begin) / PageBytes] = static_cast<std::uint8_t>(Dirty | (state & ProtectionMask));
        });
        erase(begin, end);
        _ranges.emplace(begin, Range{end, std::move(pages)});
    }

    bool Unregister(std::uintptr_t begin, std::uintptr_t end) {
        begin &= ~(PageBytes - 1);
        end = (end + PageBytes - 1) & ~(PageBytes - 1);
        if (!_available || end <= begin) return false;
        const Lock lock(_lock);
        return erase(begin, end);
    }

    bool Covers(std::uintptr_t begin, std::uintptr_t end) {
        if (!_available) return false;
        const Lock lock(_lock);
        return covers(begin, end);
    }

    bool Collect(std::uintptr_t begin, std::uintptr_t end, void (*written)(void*, std::uintptr_t, std::uintptr_t), void* context) {
        if (!_available) return false;
        begin &= ~(PageBytes - 1);
        end = (end + PageBytes - 1) & ~(PageBytes - 1);
        if (end <= begin) return true;
        std::vector<std::pair<std::uintptr_t, std::uintptr_t>> runs;
        {
            const Lock lock(_lock);
            if (!covers(begin, end)) return false;
            // A page is protected before its written flag is cleared, both under the lock the fault
            // handler takes: a write that lands in between waits, then records the page again.
            forEachPage(begin, end, [&](std::uintptr_t page, std::uint8_t& state) {
                if ((state & Dirty) == 0) return;
                if (!runs.empty() && runs.back().second == page) runs.back().second = page + PageBytes;
                else runs.emplace_back(page, page + PageBytes);
                // A page a system call is writing right now is reported but stays written and writable.
                for (const auto& [first, last] : _hostWrites)
                    if (page >= first && page < last) return;
                state &= static_cast<std::uint8_t>(~Dirty);
                if ((state & PROT_WRITE) != 0) state |= Armed;
            });
            for (const auto& [first, last] : runs) protectArmed(first, last);
        }
        for (const auto& [first, last] : runs) written(context, first, last);
        return true;
    }

    // The guest (or a native library) set this protection on the range. Watched pages take it as the
    // protection to restore and count as written, since their watch protection is gone.
    void ProtectionChanged(std::uintptr_t begin, std::uintptr_t end, int protection) {
        if (!_available) return;
        begin &= ~(PageBytes - 1);
        end = (end + PageBytes - 1) & ~(PageBytes - 1);
        const Lock lock(_lock);
        forEachPage(begin, end, [&](std::uintptr_t, std::uint8_t& state) { state = static_cast<std::uint8_t>(Dirty | (protection & ProtectionMask)); });
    }

    // Native code is about to pass this memory to a system call that writes it. Until EndHostWrite the
    // pages stay unprotected and count as written, so a collection on another thread cannot protect them
    // again in the middle of the call.
    void BeginHostWrite(std::uintptr_t begin, std::uintptr_t end) {
        if (!_available || end <= begin) return;
        begin &= ~(PageBytes - 1);
        end = (end + PageBytes - 1) & ~(PageBytes - 1);
        const Lock lock(_lock);
        _hostWrites.emplace_back(begin, end);
        forEachPage(begin, end, [&](std::uintptr_t page, std::uint8_t& state) {
            if ((state & Armed) != 0) ::mprotect(reinterpret_cast<void*>(page), PageBytes, state & ProtectionMask);
            state = static_cast<std::uint8_t>((state & ProtectionMask) | Dirty);
        });
    }

    void EndHostWrite(std::uintptr_t begin, std::uintptr_t end) {
        if (!_available || end <= begin) return;
        begin &= ~(PageBytes - 1);
        end = (end + PageBytes - 1) & ~(PageBytes - 1);
        const Lock lock(_lock);
        const auto found = std::find(_hostWrites.begin(), _hostWrites.end(), std::pair{begin, end});
        if (found != _hostWrites.end()) _hostWrites.erase(found);
    }

    // Protection the guest set on a watched page, which differs from the real one while the page is
    // write-protected for the watch. Returns -1 for an unwatched address. runEnd receives the end of the run
    // that shares the answer: same protection when watched, the next watched page when not.
    int LogicalProtection(std::uintptr_t address, std::uintptr_t limit, std::uintptr_t* runEnd) {
        const auto page = address & ~(PageBytes - 1);
        const Lock lock(_lock);
        auto it = _ranges.upper_bound(page);
        if (it != _ranges.begin() && page < std::prev(it)->second.end) {
            --it;
            const auto& pages = it->second.pages;
            const std::uint8_t protection = pages[(page - it->first) / PageBytes] & ProtectionMask;
            auto end = page + PageBytes;
            while (end < it->second.end && end < limit && (pages[(end - it->first) / PageBytes] & ProtectionMask) == protection) end += PageBytes;
            *runEnd = std::min(end, limit);
            return protection;
        }
        *runEnd = it != _ranges.end() ? std::min(it->first, limit) : limit;
        return -1;
    }

private:
    static constexpr std::uint8_t ProtectionMask = PROT_READ | PROT_WRITE | PROT_EXEC;
    static constexpr std::uint8_t Dirty = 0x10;
    static constexpr std::uint8_t Armed = 0x20;

    struct Range {
        std::uintptr_t end;
        std::vector<std::uint8_t> pages;
    };

    // Shared with the fault handler, so it cannot be a mutex. Turns are handed out in order: with a plain
    // test-and-set lock a thread that collects in a loop kept winning it and writers waiting in the handler
    // starved, which under Rosetta made a contended write take milliseconds. Nothing that holds the lock
    // touches watched memory.
    struct Turns {
        std::atomic<std::uint64_t> next{0};
        std::atomic<std::uint64_t> serving{0};
    };

    struct Lock {
        explicit Lock(Turns& turns) : _turns(turns), _turn(turns.next.fetch_add(1, std::memory_order_relaxed)) {
            while (_turns.serving.load(std::memory_order_acquire) != _turn) ::sched_yield();
        }
        ~Lock() { _turns.serving.store(_turn + 1, std::memory_order_release); }
        Turns& _turns;
        std::uint64_t _turn;
    };

    Watch() {
        if (std::getenv("APS5_NO_WRITE_WATCH") != nullptr) return;
        struct sigaction action {};
        action.sa_sigaction = &Watch::fault;
        action.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGBUS, &action, &_previousBus) != 0 || sigaction(SIGSEGV, &action, &_previousSegv) != 0) {
            std::fprintf(stderr, "[memory] write watch: cannot install the fault handler; guest buffers are fully re-read every use\n");
            return;
        }
        _available = true;
    }

    static void fault(int signal, siginfo_t* info, void* context) {
        auto& watch = Get();
        if (watch.record(reinterpret_cast<std::uintptr_t>(info->si_addr))) return;
        // Not a watched write: hand the fault to whoever was installed before, or let it terminate.
        const auto& previous = signal == SIGBUS ? watch._previousBus : watch._previousSegv;
        if ((previous.sa_flags & SA_SIGINFO) != 0 && previous.sa_sigaction != nullptr) {
            previous.sa_sigaction(signal, info, context);
            return;
        }
        if (previous.sa_handler != SIG_DFL && previous.sa_handler != SIG_IGN && previous.sa_handler != nullptr) {
            previous.sa_handler(signal);
            return;
        }
        ::signal(signal, SIG_DFL);
    }

    bool record(std::uintptr_t address) {
        const auto page = address & ~(PageBytes - 1);
        const Lock lock(_lock);
        auto it = _ranges.upper_bound(page);
        if (it == _ranges.begin()) return false;
        --it;
        if (page >= it->second.end) return false;
        auto& state = it->second.pages[(page - it->first) / PageBytes];
        if ((state & Armed) != 0) {
            state = static_cast<std::uint8_t>((state & ProtectionMask) | Dirty);
            ::mprotect(reinterpret_cast<void*>(page), PageBytes, state & ProtectionMask);
            return true;
        }
        // Another thread already recorded this page while this one was waiting to fault on it.
        return (state & PROT_WRITE) != 0;
    }

    template <typename TFunction>
    void forEachPage(std::uintptr_t begin, std::uintptr_t end, TFunction function) {
        auto it = _ranges.upper_bound(begin);
        if (it != _ranges.begin()) --it;
        for (; it != _ranges.end() && it->first < end; ++it) {
            const auto first = std::max(begin, it->first);
            const auto last = std::min(end, it->second.end);
            for (auto page = first; page < last; page += PageBytes) function(page, it->second.pages[(page - it->first) / PageBytes]);
        }
    }

    // Write-protects the armed pages of [begin, end), one call per run of equal protection.
    void protectArmed(std::uintptr_t begin, std::uintptr_t end) {
        std::uintptr_t runStart = 0;
        int runProtection = -1;
        const auto flush = [&](std::uintptr_t runEnd) {
            if (runProtection >= 0) ::mprotect(reinterpret_cast<void*>(runStart), runEnd - runStart, runProtection);
            runProtection = -1;
        };
        std::uintptr_t previous = begin;
        forEachPage(begin, end, [&](std::uintptr_t page, std::uint8_t& state) {
            const int wanted = (state & Armed) != 0 ? (state & ProtectionMask & ~PROT_WRITE) : -1;
            if (wanted != runProtection || page != previous) {
                flush(previous);
                runStart = page;
                runProtection = wanted;
            }
            previous = page + PageBytes;
        });
        flush(previous);
    }

    bool covers(std::uintptr_t begin, std::uintptr_t end) const {
        auto it = _ranges.upper_bound(begin);
        if (it == _ranges.begin()) return false;
        --it;
        auto cursor = begin;
        for (; it != _ranges.end() && it->first <= cursor; ++it) {
            if (it->second.end > cursor) cursor = it->second.end;
            if (cursor >= end) return true;
        }
        return false;
    }

    // Removes [begin, end) from the watched ranges, restoring the protection of pages that were armed.
    bool erase(std::uintptr_t begin, std::uintptr_t end) {
        bool removed = false;
        auto it = _ranges.upper_bound(begin);
        if (it != _ranges.begin()) --it;
        while (it != _ranges.end() && it->first < end) {
            const auto rangeBegin = it->first;
            const auto rangeEnd = it->second.end;
            if (rangeEnd <= begin) {
                ++it;
                continue;
            }
            removed = true;
            auto pages = std::move(it->second.pages);
            it = _ranges.erase(it);
            const auto cutBegin = std::max(begin, rangeBegin);
            const auto cutEnd = std::min(end, rangeEnd);
            for (auto page = cutBegin; page < cutEnd; page += PageBytes) {
                const auto state = pages[(page - rangeBegin) / PageBytes];
                if ((state & Armed) != 0) ::mprotect(reinterpret_cast<void*>(page), PageBytes, state & ProtectionMask);
            }
            if (rangeBegin < cutBegin) _ranges.emplace(rangeBegin, Range{cutBegin, std::vector<std::uint8_t>(pages.begin(), pages.begin() + (cutBegin - rangeBegin) / PageBytes)});
            if (cutEnd < rangeEnd) it = _ranges.emplace(cutEnd, Range{rangeEnd, std::vector<std::uint8_t>(pages.begin() + (cutEnd - rangeBegin) / PageBytes, pages.end())}).first;
        }
        return removed;
    }

    bool _available = false;
    Turns _lock;
    std::map<std::uintptr_t, Range> _ranges;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> _hostWrites;
    struct sigaction _previousBus {};
    struct sigaction _previousSegv {};
};

const bool g_opened = (Watch::Get(), true);

}
}

extern "C" {

void Aps5MacWatchProtectionChanged(void* address, std::size_t bytes, int protection) {
    const auto begin = reinterpret_cast<std::uintptr_t>(address);
    GuestWriteWatch::Watch::Get().ProtectionChanged(begin, begin + bytes, protection);
}

int Aps5MacWatchLogicalProtection(std::uintptr_t address, std::uintptr_t limit, std::uintptr_t* runEnd) {
    return GuestWriteWatch::Watch::Get().LogicalProtection(address, limit, runEnd);
}

void Aps5MacBeginHostWrite(void* address, std::size_t bytes) {
    const auto begin = reinterpret_cast<std::uintptr_t>(address);
    GuestWriteWatch::Watch::Get().BeginHostWrite(begin, begin + bytes);
}

void Aps5MacEndHostWrite(void* address, std::size_t bytes) {
    const auto begin = reinterpret_cast<std::uintptr_t>(address);
    GuestWriteWatch::Watch::Get().EndHostWrite(begin, begin + bytes);
}

}

namespace GuestWriteWatch {
namespace {
