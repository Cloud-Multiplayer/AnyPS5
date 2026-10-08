// macOS stand-in for <linux/udmabuf.h>. There is no /dev/udmabuf, so opening the device fails and the
// callers take their path for hosts without it; these declarations only let that code compile.
#ifndef PRX_LIBC_INCLUDE_SPECIFICS_MACOS_SHIM_LINUX_UDMABUF_H
#define PRX_LIBC_INCLUDE_SPECIFICS_MACOS_SHIM_LINUX_UDMABUF_H

#include <cstdint>
#include <sys/ioccom.h>

struct udmabuf_create {
    std::uint32_t memfd;
    std::uint32_t flags;
    std::uint64_t offset;
    std::uint64_t size;
};

#define UDMABUF_FLAGS_CLOEXEC 0x01
#define UDMABUF_CREATE _IOW('u', 0x42, struct udmabuf_create)

#endif
