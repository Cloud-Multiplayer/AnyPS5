#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_GENERAL_PROCPATHS_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_GENERAL_PROCPATHS_HPP

// macOS has no procfs: the listing is generated on demand in the same text format.
#if defined(__APPLE__)
#define APS5_PROC_SELF_MAPS Aps5MacProcSelfMaps()
#else
#define APS5_PROC_SELF_MAPS "/proc/self/maps"
#endif

#endif
