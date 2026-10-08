#ifndef APS5_MACOS_LOADER_HOSTSYMBOLS_HPP
#define APS5_MACOS_LOADER_HOSTSYMBOLS_HPP

#include <filesystem>
#include <string>

// Binds guest imports (named by NID) to the native system library implementations.
namespace HostSymbols {

void LoadLibrary(const std::filesystem::path& directory, const std::string& name);
// Never returns null: an import nothing provides gets a trap that reports its name when first called.
void* Resolve(const std::string& name);
// Imports left without a provider so far.
std::size_t TrapCount();

}

#endif
