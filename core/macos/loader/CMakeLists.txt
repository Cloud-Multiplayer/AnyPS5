# In-process loader for relinker Linux ELF output. x86-64 only: guest code runs natively (through Rosetta on
# Apple Silicon).
add_executable(aps5-run
        Loader.cpp
        HostSymbols.cpp
        ${CMAKE_SOURCE_DIR}/core/libs/nid/src/NidResolver.cpp
        ${CMAKE_SOURCE_DIR}/core/libs/nid/src/NidCompute.cpp
        ${CMAKE_SOURCE_DIR}/core/libs/nid/src/Sha1.cpp
        ${CMAKE_SOURCE_DIR}/core/libs/nid/src/ExportExclusions.cpp
        ${CMAKE_SOURCE_DIR}/core/libs/nid/src/ElfNidPatcher.cpp
        ${CMAKE_SOURCE_DIR}/core/libs/nid/src/PeNidPatcher.cpp
        ${CMAKE_SOURCE_DIR}/core/relinker/codegen/src/x86/X64InstructionDecoder.cpp
        ${CMAKE_SOURCE_DIR}/core/relinker/codegen/src/x86/DecodedInstruction.cpp
)
target_include_directories(aps5-run PRIVATE
        ${CMAKE_SOURCE_DIR}/core/libs/nid/include
        ${CMAKE_SOURCE_DIR}/core/relinker/codegen/include
        ${CMAKE_SOURCE_DIR}/core/relinker/domain/include
)
target_compile_features(aps5-run PRIVATE cxx_std_20)
# The system libraries resolve dl_iterate_phdr and dladdr1 from the loader.
target_link_options(aps5-run PRIVATE -Wl,-export_dynamic)
