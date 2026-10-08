#pragma once
#include "ControlFlow/ControlFlowGraph.hpp"
#include "Optimization/ShaderStageInputInfo.hpp"
#include "RdnaDecoder/RdnaProgram.hpp"
#include "Recompiler.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <stdexcept>

namespace ShaderRecompiler {

// The existing native interpolation lowering drops P1 and replaces P2 with an
// interpolated attribute. Prove that this represents the original I/J pair;
// never apply it to arbitrary barycentric arithmetic or partial P1 results.
inline void ValidateFixedFunctionInterpolation(const RdnaProgram& decoded,
                                               const ControlFlowGraph& cfg,
                                               const ShaderPixelInputInfo& pixel) {
    std::set<std::uint32_t> live;
    std::set<std::uint32_t> centers;
    for (const auto input : {PixelInput::PerspectiveSample, PixelInput::PerspectiveCenter,
                             PixelInput::PerspectiveCentroid, PixelInput::PerspectivePullModel,
                             PixelInput::LinearSample, PixelInput::LinearCenter, PixelInput::LinearCentroid}) {
        const auto base = pixel.psInputVgpr[static_cast<std::size_t>(input)];
        if (base == ShaderPixelInputInfo::NoPixelInputVgpr) continue;
        live.insert(base); live.insert(base + 1u);
        if (input == PixelInput::PerspectivePullModel) live.insert(base + 2u);
        if (input == PixelInput::PerspectiveCenter || input == PixelInput::LinearCenter) centers.insert(base);
    }
    std::uint32_t pc = 0;
    const auto failAt = [&](int rule) {
        if (std::getenv("APS5_TRACE_FFI") != nullptr) {
            std::fprintf(stderr, "[ffi] rule line %d at pc=%u; blocks=%zu instructions=%zu inputNum=%u live:", rule, pc, cfg.blocks.size(), decoded.instructions.size(), pixel.inputNum);
            for (const auto reg : live) std::fprintf(stderr, " v%u", reg);
            std::fprintf(stderr, " centers:");
            for (const auto reg : centers) std::fprintf(stderr, " v%u", reg);
            std::fprintf(stderr, "\n");
            for (std::size_t n = 0; n < decoded.instructions.size() && n < 48; ++n) {
                const auto& i = decoded.instructions[n];
                std::fprintf(stderr, "[ffi]   pc=%-4u op=%-4d fam=%-2d dst=%d:%u src0=%d:%u/%u src1=%d:%u/%u src2=%d:%u/%u\n", i.programCounter, static_cast<int>(i.op), static_cast<int>(i.family),
                             static_cast<int>(i.destination.kind), i.destination.reg, static_cast<int>(i.source0.kind), i.source0.reg, i.source0.value,
                             static_cast<int>(i.source1.kind), i.source1.reg, i.source1.value, static_cast<int>(i.source2.kind), i.source2.reg, i.source2.value);
            }
        }
        throw std::runtime_error("fixed-function interpolation requires unmodified center I/J pairs and complete P1/P2 sequences in an unconditional entry block (pc=" + std::to_string(pc) + ")");
    };
#define fail() failAt(__LINE__)
    const bool hasInterpolation = std::any_of(decoded.instructions.begin(), decoded.instructions.end(), [](const auto& i) {
        return i.op == RdnaOpcode::VInterpP1F32 || i.op == RdnaOpcode::VInterpP2F32 || i.op == RdnaOpcode::VInterpMovF32;
    });
    if (!hasInterpolation && live.empty()) return;
    const BasicBlock* entry = nullptr;
    if (cfg.blocks.size() != 1u) {
        // A branch after an unconditional interpolation prefix is harmless
        // only when every raw I/J register has been overwritten on entry.
        // Reject loops into the prefix and interpolation in later blocks.
        const auto found = std::find_if(cfg.blocks.begin(), cfg.blocks.end(), [&](const auto& b) { return b.id == cfg.entryBlock; });
        if (cfg.unsupported || cfg.irreducible || found == cfg.blocks.end() ||
            found->instructionBegin != 0u || !found->instructionEnd ||
            found->instructionEnd > decoded.instructions.size() || !found->predecessors.empty()) fail();
        entry = &*found;
    }
    struct Pair { std::uint32_t base, attribute, component; };
    std::map<std::uint32_t, Pair> pending;
    bool vectorWritten = false;
    const auto plain = [](const RdnaOperand& o) {
        return !o.negate && !o.negateHi && !o.absolute && !o.clamp && !o.omod && !o.opSel && !o.opSelHi &&
               !o.dpp && !o.dpp8 && !o.explicitSdwaDst && !o.sdwaSext && o.sdwaSel == 6u;
    };
    for (const auto& i : decoded.instructions) {
        pc = i.programCounter;
        const auto index = static_cast<std::size_t>(&i - decoded.instructions.data());
        if (entry && index >= entry->instructionEnd && (!live.empty() || !pending.empty())) fail();
        if (i.op == RdnaOpcode::VInterpMovF32) fail(); // Requires original vertex values.
        if (i.op == RdnaOpcode::VInterpP1F32 || i.op == RdnaOpcode::VInterpP2F32) {
            if (entry && index >= entry->instructionEnd) fail();
            if (i.source0.kind != RdnaOperandKind::VectorRegister || i.destination.kind != RdnaOperandKind::VectorRegister ||
                !plain(i.source0) || !plain(i.destination) || i.clampResult || i.source1.value >= 32u ||
                i.source1.value >= pixel.inputNum || i.source2.value >= 4u || pixel.InputIsCustom(i.source1.value)) fail();
            if (i.op == RdnaOpcode::VInterpP1F32) {
                if (!centers.contains(i.source0.reg) || !live.contains(i.source0.reg) ||
                    !live.contains(i.source0.reg + 1u) || pending.contains(i.destination.reg) ||
                    (live.contains(i.destination.reg) && i.destination.reg != i.source0.reg)) fail();
                pending.emplace(i.destination.reg, Pair{i.source0.reg, i.source1.value, i.source2.value});
                // P1 may consume I in place after the other P1 instructions.
                // Its original raw value cannot be used by another pair.
                live.erase(i.destination.reg);
            } else {
                const auto p = pending.find(i.destination.reg);
                if (p == pending.end() || i.source0.reg != p->second.base + 1u ||
                    !live.contains(i.source0.reg) || p->second.attribute != i.source1.value || p->second.component != i.source2.value) fail();
                pending.erase(p);
            }
            continue;
        }
        const auto writesExec = [](const RdnaOperand& o) {
            return o.kind == RdnaOperandKind::ExecLo || o.kind == RdnaOperandKind::ExecHi;
        };
        if ((!pending.empty() || (vectorWritten && !live.empty())) &&
            (writesExec(i.destination) || writesExec(i.destination2))) fail();
        // The compiler schedules unrelated work between a P1 and its P2. The lowering makes P1 a no-op and
        // P2 the whole interpolated attribute, so the only state that differs from the original between the
        // two is the partial register: an instruction is harmless exactly when it neither reads nor writes
        // a partial, stays in this block and leaves EXEC alone (checked above). That holds for
        // - vector ALU with an explicit vector result, and compares into VCC or a scalar register;
        // - scalar instructions, which cannot address vector registers, and the wait/no-op markers;
        // - image reads, whose coordinate and result registers the decoder records in full.
        // Branches, stores, atomics, buffer and export instructions, and anything unknown reject.
        if (!pending.empty()) {
            const bool vectorAlu = i.family == RdnaInstructionFamily::VOP1 || i.family == RdnaInstructionFamily::VOP2 ||
                                   i.family == RdnaInstructionFamily::VOP3 || i.family == RdnaInstructionFamily::VOP3P;
            const bool compare = i.family == RdnaInstructionFamily::VOPC;
            const bool scalar = i.family == RdnaInstructionFamily::SOP1 || i.family == RdnaInstructionFamily::SOP2 ||
                                i.family == RdnaInstructionFamily::SOPK || i.family == RdnaInstructionFamily::SOPC ||
                                i.family == RdnaInstructionFamily::SMEM || i.op == RdnaOpcode::SWaitcnt || i.op == RdnaOpcode::SNop;
            bool imageRead = i.family == RdnaInstructionFamily::MIMG && i.destination.kind == RdnaOperandKind::VectorRegister;
            switch (i.op) {
                case RdnaOpcode::ImageStore: case RdnaOpcode::ImageStoreMip: case RdnaOpcode::ImageStorePck: case RdnaOpcode::ImageStoreMipPck:
                case RdnaOpcode::ImageAtomicAdd: case RdnaOpcode::ImageAtomicAnd: case RdnaOpcode::ImageAtomicCmpswap: case RdnaOpcode::ImageAtomicDec:
                case RdnaOpcode::ImageAtomicFcmpswap: case RdnaOpcode::ImageAtomicFmax: case RdnaOpcode::ImageAtomicFmin: case RdnaOpcode::ImageAtomicInc:
                case RdnaOpcode::ImageAtomicOr: case RdnaOpcode::ImageAtomicSmax: case RdnaOpcode::ImageAtomicSmin: case RdnaOpcode::ImageAtomicSub:
                case RdnaOpcode::ImageAtomicSwap: case RdnaOpcode::ImageAtomicUmax: case RdnaOpcode::ImageAtomicUmin: case RdnaOpcode::ImageAtomicXor:
                case RdnaOpcode::ImageBvhIntersectRay: case RdnaOpcode::ImageBvh64IntersectRay:
                    imageRead = false;
                    break;
                default:
                    break;
            }
            if (vectorAlu && i.destination.kind != RdnaOperandKind::VectorRegister) fail();
            if (!vectorAlu && !compare && !scalar && !imageRead) fail();
            const auto overlapsPartial = [&](const RdnaOperand& operand, std::uint32_t count) {
                if (operand.kind != RdnaOperandKind::VectorRegister) return false;
                return std::any_of(pending.begin(), pending.end(), [&](const auto& pair) {
                    return pair.first >= operand.reg && pair.first - operand.reg < count;
                });
            };
            const auto sourceCount = imageRead ? std::max(4u, i.imageAddressComponents) : (i.is64Bit ? 2u : 1u);
            const auto resultCount = imageRead ? std::max({1u, i.dataDwordCount, i.dataComponents}) : (i.is64Bit ? 2u : 1u);
            for (const auto& source : {i.source0, i.source1, i.source2, i.source3})
                if (overlapsPartial(source, sourceCount)) fail();
            if (imageRead && i.imageNsaDwordCount != 0u)
                for (const auto reg : i.imageNsaVectorRegisters)
                    if (pending.contains(reg)) fail();
            if (overlapsPartial(i.destination, resultCount) || overlapsPartial(i.destination2, resultCount)) fail();
        }
        const bool alu = i.family == RdnaInstructionFamily::VOP1 || i.family == RdnaInstructionFamily::VOP2 ||
                         i.family == RdnaInstructionFamily::VOP3 || i.family == RdnaInstructionFamily::VOP3P || i.family == RdnaInstructionFamily::VOPC;
        const auto width = alu ? (i.is64Bit ? 2u : 1u) : std::max({4u, i.dataDwordCount, i.dataComponents, i.imageAddressComponents});
        for (const auto& source : {i.source0, i.source1, i.source2, i.source3}) {
            if (source.dpp || source.dpp8) fail();
            if (source.kind != RdnaOperandKind::VectorRegister) continue;
            for (const auto reg : live) if (reg >= source.reg && reg - source.reg < width) fail();
        }
        for (const auto reg : i.imageNsaVectorRegisters) {
            if (i.imageNsaDwordCount != 0u && live.contains(reg)) fail();
        }
        // Memory decoders record the written vector width. ALU destinations
        // forget just their first register; ambiguous wider writes reject later.
        if (i.destination.kind == RdnaOperandKind::VectorRegister) {
            const bool memory = i.family == RdnaInstructionFamily::MIMG || i.family == RdnaInstructionFamily::MUBUF ||
                                i.family == RdnaInstructionFamily::MTBUF || i.family == RdnaInstructionFamily::FLAT || i.family == RdnaInstructionFamily::DS;
            const auto count = memory ? std::max(i.dataDwordCount, 1u) : 1u;
            for (std::uint32_t j = 0; j < count; ++j) live.erase(i.destination.reg + j);
            vectorWritten = true;
        }
        if (i.destination2.kind == RdnaOperandKind::VectorRegister) live.erase(i.destination2.reg);
    }
    if (!pending.empty()) fail();
#undef fail
}
}
