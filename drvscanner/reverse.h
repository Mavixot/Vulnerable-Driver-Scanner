#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace scanner { struct DriverAnalysis; }

namespace reverse
{
    struct Instruction
    {
        std::uint64_t address = 0;
        std::uint64_t next = 0;
        std::string mnemonic;
        std::string operands;
    };

    struct ImportSymbol
    {
        std::uint64_t address = 0;
        std::string name;
        std::string module;
    };

    struct Program
    {
        std::uint64_t imageBase = 0;
        std::uint64_t entry = 0;
        std::vector<ImportSymbol> imports;
        std::function<std::vector<Instruction>(std::uint64_t)> instructions;
        std::function<std::size_t(std::uint64_t)> fileOffset;
        std::function<bool()> timeBudgetExpired;
    };

    void AnalyzeWdmX64(const Program& program, scanner::DriverAnalysis& analysis);
}
