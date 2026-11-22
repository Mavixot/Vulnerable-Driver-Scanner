#include "reverse.h"
#include "scanner.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <deque>
#include <iomanip>
#include <map>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>
#include <string_view>

namespace
{
    enum class Kind { Unknown, Constant, Import, DriverObject, Irp, IoStack, SystemBuffer, RawBuffer, Ioctl, Length, Field, Stack };
    struct Value
    {
        Kind kind = Kind::Unknown;
        std::uint64_t number = 0;
        std::int64_t offset = 0;
        std::string origin;
        unsigned int bits = 64;
        std::uint32_t sourceRva = 0;
    };
    struct Domain
    {
        std::uint64_t low = 0;
        std::uint64_t high = ~0ULL;
        std::set<std::uint64_t> excluded;
    };
    struct Probe
    {
        std::string origin;
        std::int64_t offset = 0;
        std::uint64_t size = 0;
        bool write = false;
    };
    struct Condition
    {
        bool ioctlComparison = false;
        std::uint32_t code = 0;
        bool guardComparison = false;
        std::string text;
        bool constant = false;
        bool equal = false;
        bool below = false;
        bool signedBelow = false;
        Value symbolic;
        std::uint64_t bound = 0;
        bool constrained = false;
        bool equalityOnly = false;
    };
    struct State
    {
        std::uint64_t pc = 0;
        std::array<Value, 16> registers{};
        std::map<std::int64_t, Value> stack;
        std::map<std::int64_t, unsigned int> stackWidths;
        std::vector<std::uint64_t> returns;
        std::map<std::uint64_t, unsigned int> visits;
        bool blockEntry = true;
        std::optional<std::uint32_t> ioctl;
        Condition condition;
        std::vector<std::string> notes;
        std::vector<Probe> probes;
        std::map<std::string, Domain> domains;
        std::set<std::string> guardedValues;
        std::vector<std::string> pathConditions;
        std::size_t volatileLoads = 0;
        bool pathTruncated = false;
        bool authorizationObserved = false;
        bool unknownHelper = false;
    };

    std::string Trim(std::string value)
    {
        const auto begin = value.find_first_not_of(" \t\r\n");
        if (begin == std::string::npos) return {};
        const auto end = value.find_last_not_of(" \t\r\n");
        return value.substr(begin, end - begin + 1);
    }

    std::string Lower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return value;
    }

    std::string Hex(std::uint64_t value)
    {
        std::ostringstream text;
        text << "0x" << std::hex << value;
        return text.str();
    }

    std::optional<std::uint64_t> Number(std::string value, bool address = false)
    {
        value = Lower(Trim(value));
        if (value.empty()) return {};
        int base = address ? 16 : 10;
        if (value.back() == 'h') { value.pop_back(); base = 16; }
        else if (value.rfind("0x", 0) == 0) base = 16;
        char* end = nullptr;
        const auto result = std::strtoull(value.c_str(), &end, base);
        if (end == value.c_str() || *end != '\0') return {};
        return result;
    }

    int Register(const std::string& name)
    {
        if (name == "ah") return 0;
        if (name == "ch") return 1;
        if (name == "dh") return 2;
        if (name == "bh") return 3;
        static const std::array<std::array<const char*, 4>, 16> names = {{
            {{"rax","eax","ax","al"}}, {{"rcx","ecx","cx","cl"}},
            {{"rdx","edx","dx","dl"}}, {{"rbx","ebx","bx","bl"}},
            {{"rsp","esp","sp","spl"}}, {{"rbp","ebp","bp","bpl"}},
            {{"rsi","esi","si","sil"}}, {{"rdi","edi","di","dil"}},
            {{"r8","r8d","r8w","r8b"}}, {{"r9","r9d","r9w","r9b"}},
            {{"r10","r10d","r10w","r10b"}}, {{"r11","r11d","r11w","r11b"}},
            {{"r12","r12d","r12w","r12b"}}, {{"r13","r13d","r13w","r13b"}},
            {{"r14","r14d","r14w","r14b"}}, {{"r15","r15d","r15w","r15b"}}
        }};
        static const auto aliases = [&] {
            std::unordered_map<std::string_view,int> values;
            values.reserve(64);
            for (std::size_t index = 0; index < names.size(); ++index)
                for (const auto* alias : names[index]) values.emplace(alias,static_cast<int>(index));
            return values;
        }();
        const auto found = aliases.find(name);
        return found == aliases.end() ? -1 : found->second;
    }

    unsigned int Width(const std::string& operand)
    {
        if (operand.find("qword ptr") != std::string::npos) return 64;
        if (operand.find("dword ptr") != std::string::npos) return 32;
        if (operand.find("word ptr") != std::string::npos) return 16;
        if (operand.find("byte ptr") != std::string::npos) return 8;
        if (Register(operand) < 0) return 64;
        if (operand[0] == 'e' || operand.back() == 'd') return 32;
        if (operand.size() == 2 && operand.back() == 'x') return 16;
        if (operand == "si" || operand == "di" || operand == "bp" || operand == "sp" || operand.back() == 'w') return 16;
        if (operand.back() == 'l' || operand.back() == 'b' || operand.back() == 'h') return 8;
        return 64;
    }

    std::uint64_t Mask(unsigned int bits)
    {
        return bits == 64 ? ~0ULL : (1ULL << bits) - 1;
    }

    std::string Key(const Value& value)
    {
        return value.origin + "/" + std::to_string(value.bits);
    }

    bool Symbolic(const Value& value)
    {
        return value.kind == Kind::Ioctl || value.kind == Kind::Length || value.kind == Kind::Field || value.kind == Kind::RawBuffer;
    }

    bool RequestValue(const Value& value)
    {
        return value.kind == Kind::Field || value.kind == Kind::RawBuffer;
    }

    void Note(State& state, const std::string& text)
    {
        if (state.notes.size() < 12 && std::find(state.notes.begin(), state.notes.end(), text) == state.notes.end())
            state.notes.push_back(text);
    }

    class Analyzer
    {
        struct ParsedInstruction
        {
            std::string mnemonic;
            std::string first;
            std::string second;
            std::string conditionText;
        };
        const reverse::Program& program;
        scanner::DriverAnalysis& result;
        std::map<std::uint64_t, reverse::Instruction> code;
        std::unordered_map<std::uint64_t, ParsedInstruction> parsedCode;
        std::set<std::uint64_t> attempted;
        std::map<std::uint64_t, std::string> imported;
        std::map<std::uint64_t, std::string> handlers;
        std::size_t functions = 0;
        std::size_t functionLimit = 48;
        std::size_t states = 0;
        bool limited = false;
        std::set<std::pair<std::string,std::uint64_t>> recordedGaps;

        void Gap(const std::string& reason, std::uint64_t address = 0)
        {
            limited = true;
            if (result.reverseCoverageReasons.size() >= 64 || !recordedGaps.emplace(reason,address).second) return;
            const std::string text = reason + (address ? " at RVA " + Hex(address - program.imageBase) : "");
            auto& reasons = result.reverseCoverageReasons;
            if (reasons.size() < 64 && std::find(reasons.begin(), reasons.end(), text) == reasons.end()) reasons.push_back(text);
        }

        const reverse::Instruction* Get(std::uint64_t address)
        {
            if (program.timeBudgetExpired && program.timeBudgetExpired()) { Gap("reverse-time-budget"); return nullptr; }
            auto found = code.find(address);
            if (found != code.end()) return &found->second;
            if (attempted.count(address)) return nullptr;
            if (functions >= functionLimit) { Gap(functionLimit == 16 ? "registration-region-budget" : "function-region-budget", address); return nullptr; }
            attempted.insert(address);
            ++functions;
            const auto instructions = program.instructions(address);
            for (const auto& instruction : instructions)
            {
                if (code.size() >= 100000) { Gap("decoded-instruction-budget", address); break; }
                code.emplace(instruction.address, instruction);
            }
            found = code.find(address);
            if (found == code.end()) { Gap("instruction-unavailable", address); return nullptr; }
            return &found->second;
        }

        Value Address(const std::string& operand, const State& state)
        {
            const auto begin = operand.find('[');
            const auto end = operand.find(']', begin);
            if (begin == std::string::npos || end == std::string::npos) return {};
            std::string expression = operand.substr(begin + 1, end - begin - 1);
            expression.erase(std::remove_if(expression.begin(), expression.end(), [](unsigned char c) { return std::isspace(c) != 0; }), expression.end());
            if (expression.find('*') != std::string::npos) return {};
            const auto separator = expression.find_first_of("+-", 1);
            const std::string base = expression.substr(0, separator);
            Value value;
            const int reg = Register(base);
            if (reg >= 0) value = state.registers[static_cast<std::size_t>(reg)];
            else
            {
                const auto number = Number(base, true);
                if (!number) return {};
                value.kind = Kind::Constant; value.number = *number;
            }
            if (separator != std::string::npos)
            {
                const auto displacement = Number(expression.substr(separator + 1));
                if (!displacement || *displacement > 0x7fffffff) return {};
                const auto delta = static_cast<std::int64_t>(*displacement) * (expression[separator] == '-' ? -1 : 1);
                if (value.kind == Kind::Constant) value.number += delta;
                else value.offset += delta;
            }
            return value;
        }

        bool Constrain(State& state, const Value& value, std::uint64_t bound,
            std::string branch, bool taken)
        {
            if (!Symbolic(value) || value.offset != 0) return true;
            enum class Relation { Equal, NotEqual, Below, BelowEqual, Above, AboveEqual, Unknown };
            Relation relation = Relation::Unknown;
            if (branch == "je" || branch == "jz") relation = Relation::Equal;
            else if (branch == "jne" || branch == "jnz") relation = Relation::NotEqual;
            else if (branch == "jb" || branch == "jc" || branch == "jnae") relation = Relation::Below;
            else if (branch == "jbe" || branch == "jna") relation = Relation::BelowEqual;
            else if (branch == "ja" || branch == "jnbe") relation = Relation::Above;
            else if (branch == "jae" || branch == "jnb" || branch == "jnc") relation = Relation::AboveEqual;
            if (!taken)
            {
                switch (relation)
                {
                case Relation::Equal: relation = Relation::NotEqual; break;
                case Relation::NotEqual: relation = Relation::Equal; break;
                case Relation::Below: relation = Relation::AboveEqual; break;
                case Relation::BelowEqual: relation = Relation::Above; break;
                case Relation::Above: relation = Relation::BelowEqual; break;
                case Relation::AboveEqual: relation = Relation::Below; break;
                default: break;
                }
            }
            if (relation == Relation::Unknown) return true;
            auto& domain = state.domains[Key(value)];
            domain.high = std::min(domain.high, Mask(value.bits));
            switch (relation)
            {
            case Relation::Equal: domain.low = std::max(domain.low, bound); domain.high = std::min(domain.high, bound); break;
            case Relation::NotEqual:
                if (domain.excluded.size() < 64) domain.excluded.insert(bound);
                else Gap("path-exclusion-budget");
                break;
            case Relation::Below:
                if (bound == 0) return false;
                domain.high = std::min(domain.high, bound - 1); break;
            case Relation::BelowEqual: domain.high = std::min(domain.high, bound); break;
            case Relation::Above:
                if (bound == ~0ULL) return false;
                domain.low = std::max(domain.low, bound + 1); break;
            case Relation::AboveEqual: domain.low = std::max(domain.low, bound); break;
            default: break;
            }
            while (domain.low <= domain.high && domain.excluded.count(domain.low))
            {
                if (domain.low == ~0ULL) return false;
                ++domain.low;
            }
            while (domain.low <= domain.high && domain.excluded.count(domain.high))
            {
                if (domain.high == 0) return false;
                --domain.high;
            }
            return domain.low <= domain.high;
        }

        void PathCondition(State& state, const reverse::Instruction& instruction, bool taken)
        {
            if (state.pathConditions.size() < 32)
                state.pathConditions.push_back("RVA " + Hex(instruction.address - program.imageBase) + ": " +
                    instruction.mnemonic + " " + instruction.operands + (taken ? " [taken]; " : " [fallthrough]; ") + state.condition.text);
            else state.pathTruncated = true;
        }

        void Finding(const Value& value, const reverse::Instruction& instruction, const State& state,
            std::uint64_t handler, const std::string& rule, const std::string& title, const std::string& access,
            bool physical = false, std::uint64_t size = 0)
        {
            if (!handler || !state.ioctl || !RequestValue(value)) return;
            if ((*state.ioctl & 3) == 3 && value.origin.rfind("IRP.AssociatedIrp.SystemBuffer", 0) == 0) return;
            if (value.kind == Kind::RawBuffer && ((*state.ioctl & 3) != 3)) return;
            bool probeUncertain = false;
            if (!physical)
            {
                for (const auto& probe : state.probes)
                {
                    if (probe.origin != Key(value) || (access == "write" && !probe.write)) continue;
                    if (value.offset < probe.offset) continue;
                    const auto delta = static_cast<std::uint64_t>(value.offset) - static_cast<std::uint64_t>(probe.offset);
                    if (size && probe.size && delta <= probe.size && size <= probe.size - delta) return;
                    if (!size || !probe.size) probeUncertain = true;
                }
            }
            const bool guarded = state.authorizationObserved || state.guardedValues.count(Key(value)) || probeUncertain;
            const std::string confidence = state.unknownHelper ? "partial-call-chain-review" :
                guarded ? "guard-observed-review" : "source-to-operation-trace";
            const auto existing = std::find_if(result.findings.begin(), result.findings.end(), [&](const auto& finding) {
                return finding.ioctl == *state.ioctl && finding.handlerRva == handler - program.imageBase &&
                    finding.rule == rule && finding.confidence == confidence && finding.sourceExpression == Key(value);
            });
            if (existing != result.findings.end())
            {
                const auto rva = static_cast<std::uint32_t>(instruction.address - program.imageBase);
                if (rva != existing->operationRva && existing->relatedOperationRvas.size() < 64 &&
                    std::find(existing->relatedOperationRvas.begin(), existing->relatedOperationRvas.end(), rva) == existing->relatedOperationRvas.end())
                    existing->relatedOperationRvas.push_back(rva);
                return;
            }
            if (result.findings.size() >= 64) { Gap("finding-budget", instruction.address); return; }

            scanner::FlowFinding finding;
            finding.rule = rule;
            finding.title = title;
            finding.access = access;
            finding.confidence = confidence;
            finding.reviewOnly = state.unknownHelper || guarded;
            finding.ioctl = *state.ioctl;
            finding.handlerRva = static_cast<std::uint32_t>(handler - program.imageBase);
            finding.operationRva = static_cast<std::uint32_t>(instruction.address - program.imageBase);
            finding.fileOffset = program.fileOffset(instruction.address);
            finding.sourceRva = value.sourceRva;
            finding.sourceExpression = Key(value);
            finding.accessSize = size;
            finding.pathConditions = state.pathConditions;
            finding.evidence.push_back(handlers[handler]);
            finding.evidence.push_back("Entry modeled as IRP_MJ_DEVICE_CONTROL with RequestorMode=UserMode; effective device access remains unverified.");
            finding.evidence.push_back("IOCTL " + Hex(*state.ioctl) + " equality path traced from IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode");
            finding.evidence.push_back(value.origin);
            finding.evidence.push_back("Source loaded at RVA " + Hex(value.sourceRva) + "; address displacement " +
                std::to_string(value.offset) + "; access extent " + (size ? std::to_string(size) + " byte(s)" : "unknown"));
            finding.evidence.push_back("RVA " + Hex(finding.operationRva) + ": " + instruction.mnemonic + " " + instruction.operands);
            finding.evidence.insert(finding.evidence.end(), state.notes.begin(), state.notes.end());
            finding.evidence.push_back(physical ? "Request-controlled value reaches the memory operation argument on this modeled path." :
                "No pointer probe covering this operation's direction, offset and extent was established on this modeled path.");
            finding.limitations = {
                "Potential vulnerability requiring manual confirmation; device ACLs, caller privilege and address ownership are not established.",
                "Bounded Windows x64 WDM analysis; exception handlers, runtime state, KMDF callbacks and unresolved indirect control flow are not modeled.",
                "Feasibility of branches depending on unmodeled runtime values must be checked."
            };
            if (guarded) finding.limitations.push_back("A related address/authorization guard or probe of unknown extent was observed; its adequacy requires review.");
            if (state.unknownHelper) finding.limitations.push_back("An unresolved helper may perform additional validation; absence of checks is not established.");
            if (state.pathTruncated) finding.limitations.push_back("Path witness is limited to its first 32 conditional branches.");
            result.findings.push_back(std::move(finding));
        }

        Value Read(const std::string& operand, State& state, const reverse::Instruction& instruction, std::uint64_t handler)
        {
            const auto bits = Width(operand);
            const int reg = Register(operand);
            if (reg >= 0)
            {
                Value value = state.registers[static_cast<std::size_t>(reg)];
                if (value.kind == Kind::Constant)
                    value.number = (value.number >> (operand.size() == 2 && operand.back() == 'h' ? 8 : 0)) & Mask(bits);
                else if (bits < value.bits)
                {
                    if (value.kind != Kind::Unknown) { Gap("narrow-register-read", instruction.address); state.unknownHelper = true; }
                    return {};
                }
                return value;
            }
            if (operand.find('[') == std::string::npos)
            {
                const auto number = Number(operand);
                if (number) { Value value; value.kind = Kind::Constant; value.number = *number; return value; }
                return {};
            }
            Value address = Address(operand, state);
            if (address.kind == Kind::Stack)
            {
                const auto found = state.stack.find(address.offset);
                if (found == state.stack.end()) return {};
                if (state.stackWidths[address.offset] != bits) { Gap("overlapping-stack-access", instruction.address); return {}; }
                return found->second;
            }
            if (address.kind == Kind::Constant && imported.count(address.number) && bits == 64)
                return { Kind::Import, address.number, 0, imported[address.number] };
            if (address.kind == Kind::Irp)
            {
                if (address.offset == 0xb8 && bits == 64) return { Kind::IoStack, 0, 0, "IRP.Tail.Overlay.CurrentStackLocation" };
                if (address.offset == 0x18 && bits == 64) return { Kind::SystemBuffer, 0, 0, "IRP.AssociatedIrp.SystemBuffer" };
                if (address.offset == 0x70 && bits == 64) return { Kind::RawBuffer, 0, 0, "IRP.UserBuffer", 64, static_cast<std::uint32_t>(instruction.address - program.imageBase) };
                if (address.offset == 0x40 && operand.find("byte ptr") != std::string::npos)
                    return { Kind::Constant, 1, 0, "IRP.RequestorMode=UserMode" };
            }
            if (address.kind == Kind::IoStack)
            {
                if (address.offset == 0 && operand.find("byte ptr") != std::string::npos)
                    return { Kind::Constant, 0x0e, 0, "IO_STACK_LOCATION.MajorFunction=IRP_MJ_DEVICE_CONTROL" };
                // WDM applies POINTER_ALIGNMENT to both InputBufferLength and
                // IoControlCode: on x64 these ULONG members occupy 8-byte slots.
                if (address.offset == 0x18 && bits == 32) return { Kind::Ioctl, 0, 0, "IO_STACK_LOCATION.IoControlCode", 32 };
                if ((address.offset == 0x08 || address.offset == 0x10) && bits == 32)
                    return { Kind::Length, 0, 0, address.offset == 0x08 ? "IO_STACK_LOCATION.OutputBufferLength" : "IO_STACK_LOCATION.InputBufferLength", 32 };
                if (address.offset == 0x20 && bits == 64) return { Kind::RawBuffer, 0, 0, "IO_STACK_LOCATION.Type3InputBuffer", 64, static_cast<std::uint32_t>(instruction.address - program.imageBase) };
            }
            if (address.kind == Kind::SystemBuffer || address.kind == Kind::RawBuffer)
            {
                if (address.kind == Kind::RawBuffer)
                    Finding(address, instruction, state, handler, "raw-user-pointer-read", "Direct read through a request user pointer", "read", false, bits / 8);
                const auto identity = address.origin + " -> field+" + Hex(static_cast<std::uint64_t>(address.offset)) +
                    (address.kind == Kind::RawBuffer ? "/volatile-load-" + std::to_string(++state.volatileLoads) : "");
                return { Kind::Field, 0, 0, identity,
                    bits, static_cast<std::uint32_t>(instruction.address - program.imageBase) };
            }
            Finding(address, instruction, state, handler, "request-controlled-pointer-read", "Request field used as a memory read address", "read", false, bits / 8);
            return {};
        }

        void Write(const std::string& operand, const Value& value, State& state,
            const reverse::Instruction& instruction, std::uint64_t handler)
        {
            const int reg = Register(operand);
            if (reg >= 0)
            {
                auto& target = state.registers[static_cast<std::size_t>(reg)];
                const auto bits = Width(operand);
                if (bits < 32)
                {
                    // AL/AX writes retain the other bits, unlike zero-extending EAX writes.
                    if (target.kind == Kind::Constant && value.kind == Kind::Constant)
                    {
                        const auto shift = operand.size() == 2 && operand.back() == 'h' ? 8 : 0;
                        target.number = (target.number & ~(Mask(bits) << shift)) | ((value.number & Mask(bits)) << shift);
                    }
                    else { if (target.kind != Kind::Unknown || value.kind != Kind::Constant) Gap("partial-register-write", instruction.address); target = {}; }
                    return;
                }
                target = value;
                if (bits == 32)
                {
                    if (target.kind == Kind::Constant) target.number &= Mask(32);
                    else if (target.kind == Kind::Field || target.kind == Kind::Ioctl || target.kind == Kind::Length) target.bits = 32;
                    else target = {};
                }
                return;
            }
            if (operand.find('[') == std::string::npos) return;
            const Value address = Address(operand, state);
            if (address.kind == Kind::Stack)
            {
                const auto width = Width(operand);
                for (auto iterator = state.stack.begin(); iterator != state.stack.end();)
                {
                    const auto start = iterator->first;
                    if (start < address.offset + width / 8 && address.offset < start + state.stackWidths[start] / 8)
                    { state.stackWidths.erase(start); iterator = state.stack.erase(iterator); }
                    else ++iterator;
                }
                state.stack[address.offset] = value; state.stackWidths[address.offset] = width;
                return;
            }
            if (!handler && address.kind == Kind::DriverObject && address.offset == 0xe0 && value.kind == Kind::Constant && Width(operand) == 64)
            {
                if (value.number >= program.imageBase && value.number - program.imageBase < 0xffffffff && Get(value.number))
                    handlers.emplace(value.number, "DriverEntry flow stores handler RVA " + Hex(value.number - program.imageBase) +
                        " into DriverObject.MajorFunction[IRP_MJ_DEVICE_CONTROL] at RVA " + Hex(instruction.address - program.imageBase));
            }
            Finding(address, instruction, state, handler, "request-controlled-pointer-write", "Request field used as a memory write address", "write", false, Width(operand) / 8);
            if (address.kind == Kind::SystemBuffer || address.kind == Kind::RawBuffer)
            {
                // A request field changed; earlier predicates/probes on a reloaded value no longer apply.
                state.domains.clear(); state.probes.clear(); state.guardedValues.clear();
                state.unknownHelper = true;
                Gap("request-buffer-mutation", instruction.address);
            }
        }

        void ImportedCall(const std::string& name, State& state, const reverse::Instruction& instruction, std::uint64_t handler)
        {
            const Value first = state.registers[1];
            const Value second = state.registers[2];
            const Value fourth = state.registers[9];
            const Value third = state.registers[8];
            const auto extent = third.kind == Kind::Constant ? third.number : 0;
            const std::string normalized = Lower(name);
            bool modeled = false;
            if (normalized == "mmmapiospace" || normalized == "mmmapiospaceex")
            {
                if (second.kind != Kind::Constant || second.number != 0)
                    Finding(first, instruction, state, handler, "request-controlled-physical-mapping",
                        "Request field reaches a physical memory mapping address", "physical mapping", true,
                        second.kind == Kind::Constant ? second.number : 0);
                modeled = true;
            }
            if (normalized == "memcpy" || normalized == "memmove" || normalized == "rtlmovememory" || normalized == "rtlcopymemory")
            {
                if (third.kind != Kind::Constant || third.number != 0)
                {
                    Finding(first, instruction, state, handler, "request-controlled-copy-destination", "Request field reaches a memory copy destination", "write", false, extent);
                    Finding(second, instruction, state, handler, "request-controlled-copy-source", "Request field reaches a memory copy source", "read", false, extent);
                }
                modeled = true;
            }
            if (normalized == "mmcopymemory" || normalized == "zwreadvirtualmemory" || normalized == "zwwritevirtualmemory" || normalized == "mmcopyvirtualmemory")
            {
                Value count = normalized == "mmcopymemory" ? third : fourth;
                const bool crossProcess = normalized == "mmcopyvirtualmemory";
                const auto savedAuthorization = state.authorizationObserved;
                if (crossProcess)
                {
                    count = {};
                    const auto stack = state.registers[4];
                    if (stack.kind == Kind::Stack)
                    {
                        const auto size = state.stack.find(stack.offset + 0x20);
                        if (size != state.stack.end()) count = size->second;
                        const auto mode = state.stack.find(stack.offset + 0x28);
                        if (mode == state.stack.end() || mode->second.kind != Kind::Constant || mode->second.number != 0)
                        {
                            state.authorizationObserved = true;
                            Note(state, "MmCopyVirtualMemory PreviousMode is not established as KernelMode; internal probing requires review.");
                        }
                    }
                    else state.authorizationObserved = true;
                }
                if (count.kind != Kind::Constant || count.number != 0)
                {
                    const auto size = count.kind == Kind::Constant ? count.number : 0;
                    const bool write = normalized == "zwwritevirtualmemory";
                    Finding(second, instruction, state, handler, "request-controlled-memory-call",
                        "Request field reaches a privileged memory operation", write ? "write" : "read", true, size);
                    Finding(crossProcess ? fourth : normalized == "mmcopymemory" ? first : third, instruction, state, handler,
                        "request-controlled-memory-call-buffer", "Request field reaches a privileged memory operation buffer",
                        write ? "read" : "write", true, size);
                }
                state.authorizationObserved = savedAuthorization;
                modeled = true;
            }
            if (normalized == "probeforread" || normalized == "probeforwrite")
            {
                if (RequestValue(first))
                {
                    if (second.kind != Kind::Constant || second.number != 0)
                        state.probes.push_back({Key(first), first.offset,
                            second.kind == Kind::Constant ? second.number : 0, normalized == "probeforwrite"});
                }
                Note(state, name + " observed at RVA " + Hex(instruction.address - program.imageBase));
                modeled = true;
            }
            if (normalized == "iovalidatedeviceiocontrolaccess" || normalized == "sesingleprivilegecheck" || normalized == "seprivilegecheck")
            {
                Note(state, name + " observed; its return value and effective authorization require review");
                state.authorizationObserved = true;
                modeled = true;
            }
            // Standard kernel routines can still validate inputs; do not infer missing checks across them.
            if (normalized == "iogetcurrentirpstacklocation") modeled = true;
            if (!modeled)
            {
                if (handler) state.unknownHelper = true;
                state.domains.clear(); state.probes.clear(); state.guardedValues.clear();
                Gap("unmodeled-import:" + name, instruction.address);
            }
            for (int index : { 0, 1, 2, 8, 9, 10, 11 }) state.registers[static_cast<std::size_t>(index)] = {};
            state.condition = {};
            if (normalized == "iogetcurrentirpstacklocation" && first.kind == Kind::Irp)
                state.registers[0] = { Kind::IoStack, 0, 0, "IoGetCurrentIrpStackLocation" };
        }

        void Walk(std::uint64_t entry, std::uint64_t handler)
        {
            functionLimit = handler ? 48 : 16;
            State initial;
            initial.pc = entry;
            initial.registers[4] = { Kind::Stack, 0, 0, "stack" };
            if (!handler) initial.registers[1] = { Kind::DriverObject, 0, 0, "DriverEntry.DriverObject" };
            else initial.registers[2] = { Kind::Irp, 0, 0, "dispatch.IRP" };
            std::deque<State> pending;
            pending.push_back(std::move(initial));
            std::size_t walkSteps = 0;
            std::size_t walkStates = 0;
            while (!pending.empty())
            {
                State state = std::move(pending.front()); pending.pop_front();
                if (++states > 1024 || ++walkStates > (handler ? 512u : 128u)) { Gap("state-budget", state.pc); return; }
                for (std::size_t step = 0; step < 3000; ++step)
                {
                    if (program.timeBudgetExpired && program.timeBudgetExpired()) { Gap("reverse-time-budget"); return; }
                    if (result.reverseInstructions >= 60000) { Gap("instruction-step-budget", state.pc); return; }
                    if (++walkSteps > (handler ? 40000u : 12000u)) { Gap(handler ? "handler-step-budget" : "registration-step-budget", state.pc); return; }
                    ++result.reverseInstructions;
                    // Count block entries rather than sequential instructions.
                    if (state.blockEntry && ++state.visits[state.pc] > 2) { Gap("loop-visit-budget", state.pc); break; }
                    state.blockEntry = false;
                    const auto* pointer = Get(state.pc);
                    if (!pointer) break;
                    const auto& instruction = *pointer;
                    auto parsed = parsedCode.find(instruction.address);
                    if (parsed == parsedCode.end())
                    {
                        const auto operands = Lower(instruction.operands);
                        const auto comma = operands.find(',');
                        ParsedInstruction decoded{Lower(instruction.mnemonic), Trim(operands.substr(0, comma)),
                            comma == std::string::npos ? "" : Trim(operands.substr(comma + 1)), {}};
                        if (decoded.mnemonic == "cmp" || decoded.mnemonic == "test")
                            decoded.conditionText = "RVA " + Hex(instruction.address - program.imageBase) + ": " + decoded.mnemonic + " " + instruction.operands;
                        parsed = parsedCode.emplace(instruction.address,std::move(decoded)).first;
                    }
                    const auto& mnemonic = parsed->second.mnemonic;
                    if (mnemonic == "ret" || mnemonic == "retn" || mnemonic == "call" || (!mnemonic.empty() && mnemonic[0] == 'j'))
                        state.blockEntry = true;
                    const auto& first = parsed->second.first;
                    const auto& second = parsed->second.second;
                    state.pc = instruction.next;

                    if (mnemonic == "ret" || mnemonic == "retn")
                    {
                        if (state.returns.empty()) break;
                        state.pc = state.returns.back(); state.returns.pop_back();
                        state.registers[4].offset += 8;
                    }
                    else if (mnemonic == "call" || mnemonic == "jmp")
                    {
                        std::optional<std::uint64_t> target;
                        std::string import;
                        if (first.find('[') != std::string::npos)
                        {
                            const Value address = Address(first, state);
                            if (address.kind == Kind::Constant)
                            {
                                const auto found = imported.find(address.number);
                                if (found != imported.end()) import = found->second;
                            }
                        }
                        else
                        {
                            const int reg = Register(first);
                            if (reg >= 0)
                            {
                                const auto& value = state.registers[static_cast<std::size_t>(reg)];
                                if (value.kind == Kind::Constant) target = value.number;
                                else if (value.kind == Kind::Import && imported.count(value.number)) import = imported[value.number];
                            }
                            else target = Number(first, true);
                        }
                        if (!import.empty())
                        {
                            ImportedCall(import, state, instruction, handler);
                            if (mnemonic == "jmp")
                            {
                                if (state.returns.empty()) break;
                                state.pc = state.returns.back(); state.returns.pop_back(); state.registers[4].offset += 8;
                            }
                        }
                        else if (target && Get(*target) && (mnemonic == "jmp" || state.returns.size() < 4))
                        {
                            if (mnemonic == "call")
                            {
                                state.returns.push_back(instruction.next);
                                state.registers[4].offset -= 8;
                                state.stack[state.registers[4].offset] = { Kind::Constant, instruction.next, 0, "return address" };
                                state.stackWidths[state.registers[4].offset] = 64;
                                Note(state, "Direct helper call to RVA " + Hex(*target - program.imageBase));
                            }
                            state.pc = *target;
                        }
                        else
                        {
                            Gap(mnemonic == "jmp" ? "unresolved-indirect-jump" : "unresolved-call", instruction.address);
                            if (mnemonic == "jmp") break;
                            state.unknownHelper = true;
                            state.domains.clear(); state.probes.clear(); state.guardedValues.clear();
                            state.condition = {};
                            for (int index : { 0, 1, 2, 8, 9, 10, 11 }) state.registers[static_cast<std::size_t>(index)] = {};
                        }
                    }
                    else if (mnemonic.size() > 1 && mnemonic[0] == 'j')
                    {
                        const auto target = Number(first, true);
                        if (!target) { Gap("unresolved-conditional-target", instruction.address); break; }
                        std::optional<bool> concrete;
                        if (state.condition.constant)
                        {
                            const auto& flags = state.condition;
                            if (mnemonic == "je" || mnemonic == "jz") concrete = flags.equal;
                            else if (mnemonic == "jne" || mnemonic == "jnz") concrete = !flags.equal;
                            else if (mnemonic == "jb" || mnemonic == "jc" || mnemonic == "jnae") concrete = flags.below;
                            else if (mnemonic == "jae" || mnemonic == "jnb" || mnemonic == "jnc") concrete = !flags.below;
                            else if (mnemonic == "jbe" || mnemonic == "jna") concrete = flags.below || flags.equal;
                            else if (mnemonic == "ja" || mnemonic == "jnbe") concrete = !flags.below && !flags.equal;
                            else if (mnemonic == "jl" || mnemonic == "jnge") concrete = flags.signedBelow;
                            else if (mnemonic == "jge" || mnemonic == "jnl") concrete = !flags.signedBelow;
                            else if (mnemonic == "jle" || mnemonic == "jng") concrete = flags.signedBelow || flags.equal;
                            else if (mnemonic == "jg" || mnemonic == "jnle") concrete = !flags.signedBelow && !flags.equal;
                        }
                        if (concrete)
                        {
                            PathCondition(state, instruction, *concrete);
                            ++result.reversePrunedPaths;
                            if (*concrete) state.pc = *target;
                            state.condition = {};
                            if (!state.pc) break;
                            continue;
                        }
                        State taken = state;
                        taken.pc = *target;
                        PathCondition(state, instruction, false);
                        PathCondition(taken, instruction, true);
                        const bool equal = mnemonic == "je" || mnemonic == "jz";
                        const bool unequal = mnemonic == "jne" || mnemonic == "jnz";
                        if (state.condition.ioctlComparison && (equal || unequal))
                        {
                            State& matching = equal ? taken : state;
                            if (matching.ioctl && *matching.ioctl != state.condition.code)
                            {
                                if (equal) taken.pc = 0; else state.pc = 0;
                            }
                            else matching.ioctl = state.condition.code;
                            State& nonmatching = equal ? state : taken;
                            if (nonmatching.ioctl && *nonmatching.ioctl == state.condition.code) nonmatching.pc = 0;
                        }
                        if (state.condition.guardComparison)
                        {
                            const auto key = Key(state.condition.symbolic);
                            state.guardedValues.insert(key); taken.guardedValues.insert(key);
                            Note(state, state.condition.text); Note(taken, state.condition.text);
                        }
                        if (state.condition.constrained && (!state.condition.equalityOnly || equal || unequal))
                        {
                            if (state.pc && !Constrain(state, state.condition.symbolic, state.condition.bound, mnemonic, false))
                            { state.pc = 0; ++result.reversePrunedPaths; }
                            if (taken.pc && !Constrain(taken, state.condition.symbolic, state.condition.bound, mnemonic, true))
                            { taken.pc = 0; ++result.reversePrunedPaths; }
                        }
                        else if (state.condition.ioctlComparison && (equal || unequal))
                        {
                            Value ioctl{ Kind::Ioctl, 0, 0, "IO_STACK_LOCATION.IoControlCode", 32 };
                            if (state.pc && !Constrain(state, ioctl, state.condition.code, mnemonic, false))
                            { state.pc = 0; ++result.reversePrunedPaths; }
                            if (taken.pc && !Constrain(taken, ioctl, state.condition.code, mnemonic, true))
                            { taken.pc = 0; ++result.reversePrunedPaths; }
                        }
                        state.condition = {}; taken.condition = {};
                        if (taken.pc)
                        {
                            if (pending.size() < 128) pending.push_back(std::move(taken)); else Gap("pending-state-budget", instruction.address);
                        }
                    }
                    else if (mnemonic == "cmp" || mnemonic == "test")
                    {
                        const Value left = Read(first, state, instruction, handler);
                        const Value right = Read(second, state, instruction, handler);
                        state.condition = {};
                        state.condition.text = parsed->second.conditionText;
                        if (left.kind == Kind::Constant && right.kind == Kind::Constant)
                        {
                            const auto bits = Width(first);
                            const std::uint64_t mask = bits == 64 ? ~0ULL : (1ULL << bits) - 1;
                            const auto a = left.number & mask;
                            const auto b = right.number & mask;
                            state.condition.constant = true;
                            if (mnemonic == "test")
                            {
                                state.condition.equal = (a & b) == 0;
                                // TEST clears CF/OF. Signed tests other than zero are left unmodeled.
                                state.condition.below = false;
                                state.condition.signedBelow = ((a & b) & (1ULL << (bits - 1))) != 0;
                            }
                            else
                            {
                                state.condition.equal = a == b;
                                state.condition.below = a < b;
                                state.condition.signedBelow = (a ^ (1ULL << (bits - 1))) < (b ^ (1ULL << (bits - 1)));
                            }
                        }
                        else if (mnemonic == "cmp" && left.kind == Kind::Ioctl && left.bits == 32 && right.kind == Kind::Constant)
                        {
                            state.condition.ioctlComparison = true;
                            state.condition.code = static_cast<std::uint32_t>(right.number - left.offset);
                        }
                        else if (mnemonic == "test" && first == second && left.kind == Kind::Ioctl && left.bits == 32)
                        {
                            state.condition.ioctlComparison = true;
                            state.condition.code = static_cast<std::uint32_t>(-left.offset);
                        }
                        if (mnemonic == "cmp" && Symbolic(left) && right.kind == Kind::Constant && left.offset == 0)
                        {
                            state.condition.symbolic = left;
                            state.condition.bound = right.number & Mask(Width(first));
                            state.condition.constrained = true;
                            // Null/size checks alone do not validate a caller-supplied address.
                            state.condition.guardComparison = RequestValue(left) && right.number != 0;
                        }
                        else if (mnemonic == "test" && first == second && Symbolic(left) && left.offset == 0)
                        {
                            state.condition.symbolic = left;
                            state.condition.bound = 0;
                            // TEST only establishes zero/nonzero constraints for equality branches.
                            state.condition.constrained = true;
                            state.condition.equalityOnly = true;
                        }
                        else if (RequestValue(left) || RequestValue(right))
                        {
                            state.condition.symbolic = RequestValue(left) ? left : right;
                            state.condition.guardComparison = true;
                        }
                    }
                    else if (mnemonic == "mov" || mnemonic == "movzx" || mnemonic == "movsxd" || mnemonic == "movsx")
                    {
                        Value value = Read(second, state, instruction, handler);
                        if ((mnemonic == "movsx" || mnemonic == "movsxd") && Width(second) < Width(first))
                        {
                            if (value.kind == Kind::Constant)
                            {
                                const auto bits = Width(second);
                                if (value.number & (1ULL << (bits - 1))) value.number |= ~Mask(bits);
                            }
                            else if (Symbolic(value))
                            {
                                Gap("symbolic-sign-extension", instruction.address); state.unknownHelper = true;
                                value.bits = Width(first); value.origin += " (sign extended)";
                            }
                        }
                        Write(first, value, state, instruction, handler);
                    }
                    else if (mnemonic == "lea") Write(first, Address(second, state), state, instruction, handler);
                    else if (mnemonic == "push")
                    {
                        const auto value = Read(first, state, instruction, handler);
                        state.registers[4].offset -= 8; state.stack[state.registers[4].offset] = value;
                        state.stackWidths[state.registers[4].offset] = 64;
                    }
                    else if (mnemonic == "pop")
                    {
                        const auto found = state.stack.find(state.registers[4].offset);
                        Write(first, found == state.stack.end() ? Value{} : found->second, state, instruction, handler);
                        state.registers[4].offset += 8;
                    }
                    else if ((mnemonic == "xor" || mnemonic == "sub") && first == second)
                    {
                        Write(first, { Kind::Constant, 0, 0, "zero" }, state, instruction, handler);
                        state.condition = {};
                        state.condition.constant = true; state.condition.equal = true;
                    }
                    else if (mnemonic == "add" || mnemonic == "sub")
                    {
                        Value value = Read(first, state, instruction, handler);
                        const auto amount = Number(second);
                        state.condition = {};
                        if (!amount || *amount > 0xffffffff) value = {};
                        else if (value.kind == Kind::Constant)
                        {
                            if (mnemonic == "sub") value.number -= *amount;
                            else value.number += *amount;
                        }
                        else
                        {
                            if (value.kind == Kind::Ioctl && mnemonic == "sub")
                            {
                                state.condition.ioctlComparison = true;
                                state.condition.code = static_cast<std::uint32_t>(*amount - value.offset);
                            }
                            value.offset += static_cast<std::int64_t>(*amount) * (mnemonic == "sub" ? -1 : 1);
                        }
                        Write(first, value, state, instruction, handler);
                    }
                    else if (mnemonic == "nop" || mnemonic == "endbr64") {}
                    else if (mnemonic == "int" || mnemonic == "int3" || mnemonic == "ud2") break;
                    else
                    {
                        // Unsupported instructions must not preserve stale taint or flags.
                        const int destination = Register(first);
                        if (destination >= 0)
                        {
                            state.registers[static_cast<std::size_t>(destination)] = {};
                        }
                        else if (first.find('[') != std::string::npos) state.unknownHelper = true;
                        state.condition = {};
                        state.unknownHelper = true;
                        Gap("unmodeled-instruction:" + mnemonic, instruction.address);
                    }
                    if (!state.pc) break;
                    if (step == 2999) Gap("path-step-budget", instruction.address);
                }
            }
        }

    public:
        Analyzer(const reverse::Program& binary, scanner::DriverAnalysis& analysis) : program(binary), result(analysis)
        {
            for (const auto& symbol : program.imports)
            {
                const auto module = Lower(symbol.module);
                if (module == "ntoskrnl.exe" || module == "ntkrnlmp.exe" || module == "hal.dll")
                    imported.emplace(symbol.address, symbol.name);
            }
        }
        void Run()
        {
            Walk(program.entry, 0);
            // Handler analysis must not change the recovered registrations.
            const auto registered = handlers;
            for (const auto& handler : registered)
            {
                result.dispatchHandlerRvas.push_back(static_cast<std::uint32_t>(handler.first - program.imageBase));
                Walk(handler.first, handler.first);
            }
            result.reverseAnalysisIncomplete = limited || handlers.empty();
            if (handlers.empty()) Gap("wdm-handler-not-recovered");
            result.reverseDecodedInstructions = code.size();
            result.reverseFunctions = attempted.size();
            result.reverseStates = states;
            result.reverseAnalysis = handlers.empty() ? "No WDM device-control handler recovered within the modeled DriverEntry flow; KMDF and runtime registration require separate analysis." :
                limited ? "WDM source-to-operation analysis reached unsupported control flow or resource bounds; review coverage is partial." :
                "Bounded x64 WDM handler paths analyzed; findings include request-field provenance and operation locations.";
            if (limited)
                for (auto& finding : result.findings) finding.limitations.push_back("Other paths or callees were not completely modeled; this result does not establish that checks are absent elsewhere.");
        }
    };
}

void reverse::AnalyzeWdmX64(const Program& program, scanner::DriverAnalysis& analysis)
{
    Analyzer(program, analysis).Run();
}
