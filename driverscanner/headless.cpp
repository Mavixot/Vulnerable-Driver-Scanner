#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shellapi.h>

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "headless.h"
#include "scanner.h"
#include "version.h"

namespace
{
    std::string Json(const std::string& value)
    {
        std::ostringstream output;
        output << '"';
        for (unsigned char character : value)
        {
            switch (character)
            {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20)
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<unsigned int>(character) << std::dec;
                else output << static_cast<char>(character);
            }
        }
        output << '"';
        return output.str();
    }

    void Diagnostic(const std::string& text)
    {
        HANDLE stream = GetStdHandle(STD_ERROR_HANDLE);
        if (stream == INVALID_HANDLE_VALUE || !stream) return;
        DWORD written = 0;
        WriteFile(stream, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    }

    void ResultJson(std::ostringstream& output, const scanner::DriverAnalysis& result, bool catalogAvailable)
    {
        output << "{\"path\":" << Json(scanner::WideToUtf8(result.path.wstring()))
               << ",\"parsed\":" << (result.parseSucceeded ? "true" : "false")
               << ",\"error\":" << Json(result.parseError)
               << ",\"assessment\":" << Json(result.Assessment())
               << ",\"review_required\":" << (result.IsCandidate() || !result.findings.empty() ? "true" : "false")
               << ",\"evidence_category\":" << Json(scanner::EvidenceLabel(result.Evidence()))
               << ",\"evidence_basis\":" << Json(scanner::EvidenceDescription(result.Evidence()))
               << ",\"coverage_status\":" << Json(result.CoverageStatus())
               << ",\"validation_status\":\"not-performed\""
               << ",\"blocklist_match\":" << (result.knownVulnerable ? "true" : "false")
               << ",\"policy_lookup_status\":" << Json(result.knownVulnerable ? "hash-match" :
                   !catalogAvailable || result.authenticodeSha256.empty() ? "unavailable" : "no-hash-match")
               << ",\"blocklist_rule\":" << Json(result.knownVulnerableLabel)
               << ",\"blocklist_source\":" << Json(result.knownVulnerableSource)
               << ",\"sha256\":" << Json(result.sha256)
               << ",\"authenticode_sha256\":" << Json(result.authenticodeSha256)
               << ",\"hash_error\":" << Json(result.hashError)
               << ",\"embedded_signature\":" << Json(result.signatureSource == "embedded" ? scanner::SignatureStatusText(result.signature) : "not-verified")
               << ",\"certificate_status\":" << Json(scanner::CertificateStatusText(result))
               << ",\"signature_source\":" << Json(result.signatureSource)
               << ",\"revocation_status\":\"not-checked-offline\""
               << ",\"company\":" << Json(result.companyName)
               << ",\"version\":" << Json(result.fileVersion)
               << ",\"code_analysis\":" << Json(result.codeAnalysis)
               << ",\"instruction_boundaries_verified\":"
               << (result.instructionBoundariesVerified ? "true" : "false")
               << ",\"instruction_verification_error\":" << Json(result.instructionVerificationError)
               << ",\"reverse_analysis\":" << Json(result.reverseAnalysis)
               << ",\"reverse_analysis_incomplete\":" << (result.reverseAnalysisIncomplete ? "true" : "false")
               << ",\"reverse_instruction_steps\":" << result.reverseInstructions
               << ",\"reverse_decoded_instructions\":" << result.reverseDecodedInstructions
               << ",\"reverse_function_regions\":" << result.reverseFunctions
               << ",\"reverse_states\":" << result.reverseStates
               << ",\"reverse_pruned_paths\":" << result.reversePrunedPaths
               << ",\"reverse_elapsed_ms\":" << result.reverseElapsedMilliseconds
               << ",\"reverse_coverage_reasons\":[";
        for (std::size_t index = 0; index < result.reverseCoverageReasons.size(); ++index)
        {
            if (index) output << ',';
            output << Json(result.reverseCoverageReasons[index]);
        }
        output << ']'
               << ",\"dispatch_byte_pattern_unverified\":"
               << (result.ioControlDispatchPattern ? "true" : "false")
               << ",\"broad_sddl_allow_ace_unverified\":"
               << (result.permissiveSecurityDescriptor ? "true" : "false")
               << ",\"unsafe_buffer_api_import\":"
               << (result.unsafeUserBufferApi ? "true" : "false")
               << ",\"imports\":[";
        for (std::size_t index = 0; index < result.matches.size(); ++index)
        {
            if (index) output << ',';
            const auto& match = result.matches[index];
            output << "{\"name\":" << Json(match.importedName)
                   << ",\"kind\":" << Json(scanner::IndicatorKindText(match.rule.kind)) << '}';
        }
        output << "],\"ioctl_byte_patterns_unverified\":[";
        for (std::size_t index = 0; index < result.ioctlEvidence.size(); ++index)
        {
            if (index) output << ',';
            const auto& evidence = result.ioctlEvidence[index];
            output << "{\"value\":" << evidence.code
                   << ",\"file_offset\":" << evidence.fileOffset
                   << ",\"method\":" << Json(scanner::IoctlMethodText(evidence.method))
                   << ",\"access\":" << Json(scanner::IoctlAccessText(evidence.access)) << '}';
        }
        output << "],\"wdm_handler_rvas\":[";
        for (std::size_t index = 0; index < result.dispatchHandlerRvas.size(); ++index)
        {
            if (index) output << ',';
            output << result.dispatchHandlerRvas[index];
        }
        output << "],\"flow_findings\":[";
        for (std::size_t index = 0; index < result.findings.size(); ++index)
        {
            if (index) output << ',';
            const auto& finding = result.findings[index];
            output << "{\"rule\":" << Json(finding.rule)
                   << ",\"title\":" << Json(finding.title)
                   << ",\"access\":" << Json(finding.access)
                   << ",\"trace_status\":" << Json(finding.confidence)
                   << ",\"review_only\":" << (finding.reviewOnly ? "true" : "false")
                   << ",\"ioctl\":" << finding.ioctl
                   << ",\"handler_rva\":" << finding.handlerRva
                   << ",\"operation_rva\":" << finding.operationRva
                   << ",\"file_offset\":" << finding.fileOffset
                   << ",\"source_rva\":" << finding.sourceRva
                   << ",\"source_expression\":" << Json(finding.sourceExpression)
                   << ",\"access_size_bytes\":" << finding.accessSize
                   << ",\"path_conditions\":[";
            for (std::size_t condition = 0; condition < finding.pathConditions.size(); ++condition)
            {
                if (condition) output << ',';
                output << Json(finding.pathConditions[condition]);
            }
            output << ']'
                   << ",\"validation_status\":\"not-performed\",\"evidence\":[";
            for (std::size_t evidence = 0; evidence < finding.evidence.size(); ++evidence)
            {
                if (evidence) output << ',';
                output << Json(finding.evidence[evidence]);
            }
            output << "],\"limitations\":[";
            for (std::size_t limitation = 0; limitation < finding.limitations.size(); ++limitation)
            {
                if (limitation) output << ',';
                output << Json(finding.limitations[limitation]);
            }
            output << "],\"related_operation_rvas\":[";
            for (std::size_t location = 0; location < finding.relatedOperationRvas.size(); ++location)
            {
                if (location) output << ',';
                output << finding.relatedOperationRvas[location];
            }
            output << "]}";
        }
        output << "]}";
    }
}

bool scanner::TryRunHeadless(int& exitCode)
{
    int argumentCount = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (!arguments)
    {
        exitCode = 2;
        return true;
    }
    if (argumentCount <= 1)
    {
        LocalFree(arguments);
        return false;
    }
    if (argumentCount == 2 && (std::wstring(arguments[1]) == L"--help" || std::wstring(arguments[1]) == L"--version"))
    {
        const bool help = std::wstring(arguments[1]) == L"--help";
        LocalFree(arguments);
        Diagnostic(std::string("Driver Scanner ") + app::VersionUtf8 + "\r\n");
        if (help) Diagnostic("Usage: \"Driver Scanner.exe\" --scan FOLDER --output NEW-REPORT.json\r\n"
            "Read-only recursive static analysis. JSON schema 2. Existing reports are preserved.\r\n"
            "Exit codes: 0 modeled checks finished, 1 incomplete coverage, 2 invalid arguments, 3 report I/O error, 4 unexpected error.\r\n"
            "Evidence categories describe observations, not vulnerability severity or detection probability.\r\n");
        if (help) Diagnostic("Instruction analysis requires installed Visual Studio C++ tools (dumpbin.exe). Drivers are never loaded.\r\n");
        exitCode = 0;
        return true;
    }

    std::filesystem::path inputFolder;
    std::filesystem::path reportPath;
    bool valid = true;
    for (int index = 1; index < argumentCount; ++index)
    {
        const std::wstring argument(arguments[index]);
        if (argument == L"--scan" && index + 1 < argumentCount && inputFolder.empty())
            inputFolder = arguments[++index];
        else if (argument == L"--output" && index + 1 < argumentCount && reportPath.empty())
            reportPath = arguments[++index];
        else valid = false;
    }
    LocalFree(arguments);

    std::error_code error;
    if (!valid || inputFolder.empty() || reportPath.empty() ||
        !std::filesystem::is_directory(inputFolder, error))
    {
        Diagnostic("Usage: \"Driver Scanner.exe\" --scan FOLDER --output NEW-REPORT.json\r\n");
        exitCode = 2;
        return true;
    }

    HANDLE report = CreateFileW(reportPath.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (report == INVALID_HANDLE_VALUE)
    {
        Diagnostic("Report must be a new file in an existing writable directory.\r\n");
        exitCode = 3;
        return true;
    }

    SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    exitCode = 0;
    try
    {
        std::vector<std::string> warnings;
        const auto files = GetDriverFiles(inputFolder, true, warnings);
        std::string catalogSource;
        std::string catalogError;
        const auto catalog = LoadMicrosoftVulnerableDriverBlocklist(catalogSource, catalogError);
        const auto rules = DefaultRules();
        std::vector<DriverAnalysis> results;
        std::size_t parseErrors = 0;
        std::size_t hashErrors = 0;
        std::size_t verificationErrors = 0;
        std::size_t flowFindings = 0;
        std::size_t flowCandidates = 0;
        std::size_t flowReviewTraces = 0;
        std::size_t recoveredHandlers = 0;
        std::size_t partialReverseCoverage = 0;
        std::size_t blocklistMatches = 0;
        std::size_t staticLeads = 0;
        for (const auto& file : files)
        {
            auto result = AnalyzeDriver(file, rules, catalog);
            if (!result.parseSucceeded) ++parseErrors;
            if (!result.hashError.empty()) ++hashErrors;
            if (!result.instructionVerificationError.empty()) ++verificationErrors;
            flowFindings += result.findings.size();
            for (const auto& finding : result.findings)
            {
                if (finding.reviewOnly) ++flowReviewTraces;
                else ++flowCandidates;
            }
            recoveredHandlers += result.dispatchHandlerRvas.size();
            if (result.reverseAnalysisIncomplete) ++partialReverseCoverage;
            if (result.knownVulnerable) ++blocklistMatches;
            else if (result.IsCandidate() && !result.HasDataflowCandidate()) ++staticLeads;
            results.push_back(std::move(result));
        }
        std::sort(results.begin(), results.end(), ReviewBefore);

        std::ostringstream output;
        output << "{\n\"schema_version\":" << app::ReportSchema
               << ",\n\"tool\":\"Driver Scanner\",\n\"tool_version\":" << Json(app::VersionUtf8)
               << ",\n\"mode\":\"offline-static-review\",\n"
               << "\"disassembler_available\":" << (DisassemblerPath().empty() ? "false" : "true") << ",\n"
               << "\"scanned\":" << results.size()
               << ",\n\"blocklist_matches\":" << blocklistMatches
               << ",\n\"pattern_lead_count\":" << staticLeads
               << ",\n\"parse_errors\":" << parseErrors
               << ",\n\"hash_errors\":" << hashErrors
               << ",\n\"instruction_verification_errors\":" << verificationErrors
               << ",\n\"flow_finding_count\":" << flowFindings
               << ",\n\"request_flow_count\":" << flowCandidates
               << ",\n\"qualified_flow_count\":" << flowReviewTraces
               << ",\n\"recovered_wdm_handlers\":" << recoveredHandlers
               << ",\n\"drivers_with_partial_reverse_coverage\":" << partialReverseCoverage
               << ",\n\"catalog_rules\":" << catalog.size()
               << ",\n\"catalog_source\":" << Json(catalogSource)
               << ",\n\"catalog_warning\":" << Json(catalogError)
               << ",\n\"evidence_scale\":\"Categorical evidence only; no calibrated detection probability or vulnerability severity is assigned.\""
               << ",\n\"catalog_coverage\":\"Installed XML Authenticode SHA-256 deny rules only; signer, version and page-hash rules are not evaluated. No hit does not establish safety.\""
               << ",\n\"reverse_coverage\":\"Bounded Windows x64 WDM dispatch recovery and request-field tracing with a 10 second per-driver reversing budget. KMDF, unresolved indirect calls, exception paths and unmodeled instructions require manual analysis. No finding does not establish safety.\""
               << ",\n\"warnings\":[";
        for (std::size_t index = 0; index < warnings.size(); ++index)
        {
            if (index) output << ',';
            output << Json(warnings[index]);
        }
        output << "],\n\"drivers\":[\n";
        for (std::size_t index = 0; index < results.size(); ++index)
        {
            if (index) output << ",\n";
            ResultJson(output, results[index], !catalog.empty() && catalogError.empty());
        }
        output << "\n]}\n";

        const std::string data = output.str();
        std::size_t position = 0;
        while (position < data.size())
        {
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(data.size() - position, 1024 * 1024));
            DWORD written = 0;
            if (!WriteFile(report, data.data() + position, chunk, &written, nullptr) || written == 0)
            {
                exitCode = 3;
                break;
            }
            position += written;
        }
        if (!FlushFileBuffers(report)) exitCode = 3;
        if (exitCode == 0 && (parseErrors || hashErrors || verificationErrors || partialReverseCoverage || !warnings.empty() || !catalogError.empty()))
            exitCode = 1;
    }
    catch (...)
    {
        Diagnostic("Scan failed unexpectedly; the report may be incomplete.\r\n");
        exitCode = 4;
    }
    CloseHandle(report);
    return true;
}
