#pragma once

#include <filesystem>
#include <cstdint>
#include <string>
#include <vector>

namespace scanner
{
    enum class IndicatorKind
    {
        SensitiveCapability,
        DeviceExposure,
        RequestHandling,
        Safeguard
    };

    struct ImportRule
    {
        std::string name;
        std::string category;
        std::string rationale;
        int weight = 0;
        IndicatorKind kind = IndicatorKind::SensitiveCapability;
    };

    struct ImportMatch
    {
        ImportRule rule;
        std::string importedName;
    };

    struct IoctlEvidence
    {
        unsigned long code = 0;
        unsigned int deviceType = 0;
        unsigned int function = 0;
        unsigned int method = 0;
        unsigned int access = 0;
        std::size_t fileOffset = 0;
        std::string instruction;
    };

    struct KnownVulnerableDriver
    {
        std::string sha256;
        std::string label;
        std::string source;
    };

    enum class SignatureStatus
    {
        Valid,
        Unsigned,
        Invalid,
        CheckError
    };

    // Evidence categories are observations, not calibrated severity or probability.
    enum class EvidenceCategory { AnalysisError, Metadata, Pattern, QualifiedFlow, RequestFlow, PolicyMatch };

    struct FlowFinding
    {
        std::string rule;
        std::string title;
        std::string access;
        std::string confidence;
        std::uint32_t ioctl = 0;
        std::uint32_t handlerRva = 0;
        std::uint32_t operationRva = 0;
        std::size_t fileOffset = 0;
        std::uint32_t sourceRva = 0;
        std::string sourceExpression;
        std::uint64_t accessSize = 0; // Zero means the extent is not statically known.
        std::vector<std::string> pathConditions;
        std::vector<std::string> evidence;
        std::vector<std::string> limitations;
        bool reviewOnly = false;
        std::vector<std::uint32_t> relatedOperationRvas;
    };

    struct DriverAnalysis
    {
        std::filesystem::path path;
        bool parseSucceeded = false;
        std::string parseError;
        std::vector<ImportMatch> matches;
        std::string sha256;
        std::string authenticodeSha256;
        std::string hashError;
        std::string codeAnalysis;
        SignatureStatus signature = SignatureStatus::CheckError;
        long signatureResult = 0;
        std::string signatureSource;
        bool certificatePresent = false;
        bool certificateTimeValid = false;
        bool certificateExpired = false;
        std::string companyName;
        std::string productName;
        std::string fileVersion;
        std::vector<std::string> deviceNames;
        std::vector<std::string> symbolicLinks;
        std::vector<std::string> securityDescriptors;
        std::vector<std::string> requestHandlerClues;
        std::vector<IoctlEvidence> ioctlEvidence;
        bool instructionBoundariesVerified = false;
        std::string instructionVerificationError;
        std::string reverseAnalysis;
        std::vector<std::uint32_t> dispatchHandlerRvas;
        std::vector<FlowFinding> findings;
        std::size_t reverseInstructions = 0;
        std::size_t reverseDecodedInstructions = 0;
        std::size_t reverseFunctions = 0;
        std::size_t reverseStates = 0;
        std::size_t reversePrunedPaths = 0;
        std::uint64_t reverseElapsedMilliseconds = 0;
        std::vector<std::string> reverseCoverageReasons;
        bool reverseAnalysisIncomplete = false;
        bool ioControlDispatchPattern = false;
        bool permissiveSecurityDescriptor = false;
        bool unsafeUserBufferApi = false;
        bool knownVulnerable = false;
        std::string knownVulnerableLabel;
        std::string knownVulnerableSource;

        bool HasSensitiveCapability() const;
        bool HasExposureSignal() const;
        bool HasRequestHandlingSignal() const;
        bool HasSafeguardSignal() const;
        bool HasRiskyIoctl() const;
        bool HasIoctlFamily() const;
        bool HasDataflowCandidate() const;
        bool IsCandidate() const;
        EvidenceCategory Evidence() const;
        std::string CoverageStatus() const;
        std::string Assessment() const;
    };

    std::vector<std::filesystem::path> GetDriverFiles(
        const std::filesystem::path& root,
        bool recursive,
        std::vector<std::string>& discoveryErrors);

    DriverAnalysis AnalyzeDriver(
        const std::filesystem::path& driverPath,
        const std::vector<ImportRule>& rules,
        const std::vector<KnownVulnerableDriver>& knownDrivers = {});

    std::vector<KnownVulnerableDriver> LoadMicrosoftVulnerableDriverBlocklist(
        std::string& source,
        std::string& error);

    std::vector<ImportRule> DefaultRules();
    std::filesystem::path DisassemblerPath();
    const char* IndicatorKindText(IndicatorKind kind);
    const char* SignatureStatusText(SignatureStatus status);
    const char* CertificateStatusText(const DriverAnalysis& analysis);
    const char* EvidenceLabel(EvidenceCategory category);
    const char* EvidenceDescription(EvidenceCategory category);
    bool ReviewBefore(const DriverAnalysis& left, const DriverAnalysis& right);
    const char* IoctlMethodText(unsigned int method);
    const char* IoctlAccessText(unsigned int access);
    std::string WideToUtf8(const std::wstring& value);
}
