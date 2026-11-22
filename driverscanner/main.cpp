#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <CommCtrl.h>
#include <commdlg.h>
#include <shobjidl.h>
#include <uxtheme.h>
#include <richedit.h>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <array>
#include <exception>

#include "scanner.h"
#include "headless.h"
#include "version.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace fs = std::filesystem;

namespace
{
    constexpr wchar_t kWindowClass[] = L"DriverScannerWindow";
    constexpr UINT kMessageScanCount = WM_APP + 1;
    constexpr UINT kMessageScanProgress = WM_APP + 2;
    constexpr UINT kMessageScanResult = WM_APP + 3;
    constexpr UINT kMessageScanDone = WM_APP + 4;

    constexpr int kIdFolder = 1001;
    constexpr int kIdBrowse = 1002;
    constexpr int kIdScan = 1003;
    constexpr int kIdExport = 1004;
    constexpr int kIdResults = 1005;
    constexpr int kIdDetails = 1006;
    constexpr int kIdLog = 1007;
    constexpr int kIdProgress = 1008;
    constexpr int kIdStatus = 1009;
    constexpr int kIdSearch = 1010;
    constexpr int kIdFilter = 1011;
    constexpr int kIdTabs = 1012;
    constexpr int kIdAbout = 1013;
    constexpr int kIdCopy = 1014;
    constexpr COLORREF kBackground = RGB(243, 246, 250);
    constexpr COLORREF kCard = RGB(255, 255, 255);
    constexpr COLORREF kText = RGB(27, 39, 58);
    constexpr COLORREF kMuted = RGB(97, 111, 133);
    constexpr COLORREF kBorder = RGB(220, 227, 237);
    constexpr COLORREF kAccent = RGB(37, 99, 235);

    struct ScanSummary
    {
        std::size_t scanned = 0;
        std::size_t candidates = 0;
        std::size_t knownMatches = 0;
        std::size_t capabilityOnly = 0;
        std::size_t parseErrors = 0;
        std::size_t verificationErrors = 0;
        std::size_t flowFindings = 0;
        std::size_t partialReverseCoverage = 0;
        std::size_t discoveryWarnings = 0;
        std::size_t catalogEntries = 0;
        std::string catalogSource;
        std::string catalogError;
        bool cancelled = false;
        std::string failure;
    };

    struct AppState
    {
        HWND window = nullptr;
        HWND about = nullptr;
        HWND folderLabel = nullptr;
        HWND folder = nullptr;
        HWND browse = nullptr;
        HWND scan = nullptr;
        HWND exportButton = nullptr;
        HWND progress = nullptr;
        HWND status = nullptr;
        HWND resultsLabel = nullptr;
        HWND resultCount = nullptr;
        HWND search = nullptr;
        HWND filter = nullptr;
        HWND emptyHint = nullptr;
        HWND results = nullptr;
        HWND detailsLabel = nullptr;
        HWND details = nullptr;
        HWND logLabel = nullptr;
        HWND log = nullptr;
        HWND tabs = nullptr;
        HWND copyButton = nullptr;
        HWND tooltip = nullptr;
        HFONT font = nullptr;
        HFONT smallFont = nullptr;
        HFONT sectionFont = nullptr;
        HFONT numberFont = nullptr;
        HBRUSH backgroundBrush = nullptr;
        HBRUSH cardBrush = nullptr;
        HIMAGELIST rowImages = nullptr;
        UINT dpi = 96;
        std::array<RECT, 5> metricCards{};
        RECT resultsCard{};
        RECT inspectorCard{};
        RECT folderFrame{};
        scanner::DriverAnalysis* selected = nullptr;
        std::size_t discovered = 0;
        std::size_t catalogEntries = 0;
        std::size_t visibleResults = 0;
        int sortColumn = 1;
        bool sortDescending = true;
        bool refreshing = false;
        bool scanDisplayDirty = false;
        int inspectorTab = 0;
        ULONGLONG scanStart = 0;
        std::wstring inspectorText;
        bool scanning = false;
        bool closing = false;
        std::shared_ptr<std::atomic_bool> cancel;
        std::vector<std::unique_ptr<scanner::DriverAnalysis>> analyses;
    };

    AppState g_state;

    int Dip(int value) { return MulDiv(value, static_cast<int>(g_state.dpi), 96); }

    void ShowDetails(scanner::DriverAnalysis* analysis);

    HMENU ControlId(int identifier)
    {
        return reinterpret_cast<HMENU>(static_cast<INT_PTR>(identifier));
    }

    std::wstring Utf8ToWide(const std::string& value)
    {
        if (value.empty()) return {};
        const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()), nullptr, 0);
        if (required <= 0) return std::wstring(value.begin(), value.end());
        std::wstring result(static_cast<std::size_t>(required), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()), result.data(), required);
        return result;
    }

    std::wstring PathText(const fs::path& value)
    {
        return value.wstring();
    }

    std::wstring GetWindowTextValue(HWND control)
    {
        const int length = GetWindowTextLengthW(control);
        if (length <= 0) return {};
        std::wstring result(static_cast<std::size_t>(length) + 1, L'\0');
        GetWindowTextW(control, result.data(), length + 1);
        result.resize(static_cast<std::size_t>(length));
        return result;
    }

    void SetFont(HWND control, HFONT font)
    {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }

    void AppendLog(const std::wstring& message)
    {
        if (!g_state.log) return;
        int length = GetWindowTextLengthW(g_state.log);
        if (length > 200000)
        {
            SendMessageW(g_state.log, EM_SETSEL, 0, length - 150000);
            SendMessageW(g_state.log, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(L""));
            length = GetWindowTextLengthW(g_state.log);
        }
        SendMessageW(g_state.log, EM_SETSEL, length, length);
        SYSTEMTIME time{};
        GetLocalTime(&time);
        std::wostringstream output;
        output << L'[' << std::setfill(L'0') << std::setw(2) << time.wHour << L':'
               << std::setw(2) << time.wMinute << L':' << std::setw(2) << time.wSecond << L"] " << message << L"\r\n";
        const auto line = output.str();
        SendMessageW(g_state.log, EM_REPLACESEL, FALSE,
            reinterpret_cast<LPARAM>(line.c_str()));
        SendMessageW(g_state.log, EM_SCROLLCARET, 0, 0);
    }

    std::wstring JoinValues(const std::vector<std::string>& values)
    {
        std::wostringstream output;
        for (std::size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0) output << L" | ";
            output << Utf8ToWide(values[index]);
        }
        return output.str();
    }

    std::wstring JoinImports(
        const scanner::DriverAnalysis& analysis,
        scanner::IndicatorKind kind,
        bool includeRationale = false)
    {
        std::wostringstream output;
        bool first = true;
        for (const scanner::ImportMatch& match : analysis.matches)
        {
            if (match.rule.kind != kind) continue;
            if (!first) output << (includeRationale ? L"\r\n" : L" | ");
            output << Utf8ToWide(match.importedName);
            if (includeRationale)
            {
                output << L" - " << Utf8ToWide(match.rule.rationale);
            }
            first = false;
        }
        return output.str();
    }

    std::wstring PotentialAccess(const scanner::DriverAnalysis& analysis)
    {
        if (!analysis.findings.empty())
        {
            std::vector<std::string> access;
            for (const auto& finding : analysis.findings)
                if (std::find(access.begin(), access.end(), finding.access) == access.end()) access.push_back(finding.access);
            return JoinValues(access) + L" (traced)";
        }
        bool read = false;
        bool write = false;
        bool mapping = false;
        bool addressOnly = false;

        for (const scanner::ImportMatch& match : analysis.matches)
        {
            if (match.rule.kind != scanner::IndicatorKind::SensitiveCapability) continue;
            const std::string& name = match.importedName;
            const std::string& category = match.rule.category;

            if (name == "ZwReadVirtualMemory" || name == "MmCopyMemory") read = true;
            if (name == "ZwWriteVirtualMemory") write = true;
            if (name == "MmCopyVirtualMemory")
            {
                read = true;
                write = true;
            }
            if (category.find("mapping") != std::string::npos ||
                category == "MDL mapping" || name == "MmMapIoSpace" || name == "MmMapIoSpaceEx")
            {
                mapping = true;
            }
            if (category == "address translation" || category == "bus address translation")
            {
                addressOnly = true;
            }
        }

        if (mapping) return L"Mapping API (unverified)";
        if (read && write) return L"Read/write APIs (unverified)";
        if (write) return L"Write API (unverified)";
        if (read) return L"Read API (unverified)";
        if (addressOnly) return L"Address primitive only";
        return analysis.HasSensitiveCapability() ? L"Sensitive API (import)" : L"None traced";
    }

    std::wstring InterfaceSummary(const scanner::DriverAnalysis& analysis)
    {
        if (analysis.knownVulnerable) return L"Authenticode SHA-256 hit";
        const std::wstring imports = JoinImports(analysis, scanner::IndicatorKind::DeviceExposure);
        if (!imports.empty()) return imports;
        return L"No API signal";
    }

    std::wstring SignatureText(const scanner::DriverAnalysis& analysis)
    {
        if (analysis.certificatePresent && analysis.certificateExpired) return L"Expired";
        if (analysis.signature == scanner::SignatureStatus::Valid && analysis.certificatePresent && analysis.certificateTimeValid) return L"Valid";
        return L"None";
    }

    std::wstring IoctlEvidenceText(const scanner::DriverAnalysis& analysis, bool multiline)
    {
        std::wostringstream output;
        for (std::size_t index = 0; index < analysis.ioctlEvidence.size(); ++index)
        {
            const scanner::IoctlEvidence& evidence = analysis.ioctlEvidence[index];
            if (index != 0) output << (multiline ? L"\r\n" : L" | ");
            output << L"0x" << std::hex << std::uppercase << std::setw(8)
                   << std::setfill(L'0') << evidence.code << std::dec << std::nouppercase
                   << L"  " << Utf8ToWide(scanner::IoctlMethodText(evidence.method))
                   << L"  " << Utf8ToWide(scanner::IoctlAccessText(evidence.access));
            if (multiline)
            {
                output << L"  function=0x" << std::hex << evidence.function << std::dec
                       << L"  file+0x" << std::hex << evidence.fileOffset << std::dec
                       << L"  (" << Utf8ToWide(evidence.instruction) << L")";
            }
        }
        return output.str();
    }

    void SetListText(HWND list, int row, int column, const std::wstring& value)
    {
        ListView_SetItemText(list, row, column, const_cast<wchar_t*>(value.c_str()));
    }

    void InsertAnalysisRow(int row, scanner::DriverAnalysis* analysis)
    {
        const std::wstring name = PathText(analysis->path.filename());
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = row;
        item.pszText = const_cast<wchar_t*>(name.c_str());
        item.lParam = reinterpret_cast<LPARAM>(analysis);
        const int inserted = ListView_InsertItem(g_state.results, &item);
        if (inserted < 0) return;

        SetListText(g_state.results, inserted, 1, Utf8ToWide(scanner::EvidenceLabel(analysis->Evidence())));
        SetListText(g_state.results, inserted, 2, analysis->findings.empty() ? L"None traced" : PotentialAccess(*analysis));
        SetListText(g_state.results, inserted, 3, std::to_wstring(analysis->findings.size()));
        SetListText(g_state.results, inserted, 4, Utf8ToWide(analysis->CoverageStatus()));
        SetListText(g_state.results, inserted, 5, Utf8ToWide(analysis->companyName.empty() ? "Unavailable" : analysis->companyName));
        SetListText(g_state.results, inserted, 6, SignatureText(*analysis));
    }

    bool ContainsText(const std::wstring& value, const std::wstring& search)
    {
        if (search.empty()) return true;
        if (search.size() > value.size()) return false;
        for (std::size_t index = 0; index <= value.size() - search.size(); ++index)
            if (CompareStringOrdinal(value.data() + index, static_cast<int>(search.size()), search.data(),
                static_cast<int>(search.size()), TRUE) == CSTR_EQUAL) return true;
        return false;
    }

    bool MatchesFilter(const scanner::DriverAnalysis& analysis, int filter, const std::wstring& query)
    {
        using Category = scanner::EvidenceCategory;
        const auto category = analysis.Evidence();
        if ((filter == 1 && category != Category::RequestFlow) ||
            (filter == 2 && category != Category::QualifiedFlow) ||
            (filter == 3 && category != Category::PolicyMatch) ||
            (filter == 4 && category != Category::Pattern) ||
            (filter == 5 && analysis.CoverageStatus() != "partial" && analysis.CoverageStatus() != "unavailable") ||
            (filter == 6 && category != Category::AnalysisError)) return false;
        return ContainsText(analysis.path.wstring(), query) || ContainsText(Utf8ToWide(analysis.companyName), query) ||
            ContainsText(Utf8ToWide(analysis.sha256), query) || ContainsText(Utf8ToWide(analysis.authenticodeSha256), query);
    }

    void SortResults()
    {
        std::sort(g_state.analyses.begin(), g_state.analyses.end(), [](const auto& left, const auto& right) {
            int order = 0;
            if (g_state.sortColumn == 1) order = static_cast<int>(left->Evidence()) - static_cast<int>(right->Evidence());
            else if (g_state.sortColumn == 3) order = left->findings.size() < right->findings.size() ? -1 : left->findings.size() > right->findings.size() ? 1 : 0;
            else
            {
                std::wstring a, b;
                switch (g_state.sortColumn)
                {
                case 0: a = left->path.filename().wstring(); b = right->path.filename().wstring(); break;
                case 2: a = PotentialAccess(*left); b = PotentialAccess(*right); break;
                case 4: a = Utf8ToWide(left->CoverageStatus()); b = Utf8ToWide(right->CoverageStatus()); break;
                case 5: a = Utf8ToWide(left->companyName); b = Utf8ToWide(right->companyName); break;
                default: a = SignatureText(*left); b = SignatureText(*right); break;
                }
                order = CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) - CSTR_EQUAL;
            }
            if (order) return g_state.sortDescending ? order > 0 : order < 0;
            return left->path < right->path;
        });
        HWND header = ListView_GetHeader(g_state.results);
        for (int column = 0; column < 7; ++column)
        {
            HDITEMW item{}; item.mask = HDI_FORMAT;
            Header_GetItem(header, column, &item);
            item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
            if (column == g_state.sortColumn) item.fmt |= g_state.sortDescending ? HDF_SORTDOWN : HDF_SORTUP;
            Header_SetItem(header, column, &item);
        }
    }

    void PopulateResults()
    {
        g_state.refreshing = true;
        SendMessageW(g_state.results, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(g_state.results);
        const auto query = GetWindowTextValue(g_state.search);
        const int filter = static_cast<int>(SendMessageW(g_state.filter, CB_GETCURSEL, 0, 0));
        int selectedRow = -1;
        int row = 0;
        for (std::size_t index = 0; index < g_state.analyses.size(); ++index)
        {
            auto* analysis = g_state.analyses[index].get();
            if (!MatchesFilter(*analysis, filter, query)) continue;
            if (g_state.selected == analysis) selectedRow = row;
            InsertAnalysisRow(row++, analysis);
        }
        g_state.visibleResults = static_cast<std::size_t>(row);
        if (row)
        {
            if (selectedRow < 0) selectedRow = 0;
            ListView_SetItemState(g_state.results, selectedRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            LVITEMW item{}; item.mask = LVIF_PARAM; item.iItem = selectedRow;
            if (ListView_GetItem(g_state.results, &item)) g_state.selected = reinterpret_cast<scanner::DriverAnalysis*>(item.lParam);
        }
        else g_state.selected = nullptr;
        SendMessageW(g_state.results, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(g_state.results, nullptr, TRUE);
        SetWindowTextW(g_state.resultCount, (std::to_wstring(row) + L" of " + std::to_wstring(g_state.analyses.size())).c_str());
        SetWindowTextW(g_state.emptyHint, g_state.analyses.empty() ?
            (g_state.scanning ? L"Analysis is running.\r\nResults will appear as each image finishes." : L"Choose a directory and start analysis.\r\nDriver evidence will appear here.") :
            L"No results match your search and filter.");
        ShowWindow(g_state.emptyHint, row ? SW_HIDE : SW_SHOWNA);
        g_state.refreshing = false;
        ShowDetails(g_state.selected);
    }

    void AppendEvidenceSection(
        std::wostringstream& output,
        const wchar_t* heading,
        const scanner::DriverAnalysis& analysis,
        scanner::IndicatorKind kind)
    {
        output << L"\r\n" << heading << L"\r\n";
        const std::wstring content = JoinImports(analysis, kind, true);
        output << (content.empty() ? L"None observed statically." : content) << L"\r\n";
    }

    void SetInspectorText(const std::wstring& text)
    {
        if (g_state.inspectorText == text) return;
        g_state.inspectorText = text;
        SetWindowTextW(g_state.details, text.c_str());
        CHARFORMAT2W format{};
        format.cbSize = sizeof(format);
        format.dwMask = CFM_BOLD | CFM_COLOR;
        format.crTextColor = kText;
        SendMessageW(g_state.details, EM_SETCHARFORMAT, SCF_ALL, reinterpret_cast<LPARAM>(&format));
        const std::array<const wchar_t*, 7> headings = {
            L"Evidence overview", L"Artifact", L"Policy lookup", L"Recorded observations",
            L"Analysis coverage", L"Coverage gaps", L"Static indicators"
        };
        format.dwEffects = CFE_BOLD;
        for (const auto* heading : headings)
        {
            FINDTEXTEXW find{};
            find.chrg = {0,-1}; find.lpstrText = const_cast<wchar_t*>(heading);
            if (SendMessageW(g_state.details, EM_FINDTEXTEXW, FR_DOWN, reinterpret_cast<LPARAM>(&find)) < 0) continue;
            SendMessageW(g_state.details, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&find.chrgText));
            SendMessageW(g_state.details, EM_SETCHARFORMAT, SCF_SELECTION, reinterpret_cast<LPARAM>(&format));
        }
        SendMessageW(g_state.details, EM_SETSEL, 0, 0);
        SendMessageW(g_state.details, EM_SCROLLCARET, 0, 0);
    }

    void ShowDetails(scanner::DriverAnalysis* analysis)
    {
        g_state.selected = analysis;
        const bool activity = g_state.inspectorTab == 3;
        ShowWindow(g_state.details, activity ? SW_HIDE : SW_SHOWNA);
        ShowWindow(g_state.log, activity ? SW_SHOWNA : SW_HIDE);
        EnableWindow(g_state.copyButton, activity || analysis != nullptr);
        SetWindowTextW(g_state.detailsLabel, activity ? L"Session activity" :
            analysis ? analysis->path.filename().c_str() : L"Inspector");
        if (activity) return;
        if (!analysis)
        {
            SetInspectorText(L"Select a driver to inspect its evidence.\r\n\r\n"
                L"Evidence categories describe observed code paths and policy matches. They are not severity scores or detection probabilities.\r\n\r\n"
                L"Coverage is reported separately. An empty findings list does not establish that a driver is safe.");
            return;
        }
        std::wostringstream output;
        if (g_state.inspectorTab == 0)
        {
            output << L"Evidence overview\r\n"
                   << Utf8ToWide(scanner::EvidenceLabel(analysis->Evidence())) << L"\r\n\r\n"
                   << Utf8ToWide(scanner::EvidenceDescription(analysis->Evidence())) << L"\r\n\r\n"
                   << L"Coverage: " << Utf8ToWide(analysis->CoverageStatus()) << L"\r\n"
                   << L"Recorded observations: " << analysis->findings.size() << L"\r\n"
                   << L"Runtime validation: not performed\r\n";
            if (!analysis->parseError.empty()) output << L"\r\nError: " << Utf8ToWide(analysis->parseError) << L"\r\n";
            output << L"\r\nArtifact\r\n"
                   << L"Company (metadata): " << Utf8ToWide(analysis->companyName.empty() ? "Unavailable" : analysis->companyName) << L"\r\n"
                   << L"Product: " << Utf8ToWide(analysis->productName) << L"\r\n"
                   << L"Version: " << Utf8ToWide(analysis->fileVersion) << L"\r\n"
                   << L"Certificate: " << SignatureText(*analysis) << L"\r\n"
                   << L"Verification: " << Utf8ToWide(scanner::CertificateStatusText(*analysis)) << L"\r\n"
                   << L"Signature source: " << Utf8ToWide(analysis->signatureSource) << L"\r\n"
                   << L"Path: " << analysis->path.wstring() << L"\r\n\r\n"
                   << L"SHA-256\r\n" << Utf8ToWide(analysis->sha256.empty() ? "Unavailable" : analysis->sha256) << L"\r\n\r\n"
                   << L"Authenticode SHA-256\r\n" << Utf8ToWide(analysis->authenticodeSha256.empty() ? "Unavailable" : analysis->authenticodeSha256) << L"\r\n";
            if (!analysis->hashError.empty()) output << L"Hash error: " << Utf8ToWide(analysis->hashError) << L"\r\n";
            output << L"\r\nPolicy lookup\r\n";
            if (analysis->knownVulnerable) output << Utf8ToWide(analysis->knownVulnerableLabel);
            else if (analysis->authenticodeSha256.empty()) output << L"Image hash unavailable; lookup could not establish a match.";
            else if (g_state.scanning) output << L"Session in progress. Catalog coverage will be reported on completion.";
            else if (!g_state.catalogEntries) output << L"No deny-hash catalog was loaded. Lookup coverage is unavailable.";
            else output << L"No exact match among " << g_state.catalogEntries << L" loaded Authenticode deny hashes.";
            output << L"\r\n\r\nSigner, version and page-hash deny rules are not evaluated. Embedded and installed catalog signatures are checked offline. Live revocation status is not established; timestamped signatures may remain trusted after certificate expiry.";
        }
        else if (g_state.inspectorTab == 1)
        {
            output << L"Recorded observations\r\n";
            if (analysis->findings.empty())
                output << L"No request-to-operation observation was recovered.\r\n\r\nInspect the Coverage tab for unsupported paths and analysis limits.\r\n";
            std::size_t index = 0;
            for (const auto& finding : analysis->findings)
            {
                output << L"\r\n" << ++index << L". " << Utf8ToWide(finding.title) << L"\r\n"
                       << L"Category: " << (finding.reviewOnly ? L"Qualified flow" : L"Request flow") << L"\r\n"
                       << L"Operation: " << Utf8ToWide(finding.access) << L"\r\n"
                       << L"Rule: " << Utf8ToWide(finding.rule) << L"\r\n"
                       << L"IOCTL: 0x" << std::hex << finding.ioctl
                       << L"  Handler RVA: 0x" << finding.handlerRva << L"\r\n"
                       << L"Source RVA: 0x" << finding.sourceRva << L"\r\n"
                       << L"Operation RVA: 0x" << finding.operationRva << L"  File offset: 0x" << finding.fileOffset << std::dec << L"\r\n"
                       << L"Access extent: " << (finding.accessSize ? std::to_wstring(finding.accessSize) + L" bytes" : L"unknown") << L"\r\n";
                if (!finding.relatedOperationRvas.empty())
                {
                    output << L"Other operation RVAs:";
                    for (auto rva : finding.relatedOperationRvas) output << L" 0x" << std::hex << rva;
                    output << std::dec << L"\r\n";
                }
                output << L"\r\nEvidence\r\n";
                for (const auto& evidence : finding.evidence) output << L"- " << Utf8ToWide(evidence) << L"\r\n";
                output << L"\r\nBranch witness\r\n";
                for (const auto& condition : finding.pathConditions) output << Utf8ToWide(condition) << L"\r\n";
                output << L"\r\nLimitations\r\n";
                for (const auto& limit : finding.limitations) output << L"- " << Utf8ToWide(limit) << L"\r\n";
            }
            output << L"\r\nStatic indicators\r\n"
                   << L"Interface: " << InterfaceSummary(*analysis) << L"\r\n";
            AppendEvidenceSection(output, L"Sensitive imports", *analysis, scanner::IndicatorKind::SensitiveCapability);
            AppendEvidenceSection(output, L"Observed safeguard imports", *analysis, scanner::IndicatorKind::Safeguard);
            output << L"\r\nIOCTL instruction patterns\r\n" << IoctlEvidenceText(*analysis, true)
                   << L"\r\nPattern values are separate from request-flow evidence.";
        }
        else
        {
            output << L"Analysis coverage\r\n"
                   << L"Status: " << Utf8ToWide(analysis->CoverageStatus()) << L"\r\n\r\n"
                   << Utf8ToWide(analysis->reverseAnalysis) << L"\r\n\r\n"
                   << L"WDM handlers recovered: " << analysis->dispatchHandlerRvas.size() << L"\r\n"
                   << L"Decoded instructions: " << analysis->reverseDecodedInstructions << L"\r\n"
                   << L"Executed model steps: " << analysis->reverseInstructions << L"\r\n"
                   << L"Function regions: " << analysis->reverseFunctions << L"\r\n"
                   << L"Explored states: " << analysis->reverseStates << L"\r\n"
                   << L"Pruned paths: " << analysis->reversePrunedPaths << L"\r\n"
                   << L"Reversing time: " << analysis->reverseElapsedMilliseconds << L" ms\r\n"
                   << L"Reversing time budget: 10 seconds per image\r\n\r\n"
                   << L"Coverage gaps\r\n";
            for (const auto& gap : analysis->reverseCoverageReasons) output << L"- " << Utf8ToWide(gap) << L"\r\n";
            if (analysis->reverseCoverageReasons.empty())
                output << L"No additional gap was recorded within the bounded model.\r\n";
            if (!analysis->instructionVerificationError.empty())
                output << L"\r\nInstruction verification: " << Utf8ToWide(analysis->instructionVerificationError) << L"\r\n";
            output << L"\r\nScope: Windows x64 WDM dispatch recovery and bounded request-field tracing. KMDF callbacks, exception paths, unresolved indirect control flow and runtime authorization require separate analysis.\r\n\r\n"
                   << L"Bounded coverage describes this model's execution. It is not an assurance of safety or exhaustive code coverage.";
        }
        SetInspectorText(output.str());
    }

    std::string CsvEscape(const std::string& value)
    {
        std::string safe = value;
        const auto first = safe.find_first_not_of(" \t\r\n");
        if ((!safe.empty() && (safe[0] == '\t' || safe[0] == '\r' || safe[0] == '\n')) ||
            (first != std::string::npos && std::string("=+-@").find(safe[first]) != std::string::npos)) safe.insert(safe.begin(), '\'');
        if (safe.find_first_of(",\"\r\n") == std::string::npos) return safe;
        std::string output = "\"";
        for (char character : safe)
        {
            if (character == '"') output += "\"\"";
            else output += character;
        }
        output += '"';
        return output;
    }

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty()) return {};
        const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (required <= 0) return {};
        std::string result(static_cast<std::size_t>(required), '\0');
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()), result.data(), required, nullptr, nullptr);
        return result;
    }

    std::string JoinImportCsv(
        const scanner::DriverAnalysis& analysis,
        scanner::IndicatorKind kind)
    {
        std::ostringstream output;
        bool first = true;
        for (const scanner::ImportMatch& match : analysis.matches)
        {
            if (match.rule.kind != kind) continue;
            if (!first) output << " | ";
            output << match.importedName;
            first = false;
        }
        return output.str();
    }

    std::string JoinStringCsv(const std::vector<std::string>& values)
    {
        std::ostringstream output;
        for (std::size_t index = 0; index < values.size(); ++index)
        {
            if (index != 0) output << " | ";
            output << values[index];
        }
        return output.str();
    }

    std::string FindingCsv(const scanner::DriverAnalysis& analysis)
    {
        std::ostringstream output;
        for (const auto& finding : analysis.findings)
        {
            output << finding.rule << ": " << finding.title << "; " << finding.access
                   << "; IOCTL=0x" << std::hex << finding.ioctl << "; handler_rva=0x" << finding.handlerRva
                   << "; operation_rva=0x" << finding.operationRva << "; file_offset=0x" << finding.fileOffset << std::dec
                   << "; source_rva=" << finding.sourceRva << "; access_size_bytes=" << finding.accessSize
                   << "; source_expression=" << finding.sourceExpression
                   << "; path_conditions=" << JoinStringCsv(finding.pathConditions)
                   << "; trace_status=" << finding.confidence << "; evidence=" << JoinStringCsv(finding.evidence)
                   << "; limitations=" << JoinStringCsv(finding.limitations) << "\n";
            output << "review_only=" << (finding.reviewOnly ? "true" : "false") << "; related_operation_rvas=";
            for (const auto rva : finding.relatedOperationRvas) output << "0x" << std::hex << rva << ' ';
            output << std::dec << '\n';
        }
        return output.str();
    }

    void ExportCsv()
    {
        if (g_state.analyses.empty())
        {
            MessageBoxW(g_state.window, L"There are no scan results to export.",
                app::Name, MB_OK | MB_ICONINFORMATION);
            return;
        }

        wchar_t fileName[MAX_PATH] = L"driver-scanner.csv";
        OPENFILENAMEW dialog{};
        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = g_state.window;
        dialog.lpstrFilter = L"CSV report (*.csv)\0*.csv\0All files (*.*)\0*.*\0";
        dialog.lpstrFile = fileName;
        dialog.nMaxFile = MAX_PATH;
        dialog.lpstrDefExt = L"csv";
        dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
        if (!GetSaveFileNameW(&dialog)) return;

        std::ofstream output(fs::path(fileName), std::ios::binary);
        if (!output)
        {
            MessageBoxW(g_state.window, L"The report file could not be created.",
                L"Export failed", MB_OK | MB_ICONERROR);
            return;
        }

        output << "\xef\xbb\xbf";
        output << "row,driver,path,evidence_category,evidence_basis,coverage_status,capability_or_traced_access,assessment,policy_hash_match,policy_rule,policy_source,validation_status,embedded_signature,company,certificate_status,signature_source,revocation_status,product,version,sha256,authenticode_sha256,hash_error,code_analysis,ioctl_byte_patterns_unverified,wdm_device_control_pattern_unverified,unsafe_user_buffer_api,broad_sddl_allow_ace_unverified,sensitive_capabilities,device_exposure,request_handling,observed_safeguards,device_names,symbolic_links,security_descriptors,reverse_analysis,partial_reverse_coverage,observation_count,observations,reverse_coverage_reasons,pruned_paths\r\n";
        for (std::size_t index = 0; index < g_state.analyses.size(); ++index)
        {
            const scanner::DriverAnalysis& item = *g_state.analyses[index];
            output
                << index + 1 << ','
                << CsvEscape(WideToUtf8(PathText(item.path.filename()))) << ','
                << CsvEscape(WideToUtf8(PathText(item.path))) << ','
                << CsvEscape(scanner::EvidenceLabel(item.Evidence())) << ','
                << CsvEscape(scanner::EvidenceDescription(item.Evidence())) << ','
                << CsvEscape(item.CoverageStatus()) << ','
                << CsvEscape(WideToUtf8(PotentialAccess(item))) << ','
                << CsvEscape(item.Assessment()) << ','
                << (item.knownVulnerable ? "true" : "false") << ','
                << CsvEscape(item.knownVulnerableLabel) << ','
                << CsvEscape(item.knownVulnerableSource) << ",not-performed,"
                << CsvEscape(item.signatureSource == "embedded" ? scanner::SignatureStatusText(item.signature) : "not-verified") << ','
                << CsvEscape(item.companyName) << ','
                << CsvEscape(scanner::CertificateStatusText(item)) << ',' << CsvEscape(item.signatureSource) << ",not-checked-offline,"
                << CsvEscape(item.productName) << ','
                << CsvEscape(item.fileVersion) << ','
                << item.sha256 << ','
                << item.authenticodeSha256 << ','
                << CsvEscape(item.hashError) << ','
                << CsvEscape(item.codeAnalysis) << ','
                << CsvEscape(WideToUtf8(IoctlEvidenceText(item, false))) << ','
                << (item.ioControlDispatchPattern ? "true" : "false") << ','
                << (item.unsafeUserBufferApi ? "true" : "false") << ','
                << (item.permissiveSecurityDescriptor ? "true" : "false") << ','
                << CsvEscape(JoinImportCsv(item, scanner::IndicatorKind::SensitiveCapability)) << ','
                << CsvEscape(JoinImportCsv(item, scanner::IndicatorKind::DeviceExposure)) << ','
                << CsvEscape(JoinImportCsv(item, scanner::IndicatorKind::RequestHandling)) << ','
                << CsvEscape(JoinImportCsv(item, scanner::IndicatorKind::Safeguard)) << ','
                << CsvEscape(JoinStringCsv(item.deviceNames)) << ','
                << CsvEscape(JoinStringCsv(item.symbolicLinks)) << ','
                << CsvEscape(JoinStringCsv(item.securityDescriptors)) << ','
                << CsvEscape(item.reverseAnalysis) << ',' << (item.reverseAnalysisIncomplete ? "true" : "false") << ','
                << item.findings.size() << ',' << CsvEscape(FindingCsv(item)) << ','
                << CsvEscape(JoinStringCsv(item.reverseCoverageReasons)) << ',' << item.reversePrunedPaths << "\r\n";
        }

        if (!output)
        {
            MessageBoxW(g_state.window, L"The report could not be written completely.",
                L"Export failed", MB_OK | MB_ICONERROR);
            return;
        }
        AppendLog(L"Exported CSV: " + std::wstring(fileName));
    }

    void ChooseFolder()
    {
        IFileOpenDialog* dialog = nullptr;
        if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                IID_PPV_ARGS(&dialog))))
        {
            MessageBoxW(g_state.window, L"The Windows folder picker could not be opened.",
                L"Folder picker", MB_OK | MB_ICONERROR);
            return;
        }

        DWORD options = 0;
        dialog->GetOptions(&options);
        dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
        dialog->SetTitle(L"Choose a folder containing .sys drivers");

        const std::wstring current = GetWindowTextValue(g_state.folder);
        if (!current.empty())
        {
            IShellItem* initial = nullptr;
            if (SUCCEEDED(SHCreateItemFromParsingName(current.c_str(), nullptr,
                    IID_PPV_ARGS(&initial))))
            {
                dialog->SetFolder(initial);
                initial->Release();
            }
        }

        if (SUCCEEDED(dialog->Show(g_state.window)))
        {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dialog->GetResult(&item)))
            {
                PWSTR path = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)))
                {
                    SetWindowTextW(g_state.folder, path);
                    AppendLog(L"Selected folder: " + std::wstring(path));
                    CoTaskMemFree(path);
                }
                item->Release();
            }
        }
        dialog->Release();
    }

    void SetScanControlsEnabled(bool enabled)
    {
        EnableWindow(g_state.folder, enabled);
        EnableWindow(g_state.browse, enabled);
        EnableWindow(g_state.scan, !g_state.closing);
        SetWindowTextW(g_state.scan, enabled ? L"Start analysis" : L"Stop scan");
        EnableWindow(g_state.exportButton, enabled && !g_state.analyses.empty());
    }

    void StartScan()
    {
        if (g_state.scanning)
        {
            if (g_state.cancel) g_state.cancel->store(true);
            SetWindowTextW(g_state.scan, L"Stopping...");
            EnableWindow(g_state.scan, FALSE);
            SetWindowTextW(g_state.status, L"Stopping after the current image. Existing results will be retained.");
            return;
        }
        const std::wstring folderText = GetWindowTextValue(g_state.folder);
        if (folderText.empty())
        {
            MessageBoxW(g_state.window, L"Choose a directory containing Windows driver files.",
                L"Folder Directory required", MB_OK | MB_ICONINFORMATION);
            return;
        }
        std::error_code error;
        const fs::path folder(folderText);
        if (!fs::is_directory(folder, error))
        {
            MessageBoxW(g_state.window, L"The directory does not exist or cannot be accessed.",
                L"Directory unavailable", MB_OK | MB_ICONERROR);
            return;
        }

        g_state.selected = nullptr;
        // List items hold pointers into analyses.
        g_state.refreshing = true;
        ListView_DeleteAllItems(g_state.results);
        g_state.refreshing = false;
        g_state.analyses.clear();
        g_state.discovered = 0;
        g_state.catalogEntries = 0;
        g_state.scanStart = GetTickCount64();
        g_state.scanning = true;
        g_state.cancel = std::make_shared<std::atomic_bool>(false);
        PopulateResults();
        SetWindowTextW(g_state.log, L"");
        AppendLog(L"Analysis started: " + folderText);
        AppendLog(L"Read-only inspection; driver images will not be loaded.");
        SendMessageW(g_state.progress, PBM_SETRANGE32, 0, 1);
        SendMessageW(g_state.progress, PBM_SETPOS, 0, 0);
        SetWindowTextW(g_state.status, L"Discovering driver images...");
        SetScanControlsEnabled(false);
        SetTimer(g_state.window,1,200,nullptr);
        InvalidateRect(g_state.window, nullptr, FALSE);

        const HWND window = g_state.window;
        const auto cancel = g_state.cancel;
        try
        {
            std::thread([window, folder, cancel]() {
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
                auto summary = std::make_unique<ScanSummary>();
                try
                {
                    std::vector<std::string> discoveryErrors;
                    const auto files = scanner::GetDriverFiles(folder, true, discoveryErrors);
                    summary->discoveryWarnings = discoveryErrors.size();
                    PostMessageW(window, kMessageScanCount, static_cast<WPARAM>(files.size()), 0);
                    const auto rules = scanner::DefaultRules();
                    const auto knownDrivers = scanner::LoadMicrosoftVulnerableDriverBlocklist(
                        summary->catalogSource, summary->catalogError);
                    summary->catalogEntries = knownDrivers.size();
                    for (std::size_t index = 0; index < files.size(); ++index)
                    {
                        if (cancel->load()) { summary->cancelled = true; break; }
                        scanner::DriverAnalysis analysis;
                        try { analysis = scanner::AnalyzeDriver(files[index], rules, knownDrivers); }
                        catch (const std::exception& failure)
                        {
                            analysis.path = files[index];
                            analysis.parseError = std::string("Analysis exception: ") + failure.what();
                        }
                        summary->flowFindings += analysis.findings.size();
                        if (analysis.reverseAnalysisIncomplete) ++summary->partialReverseCoverage;
                        ++summary->scanned;
                        if (!analysis.parseSucceeded) ++summary->parseErrors;
                        if (!analysis.instructionVerificationError.empty()) ++summary->verificationErrors;
                        if (analysis.IsCandidate() || !analysis.findings.empty()) ++summary->candidates;
                        if (analysis.knownVulnerable) ++summary->knownMatches;
                        auto completed = std::make_unique<scanner::DriverAnalysis>(std::move(analysis));
                        if (PostMessageW(window, kMessageScanResult, 0, reinterpret_cast<LPARAM>(completed.get()))) completed.release();
                        PostMessageW(window, kMessageScanProgress, static_cast<WPARAM>(index + 1), static_cast<LPARAM>(files.size()));
                    }
                }
                catch (const std::exception& failure) { summary->failure = failure.what(); }
                catch (...) { summary->failure = "Unexpected analysis failure."; }
                if (PostMessageW(window, kMessageScanDone, 0, reinterpret_cast<LPARAM>(summary.get()))) summary.release();
            }).detach();
        }
        catch (const std::exception& failure)
        {
            g_state.scanning = false;
            SetScanControlsEnabled(true);
            AppendLog(L"Unable to start worker: " + Utf8ToWide(failure.what()));
            SetWindowTextW(g_state.status, L"Analysis could not start. See Activity for details.");
        }
    }

    void AddListColumn(HWND list, int index, int width, const wchar_t* text)
    {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        column.iSubItem = index;
        column.cx = width;
        column.pszText = const_cast<wchar_t*>(text);
        ListView_InsertColumn(list, index, &column);
    }

    void ApplyFonts()
    {
        const std::array<HFONT, 4> old = {g_state.font, g_state.smallFont, g_state.sectionFont, g_state.numberFont};
        const auto font = [](int size, int weight) {
            return CreateFontW(-Dip(size), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        };
        g_state.font = font(15, FW_NORMAL);
        g_state.smallFont = font(13, FW_NORMAL);
        g_state.sectionFont = font(15, FW_SEMIBOLD);
        g_state.numberFont = font(27, FW_SEMIBOLD);
        const std::vector<HWND> controls = {g_state.folder, g_state.browse, g_state.scan, g_state.exportButton,
            g_state.results, g_state.search, g_state.filter, g_state.tabs, g_state.details, g_state.copyButton};
        for (HWND control : controls) SetFont(control, g_state.font);
        for (HWND control : {g_state.status, g_state.resultCount, g_state.log, g_state.about, g_state.emptyHint})
            SetFont(control, g_state.smallFont);
        for (HWND control : {g_state.folderLabel, g_state.resultsLabel, g_state.detailsLabel})
            SetFont(control, g_state.sectionFont);
        SetFont(ListView_GetHeader(g_state.results), g_state.sectionFont);
        SendMessageW(g_state.filter, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1), Dip(25));
        SendMessageW(g_state.filter, CB_SETITEMHEIGHT, 0, Dip(25));
        SendMessageW(g_state.folder, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, 0);
        SendMessageW(g_state.search, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(Dip(8), Dip(8)));
        SendMessageW(g_state.tabs, TCM_SETPADDING, 0, MAKELPARAM(Dip(12), Dip(6)));
        HIMAGELIST images = ImageList_Create(1, Dip(34), ILC_COLOR32, 1, 1);
        if (images)
        {
            ImageList_SetImageCount(images, 1);
            ListView_SetImageList(g_state.results, images, LVSIL_SMALL);
            if (g_state.rowImages) ImageList_Destroy(g_state.rowImages);
            g_state.rowImages = images;
        }
        for (HFONT handle : old) if (handle) DeleteObject(handle);
        g_state.inspectorText.clear();
        ShowDetails(g_state.selected);
    }


    void CreateControls(HWND window)
    {
        g_state.dpi = GetDpiForWindow(window);
        if (!g_state.dpi) g_state.dpi = 96;
        g_state.backgroundBrush = CreateSolidBrush(kBackground);
        g_state.cardBrush = CreateSolidBrush(kCard);
        static const HMODULE richEdit = LoadLibraryExW(L"Msftedit.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        const wchar_t* editClass = richEdit ? L"RICHEDIT50W" : L"EDIT";
        const auto label = [window](const wchar_t* text, DWORD extra = 0) {
            return CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE | extra, 0,0,0,0, window, nullptr, nullptr, nullptr);
        };
        const auto button = [window](const wchar_t* text, int id) {
            return CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                0,0,0,0, window, ControlId(id), nullptr, nullptr);
        };
        g_state.about = button(L"About", kIdAbout);
        g_state.folderLabel = label(L"Folder Directory");
        g_state.folder = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            0,0,0,0, window, ControlId(kIdFolder), nullptr, nullptr);
        SendMessageW(g_state.folder, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Choose a directory containing .sys files"));
        SendMessageW(g_state.folder, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, 0);
        g_state.browse = button(L"Choose folder", kIdBrowse);
        g_state.scan = button(L"Start analysis", kIdScan);
        g_state.exportButton = button(L"Export CSV", kIdExport);
        EnableWindow(g_state.exportButton, FALSE);
        g_state.progress = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            0,0,0,0, window, ControlId(kIdProgress), nullptr, nullptr);
        g_state.status = label(scanner::DisassemblerPath().empty() ?
            L"Limited coverage: install Visual Studio C++ tools to enable instruction analysis." :
            L"Ready. Instruction-analysis backend available. Choose an input directory.", SS_ENDELLIPSIS);
        g_state.resultsLabel = label(L"Analysis results");
        g_state.resultCount = label(L"0 of 0", SS_RIGHT);
        g_state.search = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            0,0,0,0, window, ControlId(kIdSearch), nullptr, nullptr);
        SendMessageW(g_state.search, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Search name, company or SHA-256"));
        SendMessageW(g_state.search, EM_SETLIMITTEXT, 256, 0);
        SendMessageW(g_state.search, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(Dip(8), Dip(8)));
        g_state.filter = CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_VSCROLL,
            0,0,0,0, window, ControlId(kIdFilter), nullptr, nullptr);
        for (const auto* text : {L"All evidence", L"Request flows", L"Qualified flows", L"Policy matches",
            L"Pattern leads", L"Incomplete coverage", L"Analysis errors"})
            SendMessageW(g_state.filter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text));
        SendMessageW(g_state.filter, CB_SETCURSEL, 0, 0);
        g_state.results = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP |
            LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0,0,0,0, window, ControlId(kIdResults), nullptr, nullptr);
        ListView_SetExtendedListViewStyle(g_state.results, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
        ListView_SetBkColor(g_state.results, kCard);
        ListView_SetTextColor(g_state.results, kText);
        ListView_SetTextBkColor(g_state.results, kCard);
        SetWindowTheme(g_state.results, L"Explorer", nullptr);
        const std::array<const wchar_t*, 7> columns = {L"Driver", L"Evidence", L"Operation", L"Obs", L"Coverage", L"Company", L"Certificate"};
        for (int index = 0; index < static_cast<int>(columns.size()); ++index) AddListColumn(g_state.results, index, Dip(100), columns[index]);
        g_state.emptyHint = label(L"Choose a directory and start analysis.\r\nDriver evidence will appear here.", SS_CENTER);
        g_state.detailsLabel = label(L"Inspector", SS_ENDELLIPSIS);
        g_state.copyButton = button(L"Copy", kIdCopy);
        g_state.tabs = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | TCS_FOCUSNEVER,
            0,0,0,0, window, ControlId(kIdTabs), nullptr, nullptr);
        int tab = 0;
        for (const auto* text : {L"Overview", L"Findings", L"Coverage", L"Activity"})
        {
            TCITEMW item{}; item.mask = TCIF_TEXT; item.pszText = const_cast<wchar_t*>(text);
            TabCtrl_InsertItem(g_state.tabs, tab++, &item);
        }
        SendMessageW(g_state.tabs, TCM_SETPADDING, 0, MAKELPARAM(Dip(12), Dip(6)));
        const DWORD editStyle = WS_CHILD | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL;
        g_state.details = CreateWindowExW(0, editClass, L"", editStyle | WS_VISIBLE, 0,0,0,0,
            window, ControlId(kIdDetails), nullptr, nullptr);
        g_state.log = CreateWindowExW(0, editClass, L"", editStyle, 0,0,0,0, window, ControlId(kIdLog), nullptr, nullptr);
        for (HWND control : {g_state.details, g_state.log})
        {
            SendMessageW(control, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
            SendMessageW(control, EM_SETBKGNDCOLOR, 0, kCard);
            SetWindowTheme(control, L"Explorer", nullptr);
        }
        ApplyFonts();
        g_state.tooltip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, window, nullptr, nullptr, nullptr);
        SendMessageW(g_state.tooltip, TTM_SETMAXTIPWIDTH, 0, Dip(360));
        const auto tip = [window](HWND control, const wchar_t* text) {
            TOOLINFOW info{}; info.cbSize = sizeof(info); info.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
            info.hwnd = window; info.uId = reinterpret_cast<UINT_PTR>(control); info.lpszText = const_cast<wchar_t*>(text);
            SendMessageW(g_state.tooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&info));
        };
        tip(g_state.exportButton, L"Export all analyzed images to CSV, including results hidden by search or filters.");
        tip(g_state.filter, L"Filter by evidence category. Analysis coverage is reported separately.");
        tip(g_state.resultsLabel, L"Evidence categories describe observations, not severity or detection probability. Obs. counts grouped observations, not vulnerabilities.");
        AppendLog(std::wstring(L"Driver Scanner ") + app::Version + L". Static inspection ready.");
    }

    void LayoutControls(HWND window)
    {
        if (!g_state.results) return;
        RECT client{};
        GetClientRect(window, &client);
        const int width = client.right, height = client.bottom;
        const int margin = Dip(24), gap = Dip(16), content = width - 2 * margin;
        const auto move = [](HWND control, int x, int y, int w, int h) {
            MoveWindow(control, x, y, std::max(1, w), std::max(1, h), TRUE);
        };
        move(g_state.about, width - margin - Dip(76), Dip(18), Dip(76), Dip(32));
        move(g_state.folderLabel, margin, Dip(24), content - Dip(100), Dip(20));
        const int browseWidth = Dip(112), scanWidth = Dip(132), exportWidth = Dip(108);
        const int editWidth = content - browseWidth - scanWidth - exportWidth - gap * 3;
        g_state.folderFrame = {margin,Dip(56),margin + editWidth,Dip(94)};
        move(g_state.folder, margin + Dip(12), Dip(64), editWidth - Dip(24), Dip(22));
        int x = margin + editWidth + gap;
        move(g_state.browse, x, Dip(56), browseWidth, Dip(38)); x += browseWidth + gap;
        move(g_state.scan, x, Dip(56), scanWidth, Dip(38)); x += scanWidth + gap;
        move(g_state.exportButton, x, Dip(56), exportWidth, Dip(38));
        const int metricGap = Dip(12), metricWidth = (content - 4 * metricGap) / 5;
        for (int index = 0; index < 5; ++index)
            g_state.metricCards[index] = {margin + index * (metricWidth + metricGap), Dip(114),
                index == 4 ? width - margin : margin + index * (metricWidth + metricGap) + metricWidth, Dip(195)};
        const int bodyTop = Dip(214), bodyBottom = height - Dip(63), panelGap = Dip(18);
        const int leftWidth = (content - panelGap) * 59 / 100;
        g_state.resultsCard = {margin, bodyTop, margin + leftWidth, bodyBottom};
        g_state.inspectorCard = {margin + leftWidth + panelGap, bodyTop, width - margin, bodyBottom};
        const auto left = g_state.resultsCard, right = g_state.inspectorCard;
        const int padding = Dip(14), leftInner = left.right - left.left - 2 * padding;
        move(g_state.resultsLabel, left.left + padding, bodyTop + Dip(17), leftInner - Dip(100), Dip(23));
        move(g_state.resultCount, left.right - padding - Dip(95), bodyTop + Dip(20), Dip(95), Dip(20));
        const int filterWidth = Dip(165);
        move(g_state.search, left.left + padding + Dip(8), bodyTop + Dip(60), leftInner - filterWidth - Dip(26), Dip(20));
        move(g_state.filter, left.right - padding - filterWidth, bodyTop + Dip(53), filterWidth, Dip(240));
        move(g_state.results, left.left + padding, bodyTop + Dip(99), leftInner, bodyBottom - bodyTop - Dip(112));
        move(g_state.emptyHint, left.left + padding + Dip(20), bodyTop + Dip(180), leftInner - Dip(40), Dip(64));
        SetWindowPos(g_state.emptyHint, HWND_TOP, 0,0,0,0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        const int tableWidth = std::max(100, leftInner - GetSystemMetricsForDpi(SM_CXVSCROLL, g_state.dpi) - Dip(3));
        const bool compact = tableWidth < Dip(850);
        const std::array<int,7> widths = {std::max(Dip(110),tableWidth - Dip(compact ? 430 : 579)),Dip(116),compact ? 0 : Dip(105),compact ? 0 : Dip(44),Dip(84),Dip(90),Dip(140)};
        for (int column = 0; column < 7; ++column) ListView_SetColumnWidth(g_state.results,column,widths[column]);
        const int rightInner = right.right - right.left - 2 * padding;
        move(g_state.detailsLabel, right.left + padding, bodyTop + Dip(18), rightInner - Dip(82), Dip(25));
        move(g_state.copyButton, right.right - padding - Dip(65), bodyTop + Dip(13), Dip(65), Dip(31));
        move(g_state.tabs, right.left + padding, bodyTop + Dip(53), rightInner, Dip(36));
        const int detailTop = bodyTop + Dip(102), detailHeight = bodyBottom - detailTop - Dip(12);
        for (HWND control : {g_state.details, g_state.log})
        {
            move(control, right.left + padding, detailTop, rightInner, detailHeight);
            RECT text{Dip(4), Dip(5), rightInner - Dip(18), detailHeight - Dip(5)};
            SendMessageW(control, EM_SETRECT, 0, reinterpret_cast<LPARAM>(&text));
        }
        move(g_state.progress, margin, height - Dip(42), content, Dip(4));
        move(g_state.status, margin, height - Dip(29), content, Dip(20));
        InvalidateRect(window, nullptr, TRUE);
    }

    void DrawCard(HDC dc, const RECT& rectangle)
    {
        HPEN pen = CreatePen(PS_SOLID, 1, kBorder);
        HGDIOBJ oldPen = SelectObject(dc, pen), oldBrush = SelectObject(dc, g_state.cardBrush);
        RoundRect(dc, rectangle.left, rectangle.top, rectangle.right, rectangle.bottom, Dip(12), Dip(12));
        SelectObject(dc, oldBrush); SelectObject(dc, oldPen); DeleteObject(pen);
    }

    void PaintBackground(HWND window, HDC dc)
    {
        RECT client{}; GetClientRect(window, &client);
        FillRect(dc, &client, g_state.backgroundBrush);
        SetBkMode(dc, TRANSPARENT);
        DrawCard(dc, g_state.folderFrame);
        if (GetFocus() == g_state.folder)
        {
            HPEN pen = CreatePen(PS_SOLID, Dip(1), kAccent);
            auto oldPen = SelectObject(dc, pen), oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
            const auto frame = g_state.folderFrame;
            RoundRect(dc, frame.left, frame.top, frame.right, frame.bottom, Dip(12), Dip(12));
            SelectObject(dc, oldBrush); SelectObject(dc, oldPen); DeleteObject(pen);
        }
        HGDIOBJ oldFont = SelectObject(dc, g_state.sectionFont);
        std::array<std::size_t, 5> counts{g_state.analyses.size(),0,0,0,0};
        for (const auto& item : g_state.analyses)
        {
            if (item->HasDataflowCandidate()) ++counts[1];
            else if (!item->findings.empty() || item->Evidence() == scanner::EvidenceCategory::Pattern) ++counts[2];
            if (item->knownVulnerable) ++counts[3];
            if (item->parseSucceeded && item->CoverageStatus() != "bounded") ++counts[4];
        }
        const std::array<const wchar_t*, 5> labels = {L"Analyzed files", L"Request flows", L"Review items", L"Policy matches", L"Partial coverage"};
        for (std::size_t index = 0; index < counts.size(); ++index)
        {
            DrawCard(dc, g_state.metricCards[index]);
            RECT label = g_state.metricCards[index];
            label.left += Dip(15); label.top += Dip(12); label.right -= Dip(10); label.bottom = label.top + Dip(20);
            SelectObject(dc, g_state.smallFont); SetTextColor(dc, kMuted);
            DrawTextW(dc, labels[index], -1, &label, DT_SINGLELINE | DT_END_ELLIPSIS);
            RECT value = label; value.top += Dip(23); value.bottom = value.top + Dip(34);
            SelectObject(dc, g_state.numberFont); SetTextColor(dc, index == 1 ? kAccent : kText);
            DrawTextW(dc, std::to_wstring(counts[index]).c_str(), -1, &value, DT_SINGLELINE);
        }
        DrawCard(dc, g_state.resultsCard);
        DrawCard(dc, g_state.inspectorCard);
        RECT search{g_state.resultsCard.left + Dip(14),g_state.resultsCard.top + Dip(53),g_state.resultsCard.right - Dip(189),g_state.resultsCard.top + Dip(88)};
        DrawCard(dc,search);
        SelectObject(dc, oldFont);
    }

    void DrawButton(const DRAWITEMSTRUCT& item)
    {
        const bool primary = item.CtlID == kIdScan;
        const bool disabled = (item.itemState & ODS_DISABLED) != 0;
        COLORREF fill = primary ? kAccent : kCard;
        if (disabled) fill = RGB(233,237,243);
        else if (item.itemState & ODS_SELECTED) fill = primary ? RGB(29,78,216) : RGB(234,239,247);
        HBRUSH brush = CreateSolidBrush(fill);
        HPEN pen = CreatePen(PS_SOLID, 1, primary && !disabled ? fill : kBorder);
        auto oldBrush = SelectObject(item.hDC, brush), oldPen = SelectObject(item.hDC, pen);
        RoundRect(item.hDC, item.rcItem.left, item.rcItem.top, item.rcItem.right, item.rcItem.bottom, Dip(9), Dip(9));
        SelectObject(item.hDC, oldBrush); SelectObject(item.hDC, oldPen);
        DeleteObject(brush); DeleteObject(pen);
        SetBkMode(item.hDC, TRANSPARENT);
        SetTextColor(item.hDC, disabled ? RGB(148,158,175) : primary ? RGB(255,255,255) : kText);
        auto oldFont = SelectObject(item.hDC, g_state.font);
        RECT text = item.rcItem;
        const auto caption = GetWindowTextValue(item.hwndItem);
        DrawTextW(item.hDC, caption.c_str(), -1, &text, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        if (item.itemState & ODS_FOCUS) { InflateRect(&text, -Dip(4), -Dip(4)); DrawFocusRect(item.hDC, &text); }
        SelectObject(item.hDC, oldFont);
    }

    void CopyInspector()
    {
        const auto text = GetWindowTextValue(g_state.inspectorTab == 3 ? g_state.log : g_state.details);
        if (text.empty() || !OpenClipboard(g_state.window)) return;
        const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
        HGLOBAL data = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (data)
        {
            void* pointer = GlobalLock(data);
            if (pointer)
            {
                memcpy(pointer, text.c_str(), bytes); GlobalUnlock(data);
                if (EmptyClipboard() && SetClipboardData(CF_UNICODETEXT, data)) data = nullptr;
            }
            if (data) GlobalFree(data);
        }
        CloseClipboard();
    }

    void DrawFilter(const DRAWITEMSTRUCT& item)
    {
        const bool selected = (item.itemState & ODS_SELECTED) && !(item.itemState & ODS_COMBOBOXEDIT);
        HBRUSH brush = CreateSolidBrush(selected ? kAccent : kCard);
        FillRect(item.hDC, &item.rcItem, brush); DeleteObject(brush);
        int index = static_cast<int>(item.itemID);
        if (index < 0) index = static_cast<int>(SendMessageW(item.hwndItem, CB_GETCURSEL, 0, 0));
        if (index < 0) return;
        const auto length = SendMessageW(item.hwndItem, CB_GETLBTEXTLEN, index, 0);
        if (length < 0 || length > 1024) return;
        std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
        SendMessageW(item.hwndItem, CB_GETLBTEXT, index, reinterpret_cast<LPARAM>(text.data()));
        SetBkMode(item.hDC, TRANSPARENT);
        SetTextColor(item.hDC, selected ? kCard : kText);
        auto old = SelectObject(item.hDC, g_state.font ? g_state.font : GetStockObject(DEFAULT_GUI_FONT));
        RECT rectangle = item.rcItem; rectangle.left += Dip(7); rectangle.right -= Dip(3);
        DrawTextW(item.hDC, text.c_str(), -1, &rectangle, DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        SelectObject(item.hDC, old);
    }

    LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
        case WM_CREATE:
            g_state.window = window;
            CreateControls(window);
            if (!g_state.results || !g_state.details || !g_state.filter) return -1;
            return 0;

        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT:
        {
            PAINTSTRUCT paint{};
            HDC dc = BeginPaint(window, &paint);
            HDC buffer = CreateCompatibleDC(dc);
            RECT rectangle{}; GetClientRect(window,&rectangle);
            HBITMAP bitmap = CreateCompatibleBitmap(dc,std::max(1L,rectangle.right),std::max(1L,rectangle.bottom));
            if (buffer && bitmap)
            {
                auto previous = SelectObject(buffer,bitmap);
                PaintBackground(window,buffer);
                BitBlt(dc,0,0,rectangle.right,rectangle.bottom,buffer,0,0,SRCCOPY);
                SelectObject(buffer,previous);
            }
            else PaintBackground(window,dc);
            if (bitmap) DeleteObject(bitmap);
            if (buffer) DeleteDC(buffer);
            EndPaint(window, &paint);
            return 0;
        }

        case WM_PRINTCLIENT:
            PaintBackground(window, reinterpret_cast<HDC>(wParam));
            return 0;

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
        {
            HDC dc = reinterpret_cast<HDC>(wParam);
            HWND control = reinterpret_cast<HWND>(lParam);
            const bool outside = control == g_state.status || control == g_state.folderLabel;
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, control == g_state.status ||
                control == g_state.resultCount || control == g_state.emptyHint ? kMuted : kText);
            return reinterpret_cast<LRESULT>(outside ? g_state.backgroundBrush : g_state.cardBrush);
        }

        case WM_DRAWITEM:
            if (reinterpret_cast<DRAWITEMSTRUCT*>(lParam)->CtlType == ODT_COMBOBOX)
            { DrawFilter(*reinterpret_cast<DRAWITEMSTRUCT*>(lParam)); return TRUE; }
            if (reinterpret_cast<DRAWITEMSTRUCT*>(lParam)->CtlType == ODT_BUTTON)
            { DrawButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lParam)); return TRUE; }
            break;

        case WM_MEASUREITEM:
        {
            auto* item = reinterpret_cast<MEASUREITEMSTRUCT*>(lParam);
            if (item->CtlType == ODT_COMBOBOX) { item->itemHeight = static_cast<UINT>(Dip(23)); return TRUE; }
            break;
        }

        case WM_DPICHANGED:
        {
            g_state.dpi = HIWORD(wParam);
            ApplyFonts();
            const auto rectangle = reinterpret_cast<const RECT*>(lParam);
            SetWindowPos(window, nullptr, rectangle->left, rectangle->top, rectangle->right - rectangle->left,
                rectangle->bottom - rectangle->top, SWP_NOACTIVATE | SWP_NOZORDER);
            LayoutControls(window);
            return 0;
        }

        case WM_SIZE:
            LayoutControls(window);
            return 0;

        case WM_LBUTTONDOWN:
        {
            POINT point{static_cast<short>(LOWORD(lParam)),static_cast<short>(HIWORD(lParam))};
            if (PtInRect(&g_state.folderFrame, point)) { SetFocus(g_state.folder); return 0; }
            break;
        }

        case WM_GETMINMAXINFO:
        {
            auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
            info->ptMinTrackSize.x = Dip(1080);
            info->ptMinTrackSize.y = Dip(720);
            return 0;
        }

        case WM_COMMAND:
            if (LOWORD(wParam) == kIdFolder && (HIWORD(wParam) == EN_SETFOCUS || HIWORD(wParam) == EN_KILLFOCUS))
                InvalidateRect(window, &g_state.folderFrame, FALSE);
            if ((LOWORD(wParam) == kIdSearch && HIWORD(wParam) == EN_CHANGE) ||
                (LOWORD(wParam) == kIdFilter && HIWORD(wParam) == CBN_SELCHANGE))
            {
                if (g_state.results) PopulateResults();
                return 0;
            }
            switch (LOWORD(wParam))
            {
            case kIdBrowse:
                ChooseFolder();
                return 0;
            case kIdScan:
                StartScan();
                return 0;
            case kIdExport:
                ExportCsv();
                return 0;
            case kIdCopy:
                CopyInspector();
                return 0;
            case kIdAbout:
                MessageBoxW(window, (std::wstring(app::Name) + L" " + app::Version +
                    L"\r\n\r\nRead-only static analysis for Windows kernel drivers.\r\n\r\n"
                    L"Evidence: policy hash match, request flow, qualified flow, pattern lead, metadata, or analysis error. These categories are observations, not calibrated severity or detection probability.\r\n\r\n"
                    L"Scope: bounded Windows x64 WDM analysis, with a 10-second reversing budget per image. KMDF callbacks, exceptions and unresolved indirect paths require separate review. Runtime exploitability is not validated.\r\n\r\n"
                    L"Instruction tracing requires installed Visual Studio C++ tools (dumpbin.exe). Company/version fields come from PE metadata and are not verified publisher identities.\r\n\r\n"
                    L"Policy lookup uses installed Authenticode SHA-256 deny rules only. Embedded and installed catalog signatures are checked offline; live revocation status is not established.\r\n\r\n"
                    L"Credits: Mavix").c_str(),
                    L"About Driver Scanner", MB_OK | MB_ICONINFORMATION);
                return 0;
            default:
                break;
            }
            break;

        case WM_NOTIFY:
        {
            const auto* header = reinterpret_cast<NMHDR*>(lParam);
            if (header->idFrom == kIdTabs && header->code == TCN_SELCHANGE)
            {
                g_state.inspectorTab = TabCtrl_GetCurSel(g_state.tabs);
                ShowDetails(g_state.selected);
                return 0;
            }
            if (header->idFrom == kIdResults && header->code == LVN_COLUMNCLICK)
            {
                const int column = reinterpret_cast<const NMLISTVIEW*>(lParam)->iSubItem;
                g_state.sortDescending = column == g_state.sortColumn ? !g_state.sortDescending : column == 1 || column == 3;
                g_state.sortColumn = column;
                SortResults(); PopulateResults();
                return 0;
            }
            if (header->idFrom == kIdResults && header->code == NM_CUSTOMDRAW)
            {
                auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
                if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
                if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) return CDRF_NOTIFYSUBITEMDRAW;
                if (draw->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM))
                {
                    if (!(draw->nmcd.uItemState & CDIS_SELECTED))
                    {
                        draw->clrTextBk = draw->nmcd.dwItemSpec % 2 ? RGB(248,250,253) : kCard;
                        draw->clrText = kText;
                        if (draw->iSubItem == 1)
                        {
                            const auto* analysis = reinterpret_cast<const scanner::DriverAnalysis*>(draw->nmcd.lItemlParam);
                            if (analysis) draw->clrText = analysis->knownVulnerable ? RGB(153,102,15) : analysis->HasDataflowCandidate() ? kAccent : kMuted;
                        }
                        else if (draw->iSubItem == 4 || draw->iSubItem == 6) draw->clrText = kMuted;
                    }
                    return CDRF_DODEFAULT;
                }
            }
            if (header->idFrom == kIdResults && header->code == LVN_ITEMCHANGED)
            {
                const auto* change = reinterpret_cast<NMLISTVIEW*>(lParam);
                if (!g_state.refreshing && (change->uNewState & LVIS_SELECTED) != 0)
                {
                    LVITEMW item{};
                    item.mask = LVIF_PARAM;
                    item.iItem = change->iItem;
                    if (ListView_GetItem(g_state.results, &item))
                    {
                        ShowDetails(reinterpret_cast<scanner::DriverAnalysis*>(item.lParam));
                    }
                }
            }
            return 0;
        }

        case kMessageScanCount:
        {
            const int total = static_cast<int>(std::min<WPARAM>(wParam, INT_MAX));
            g_state.discovered = static_cast<std::size_t>(total);
            SendMessageW(g_state.progress, PBM_SETRANGE32, 0, std::max(1, total));
            SetWindowTextW(g_state.status,
                (L"Analyzing " + std::to_wstring(total) + L" driver images...").c_str());
            AppendLog(L"Discovered " + std::to_wstring(total) + L" .sys file(s).");
            return 0;
        }

        case kMessageScanProgress:
        {
            const int completed = static_cast<int>(std::min<WPARAM>(wParam, INT_MAX));
            const int total = static_cast<int>(std::min<LPARAM>(lParam, INT_MAX));
            SendMessageW(g_state.progress, PBM_SETPOS, completed, 0);
            SetWindowTextW(g_state.status,
                (L"Analyzing " + std::to_wstring(completed) + L" of " + std::to_wstring(total) +
                    L" images  |  " + std::to_wstring((GetTickCount64() - g_state.scanStart) / 1000) + L" s elapsed").c_str());
            return 0;
        }

        case kMessageScanResult:
        {
            std::unique_ptr<scanner::DriverAnalysis> result(
                reinterpret_cast<scanner::DriverAnalysis*>(lParam));
            AppendLog(PathText(result->path.filename()) + L"  |  " + Utf8ToWide(scanner::EvidenceLabel(result->Evidence())) +
                (result->reverseAnalysisIncomplete ? L", partial reverse coverage" : L""));
            g_state.analyses.push_back(std::move(result));
            auto* added = g_state.analyses.back().get();
            if (MatchesFilter(*added,static_cast<int>(SendMessageW(g_state.filter,CB_GETCURSEL,0,0)),GetWindowTextValue(g_state.search)))
            {
                const int row = ListView_GetItemCount(g_state.results);
                InsertAnalysisRow(row,added); ++g_state.visibleResults;
                if (!g_state.selected) ListView_SetItemState(g_state.results,row,LVIS_SELECTED | LVIS_FOCUSED,LVIS_SELECTED | LVIS_FOCUSED);
            }
            g_state.scanDisplayDirty = true;
            return 0;
        }

        case WM_TIMER:
            if (wParam == 1 && g_state.scanDisplayDirty)
            {
                g_state.scanDisplayDirty = false;
                SetWindowTextW(g_state.resultCount,(std::to_wstring(g_state.visibleResults) + L" of " + std::to_wstring(g_state.analyses.size())).c_str());
                ShowWindow(g_state.emptyHint,g_state.visibleResults ? SW_HIDE : SW_SHOWNA);
                RECT metrics = g_state.metricCards.front(); metrics.right = g_state.metricCards.back().right;
                InvalidateRect(window,&metrics,FALSE);
            }
            return 0;

        case kMessageScanDone:
        {
            std::unique_ptr<ScanSummary> summary(reinterpret_cast<ScanSummary*>(lParam));
            g_state.scanning = false;
            g_state.catalogEntries = summary->catalogEntries;
            KillTimer(window,1);
            SortResults();
            PopulateResults();
            SetScanControlsEnabled(true);

            std::wostringstream status;
            if (summary->cancelled)
            {
                status << L"Scan cancelled after " << summary->scanned << L" file(s).";
            }
            else
            {
                status << L"Analysis finished: " << summary->scanned << L" images, "
                       << summary->candidates << L" review result(s), "
                       << summary->knownMatches << L" exact blocklist match(es), "
                       << summary->parseErrors << L" parse error(s), "
                       << summary->verificationErrors << L" incomplete instruction check(s).";
            }
            SetWindowTextW(g_state.status, status.str().c_str());
            if (!summary->failure.empty())
            {
                SetWindowTextW(g_state.status, L"Analysis stopped with an error. Existing results retained; see Activity.");
                AppendLog(L"Analysis error: " + Utf8ToWide(summary->failure));
            }
            AppendLog(status.str());
            AppendLog(L"Request-flow findings: " + std::to_wstring(summary->flowFindings) +
                L". Drivers with partial reverse coverage: " + std::to_wstring(summary->partialReverseCoverage) + L".");
            if (summary->discoveryWarnings != 0)
            {
                AppendLog(L"Discovery warnings: " +
                    std::to_wstring(summary->discoveryWarnings));
            }
            if (!summary->catalogSource.empty())
            {
                AppendLog(L"Loaded " + std::to_wstring(summary->catalogEntries) +
                    L" Microsoft Authenticode SHA-256 deny rule(s) from: " +
                    Utf8ToWide(summary->catalogSource));
            }
            if (!summary->catalogError.empty())
            {
                AppendLog(L"Blocklist warning: " + Utf8ToWide(summary->catalogError));
            }
            AppendLog(L"Runtime validation was not performed. Evidence categories and analysis coverage are reported separately.");
            InvalidateRect(window, nullptr, FALSE);

            if (g_state.closing)
            {
                DestroyWindow(window);
            }
            return 0;
        }

        case WM_CLOSE:
            if (g_state.scanning)
            {
                g_state.closing = true;
                if (g_state.cancel) g_state.cancel->store(true);
                SetWindowTextW(g_state.status, L"Cancelling scan before closing...");
                SetScanControlsEnabled(false);
                return 0;
            }
            DestroyWindow(window);
            return 0;

        case WM_DESTROY:
            for (HFONT font : {g_state.font, g_state.smallFont, g_state.sectionFont, g_state.numberFont}) if (font) DeleteObject(font);
            if (g_state.rowImages) ImageList_Destroy(g_state.rowImages);
            if (g_state.backgroundBrush) DeleteObject(g_state.backgroundBrush);
            if (g_state.cardBrush) DeleteObject(g_state.cardBrush);
            PostQuitMessage(0);
            return 0;

        default:
            break;
        }
        return DefWindowProcW(window, message, wParam, lParam);
    }
}

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int showCommand)
{
    int headlessExitCode = 0;
    if (scanner::TryRunHeadless(headlessExitCode)) return headlessExitCode;
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    g_state.dpi = GetDpiForSystem();
    const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&controls);

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(101));
    windowClass.hIconSm = reinterpret_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(101), IMAGE_ICON,
        GetSystemMetricsForDpi(SM_CXSMICON, g_state.dpi), GetSystemMetricsForDpi(SM_CYSMICON, g_state.dpi), 0));
    windowClass.hbrBackground = nullptr;
    windowClass.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&windowClass))
    {
        if (SUCCEEDED(comResult)) CoUninitialize();
        return 1;
    }

    HWND window = CreateWindowExW(0, kWindowClass,
        L"Driver Scanner", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, Dip(1320), Dip(900),
        nullptr, nullptr, instance, nullptr);
    if (!window)
    {
        if (SUCCEEDED(comResult)) CoUninitialize();
        return 1;
    }

    ShowWindow(window, showCommand);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0)
    {
        if (message.message == WM_KEYDOWN && (GetKeyState(VK_CONTROL) & 0x8000))
        {
            if (message.wParam == 'F') { SetFocus(g_state.search); continue; }
            if (message.wParam == 'O' && !g_state.scanning) { ChooseFolder(); continue; }
        }
        if (IsDialogMessageW(window, &message)) continue;
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (SUCCEEDED(comResult)) CoUninitialize();
    return static_cast<int>(message.wParam);
}
