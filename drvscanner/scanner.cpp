#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Softpub.h>
#include <Wincrypt.h>
#include <Wintrust.h>
#include <mscat.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <cstdlib>
#include <unordered_set>

#include "scanner.h"
#include "reverse.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;

namespace
{
    constexpr std::size_t kMaximumDriverSize = 512ULL * 1024ULL * 1024ULL;
    constexpr std::size_t kMaximumImportCount = 65536;
    constexpr std::size_t kMaximumStringLength = 4096;

    std::string ToLowerAscii(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        return value;
    }

    template <typename T>
    bool ReadValue(const std::vector<std::uint8_t>& bytes, std::size_t offset, T& value)
    {
        if (offset > bytes.size() || sizeof(T) > bytes.size() - offset)
        {
            return false;
        }

        std::memcpy(&value, bytes.data() + offset, sizeof(T));
        return true;
    }

    bool ReadAsciiString(
        const std::vector<std::uint8_t>& bytes,
        std::size_t offset,
        std::string& value,
        std::size_t maximumLength = kMaximumStringLength)
    {
        if (offset >= bytes.size())
        {
            return false;
        }

        const std::size_t available = std::min(maximumLength, bytes.size() - offset);
        const auto* begin = reinterpret_cast<const char*>(bytes.data() + offset);
        const auto* end = static_cast<const char*>(std::memchr(begin, '\0', available));
        if (!end)
        {
            return false;
        }

        value.assign(begin, end);
        return true;
    }

    bool ReadFileBytes(const fs::path& path, std::vector<std::uint8_t>& bytes, std::string& error)
    {
        std::error_code sizeError;
        const std::uintmax_t fileSize = fs::file_size(path, sizeError);
        if (sizeError)
        {
            error = "unable to determine file size: " + sizeError.message();
            return false;
        }
        if (fileSize == 0)
        {
            error = "file is empty";
            return false;
        }
        if (fileSize > kMaximumDriverSize || fileSize > std::numeric_limits<std::size_t>::max())
        {
            error = "file exceeds the 512 MiB safety limit";
            return false;
        }

        std::ifstream input(path, std::ios::binary);
        if (!input)
        {
            error = "unable to open file";
            return false;
        }

        bytes.resize(static_cast<std::size_t>(fileSize));
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!input || static_cast<std::size_t>(input.gcount()) != bytes.size())
        {
            error = "short read while loading file";
            bytes.clear();
            return false;
        }

        return true;
    }

    struct Section
    {
        std::uint32_t virtualSize = 0;
        std::uint32_t virtualAddress = 0;
        std::uint32_t rawSize = 0;
        std::uint32_t rawOffset = 0;
        std::uint32_t characteristics = 0;
    };

    std::optional<std::size_t> RvaToOffset(
        std::uint32_t rva,
        std::uint32_t sizeOfHeaders,
        const std::vector<Section>& sections,
        std::size_t fileSize)
    {
        if (rva < sizeOfHeaders && rva < fileSize)
        {
            return static_cast<std::size_t>(rva);
        }

        for (const Section& section : sections)
        {
            const std::uint64_t span = std::max(section.virtualSize, section.rawSize);
            if (rva < section.virtualAddress ||
                static_cast<std::uint64_t>(rva) >= static_cast<std::uint64_t>(section.virtualAddress) + span)
            {
                continue;
            }

            const std::uint64_t delta = static_cast<std::uint64_t>(rva) - section.virtualAddress;
            if (delta >= section.rawSize)
            {
                return std::nullopt;
            }

            const std::uint64_t offset = static_cast<std::uint64_t>(section.rawOffset) + delta;
            if (offset >= fileSize)
            {
                return std::nullopt;
            }
            return static_cast<std::size_t>(offset);
        }

        return std::nullopt;
    }

    bool ParseImports(
        const std::vector<std::uint8_t>& bytes,
        std::vector<std::string>& imports,
        bool& is64Bit,
        std::uint16_t& machine,
        std::vector<Section>& sections,
        std::vector<reverse::ImportSymbol>& importedSymbols,
        std::string& error)
    {
        std::uint16_t dosMagic = 0;
        std::int32_t peOffsetSigned = 0;
        if (!ReadValue(bytes, 0, dosMagic) || dosMagic != IMAGE_DOS_SIGNATURE ||
            !ReadValue(bytes, 0x3c, peOffsetSigned) || peOffsetSigned < 0)
        {
            error = "invalid DOS header";
            return false;
        }

        const std::size_t peOffset = static_cast<std::size_t>(peOffsetSigned);
        std::uint32_t peSignature = 0;
        if (!ReadValue(bytes, peOffset, peSignature) || peSignature != IMAGE_NT_SIGNATURE)
        {
            error = "invalid or truncated PE signature";
            return false;
        }

        const std::size_t coffOffset = peOffset + sizeof(std::uint32_t);
        std::uint16_t sectionCount = 0;
        std::uint16_t optionalHeaderSize = 0;
        std::uint16_t characteristics = 0;
        if (!ReadValue(bytes, coffOffset, machine) ||
            !ReadValue(bytes, coffOffset + 2, sectionCount) ||
            !ReadValue(bytes, coffOffset + 16, optionalHeaderSize) ||
            !ReadValue(bytes, coffOffset + 18, characteristics))
        {
            error = "truncated COFF header";
            return false;
        }
        if (sectionCount == 0 || sectionCount > 96)
        {
            error = "invalid PE section count";
            return false;
        }
        if ((characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
        {
            error = "PE image is not executable";
            return false;
        }

        const std::size_t optionalOffset = coffOffset + 20;
        if (optionalOffset > bytes.size() || optionalHeaderSize > bytes.size() - optionalOffset)
        {
            error = "truncated optional header";
            return false;
        }

        std::uint16_t optionalMagic = 0;
        if (!ReadValue(bytes, optionalOffset, optionalMagic))
        {
            error = "missing optional-header magic";
            return false;
        }

        std::size_t dataDirectoryOffset = 0;
        std::size_t numberOfDirectoriesOffset = 0;
        std::size_t thunkSize = 0;
        std::uint64_t ordinalMask = 0;
        if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            is64Bit = false;
            dataDirectoryOffset = 96;
            numberOfDirectoriesOffset = 92;
            thunkSize = sizeof(std::uint32_t);
            ordinalMask = IMAGE_ORDINAL_FLAG32;
        }
        else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            is64Bit = true;
            dataDirectoryOffset = 112;
            numberOfDirectoriesOffset = 108;
            thunkSize = sizeof(std::uint64_t);
            ordinalMask = IMAGE_ORDINAL_FLAG64;
        }
        else
        {
            error = "unsupported optional-header format";
            return false;
        }

        if (optionalHeaderSize < dataDirectoryOffset)
        {
            error = "optional header is smaller than its declared PE format";
            return false;
        }

        std::uint32_t sizeOfHeaders = 0;
        std::uint32_t numberOfDirectories = 0;
        std::uint16_t subsystem = 0;
        if (!ReadValue(bytes, optionalOffset + 60, sizeOfHeaders) ||
            !ReadValue(bytes, optionalOffset + 68, subsystem) ||
            !ReadValue(bytes, optionalOffset + numberOfDirectoriesOffset, numberOfDirectories))
        {
            error = "truncated optional header";
            return false;
        }
        if (subsystem != IMAGE_SUBSYSTEM_NATIVE)
        {
            error = "PE image is not a native-subsystem Windows driver";
            return false;
        }

        constexpr std::size_t importDirectoryIndex = IMAGE_DIRECTORY_ENTRY_IMPORT;
        const std::size_t importDirectoryEntry = dataDirectoryOffset + importDirectoryIndex * 8;
        std::uint32_t importRva = 0;
        std::uint32_t importSize = 0;
        if (numberOfDirectories > importDirectoryIndex)
        {
            if (importDirectoryEntry + 8 > optionalHeaderSize)
            {
                error = "declared import directory exceeds the optional header";
                return false;
            }
            ReadValue(bytes, optionalOffset + importDirectoryEntry, importRva);
            ReadValue(bytes, optionalOffset + importDirectoryEntry + 4, importSize);
        }

        const std::size_t sectionTableOffset = optionalOffset + optionalHeaderSize;
        if (sectionTableOffset > bytes.size() ||
            static_cast<std::size_t>(sectionCount) > (bytes.size() - sectionTableOffset) / 40)
        {
            error = "truncated section table";
            return false;
        }

        sections.clear();
        sections.reserve(sectionCount);
        for (std::size_t index = 0; index < sectionCount; ++index)
        {
            const std::size_t offset = sectionTableOffset + index * 40;
            Section section;
            ReadValue(bytes, offset + 8, section.virtualSize);
            ReadValue(bytes, offset + 12, section.virtualAddress);
            ReadValue(bytes, offset + 16, section.rawSize);
            ReadValue(bytes, offset + 20, section.rawOffset);
            ReadValue(bytes, offset + 36, section.characteristics);
            if (section.rawSize != 0 && (section.rawOffset > bytes.size() ||
                section.rawSize > bytes.size() - section.rawOffset))
            {
                error = "section raw data extends past the end of file";
                return false;
            }
            sections.push_back(section);
        }

        if (importRva == 0 || importSize == 0)
        {
            return true;
        }

        const std::optional<std::size_t> importOffset =
            RvaToOffset(importRva, sizeOfHeaders, sections, bytes.size());
        if (!importOffset)
        {
            error = "import directory points outside file-backed PE data";
            return false;
        }

        const std::size_t descriptorLimit = std::min<std::size_t>(
            kMaximumImportCount, static_cast<std::size_t>(importSize) / 20);
        if (descriptorLimit == 0)
        {
            error = "import directory is smaller than one descriptor";
            return false;
        }
        std::unordered_set<std::string> seen;
        bool foundTerminator = false;

        for (std::size_t descriptorIndex = 0; descriptorIndex < descriptorLimit; ++descriptorIndex)
        {
            const std::size_t descriptorOffset = *importOffset + descriptorIndex * 20;
            std::uint32_t originalFirstThunk = 0;
            std::uint32_t nameRva = 0;
            std::uint32_t firstThunk = 0;
            if (!ReadValue(bytes, descriptorOffset, originalFirstThunk) ||
                !ReadValue(bytes, descriptorOffset + 12, nameRva) ||
                !ReadValue(bytes, descriptorOffset + 16, firstThunk))
            {
                error = "truncated import descriptor table";
                return false;
            }

            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
            {
                foundTerminator = true;
                break;
            }

            const std::uint32_t thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            const auto moduleOffset = RvaToOffset(nameRva, sizeOfHeaders, sections, bytes.size());
            std::string module;
            if (!moduleOffset || !ReadAsciiString(bytes, *moduleOffset, module))
            {
                error = "invalid import module name";
                return false;
            }
            const std::optional<std::size_t> thunkOffset =
                RvaToOffset(thunkRva, sizeOfHeaders, sections, bytes.size());
            if (!thunkOffset)
            {
                error = "import thunk points outside file-backed PE data";
                return false;
            }

            bool foundThunkTerminator = false;
            for (std::size_t thunkIndex = 0; thunkIndex < kMaximumImportCount; ++thunkIndex)
            {
                const std::size_t entryOffset = *thunkOffset + thunkIndex * thunkSize;
                std::uint64_t thunkValue = 0;
                if (thunkSize == sizeof(std::uint64_t))
                {
                    if (!ReadValue(bytes, entryOffset, thunkValue))
                    {
                        error = "truncated 64-bit import thunk table";
                        return false;
                    }
                }
                else
                {
                    std::uint32_t value32 = 0;
                    if (!ReadValue(bytes, entryOffset, value32))
                    {
                        error = "truncated 32-bit import thunk table";
                        return false;
                    }
                    thunkValue = value32;
                }

                if (thunkValue == 0)
                {
                    foundThunkTerminator = true;
                    break;
                }
                if ((thunkValue & ordinalMask) != 0)
                {
                    continue;
                }
                if (thunkValue > std::numeric_limits<std::uint32_t>::max())
                {
                    error = "invalid import-name RVA";
                    return false;
                }

                const std::optional<std::size_t> nameOffset = RvaToOffset(
                    static_cast<std::uint32_t>(thunkValue), sizeOfHeaders, sections, bytes.size());
                if (!nameOffset || *nameOffset > bytes.size() || bytes.size() - *nameOffset < 2)
                {
                    error = "import name points outside file-backed PE data";
                    return false;
                }

                std::string importName;
                if (!ReadAsciiString(bytes, *nameOffset + 2, importName))
                {
                    error = "unterminated or invalid import name";
                    return false;
                }

                const std::string normalized = ToLowerAscii(importName);
                importedSymbols.push_back({ static_cast<std::uint64_t>(firstThunk) + thunkIndex * thunkSize, importName, module });
                if (seen.insert(normalized).second)
                {
                    imports.push_back(std::move(importName));
                }
            }

            if (!foundThunkTerminator)
            {
                error = "import thunk table exceeds the safety limit";
                return false;
            }
        }

        if (!foundTerminator)
        {
            error = "import descriptor table is not terminated within its declared bounds";
            return false;
        }

        std::sort(imports.begin(), imports.end());
        return true;
    }

    std::string Sha256(const std::vector<std::uint8_t>& bytes)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD objectLength = 0;
        DWORD hashLength = 0;
        DWORD copied = 0;
        std::vector<std::uint8_t> object;
        std::vector<std::uint8_t> digest;

        auto cleanup = [&]() {
            if (hash) BCryptDestroyHash(hash);
            if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        };

        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
            BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &copied, 0) < 0 ||
            BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &copied, 0) < 0)
        {
            cleanup();
            return {};
        }

        object.resize(objectLength);
        digest.resize(hashLength);
        if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) < 0)
        {
            cleanup();
            return {};
        }

        std::size_t offset = 0;
        while (offset < bytes.size())
        {
            const ULONG chunk = static_cast<ULONG>(std::min<std::size_t>(
                bytes.size() - offset, std::numeric_limits<ULONG>::max()));
            if (BCryptHashData(hash, const_cast<PUCHAR>(bytes.data() + offset), chunk, 0) < 0)
            {
                cleanup();
                return {};
            }
            offset += chunk;
        }

        if (BCryptFinishHash(hash, digest.data(), hashLength, 0) < 0)
        {
            cleanup();
            return {};
        }
        cleanup();

        std::ostringstream output;
        output << std::hex << std::setfill('0');
        for (std::uint8_t value : digest)
        {
            output << std::setw(2) << static_cast<unsigned int>(value);
        }
        return output.str();
    }

    struct ReadHandle
    {
        HANDLE value = INVALID_HANDLE_VALUE;
        ~ReadHandle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    };

    std::string AuthenticodeSha256(HANDLE file, std::string& error)
    {
        // App Control hashes exclude the PE checksum and certificate table.
        HMODULE module = LoadLibraryExW(L"wintrust.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module)
        {
            error = "unable to load the Windows Authenticode hashing provider";
            return {};
        }
        const auto acquire = reinterpret_cast<decltype(&CryptCATAdminAcquireContext2)>(
            GetProcAddress(module, "CryptCATAdminAcquireContext2"));
        const auto calculate = reinterpret_cast<decltype(&CryptCATAdminCalcHashFromFileHandle2)>(
            GetProcAddress(module, "CryptCATAdminCalcHashFromFileHandle2"));
        const auto release = reinterpret_cast<decltype(&CryptCATAdminReleaseContext)>(
            GetProcAddress(module, "CryptCATAdminReleaseContext"));

        HCATADMIN context = nullptr;
        std::vector<std::uint8_t> digest(32);
        DWORD digestLength = static_cast<DWORD>(digest.size());
        const bool success = acquire && calculate && release &&
            acquire(&context, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0) &&
            calculate(context, file, &digestLength, digest.data(), 0) && digestLength == 32;
        if (context && release) release(context, 0);
        FreeLibrary(module);
        if (!success)
        {
            error = "Windows could not calculate the Authenticode SHA-256; blocklist lookup unavailable";
            return {};
        }

        std::ostringstream output;
        output << std::hex << std::setfill('0');
        for (std::uint8_t value : digest) output << std::setw(2) << static_cast<unsigned int>(value);
        return output.str();
    }

    scanner::SignatureStatus VerifySignature(const fs::path& path, scanner::DriverAnalysis& analysis)
    {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        const std::wstring nativePath = path.wstring();
        fileInfo.pcwszFilePath = nativePath.c_str();

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

        GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const auto verify = [&](const char* source) {
            analysis.certificatePresent = false;
            analysis.certificateTimeValid = false;
            analysis.certificateExpired = false;
            const LONG status = WinVerifyTrust(nullptr, &policy, &trustData);
            auto* provider = trustData.hWVTStateData ? WTHelperProvDataFromStateData(trustData.hWVTStateData) : nullptr;
            auto* signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
            if (signer && signer->csCertChain && signer->pasCertChain[0].pCert)
            {
                analysis.certificatePresent = true;
                const LONG validity = CertVerifyTimeValidity(nullptr, signer->pasCertChain[0].pCert->pCertInfo);
                analysis.certificateTimeValid = validity == 0;
                analysis.certificateExpired = validity > 0;
            }
            analysis.signatureSource = source;
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &policy, &trustData);
            trustData.hWVTStateData = nullptr;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            return status;
        };
        LONG result = verify("embedded");
        if (result == TRUST_E_NOSIGNATURE || result == TRUST_E_SUBJECT_FORM_UNKNOWN || result == TRUST_E_PROVIDER_UNKNOWN)
        {
            analysis.signatureSource = "none";
            // Catalog lookup uses the local catalog store.
            HANDLE file = CreateFileW(nativePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            if (file != INVALID_HANDLE_VALUE)
            {
                for (const wchar_t* algorithm : {L"SHA256", L"SHA1"})
                {
                    HCATADMIN admin = nullptr;
                    GUID subsystem = DRIVER_ACTION_VERIFY;
                    if (!CryptCATAdminAcquireContext2(&admin, &subsystem, algorithm, nullptr, 0)) continue;
                    BYTE hash[64]{}; DWORD size = sizeof(hash);
                    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
                    if (CryptCATAdminCalcHashFromFileHandle2(admin, file, &size, hash, 0) && size <= sizeof(hash))
                    {
                        std::wostringstream tag;
                        tag << std::uppercase << std::hex << std::setfill(L'0');
                        for (DWORD index = 0; index < size; ++index) tag << std::setw(2) << static_cast<unsigned int>(hash[index]);
                        const auto member = tag.str();
                        HCATINFO catalog = nullptr;
                        for (int index = 0; index < 8; ++index)
                        {
                            catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, catalog ? &catalog : nullptr);
                            if (!catalog) break;
                            CATALOG_INFO info{}; info.cbStruct = sizeof(info);
                            if (CryptCATCatalogInfoFromContext(catalog, &info, 0))
                            {
                                WINTRUST_CATALOG_INFO cat{}; cat.cbStruct = sizeof(cat);
                                cat.pcwszCatalogFilePath = info.wszCatalogFile;
                                cat.pcwszMemberTag = member.c_str(); cat.pcwszMemberFilePath = nativePath.c_str();
                                cat.hMemberFile = file; cat.pbCalculatedFileHash = hash; cat.cbCalculatedFileHash = size; cat.hCatAdmin = admin;
                                trustData.dwUnionChoice = WTD_CHOICE_CATALOG; trustData.pCatalog = &cat;
                                SetFilePointer(file,0,nullptr,FILE_BEGIN);
                                result = verify("catalog");
                            }
                            if (result == ERROR_SUCCESS || index == 7)
                            { CryptCATAdminReleaseCatalogContext(admin, catalog, 0); catalog = nullptr; break; }
                        }
                    }
                    CryptCATAdminReleaseContext(admin, 0);
                    if (result == ERROR_SUCCESS) break;
                }
                CloseHandle(file);
            }
        }
        analysis.signatureResult = result;

        if (result == ERROR_SUCCESS) return scanner::SignatureStatus::Valid;
        if (result == TRUST_E_NOSIGNATURE || result == TRUST_E_SUBJECT_FORM_UNKNOWN ||
            result == TRUST_E_PROVIDER_UNKNOWN)
        {
            return scanner::SignatureStatus::Unsigned;
        }
        if (result == TRUST_E_EXPLICIT_DISTRUST || result == TRUST_E_SUBJECT_NOT_TRUSTED ||
            result == CRYPT_E_SECURITY_SETTINGS || result == CERT_E_EXPIRED || result == CERT_E_REVOKED)
        {
            return scanner::SignatureStatus::Invalid;
        }
        return scanner::SignatureStatus::CheckError;
    }

    std::wstring VersionValue(
        const std::vector<std::uint8_t>& versionData,
        WORD language,
        WORD codePage,
        const wchar_t* key)
    {
        std::wstringstream query;
        query << L"\\StringFileInfo\\" << std::hex << std::setw(4) << std::setfill(L'0') << language
              << std::setw(4) << codePage << L"\\" << key;

        void* value = nullptr;
        UINT valueLength = 0;
        if (!VerQueryValueW(const_cast<std::uint8_t*>(versionData.data()), query.str().c_str(),
                &value, &valueLength) || !value || valueLength == 0)
        {
            return {};
        }
        return std::wstring(static_cast<const wchar_t*>(value), valueLength - 1);
    }

    void ReadVersionMetadata(const fs::path& path, scanner::DriverAnalysis& analysis)
    {
        DWORD ignored = 0;
        const std::wstring nativePath = path.wstring();
        const DWORD size = GetFileVersionInfoSizeW(nativePath.c_str(), &ignored);
        if (size == 0) return;

        std::vector<std::uint8_t> data(size);
        if (!GetFileVersionInfoW(nativePath.c_str(), 0, size, data.data())) return;

        struct Translation { WORD language; WORD codePage; };
        Translation* translations = nullptr;
        UINT translationBytes = 0;
        WORD language = 0x0409;
        WORD codePage = 0x04b0;
        if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                reinterpret_cast<void**>(&translations), &translationBytes) &&
            translations && translationBytes >= sizeof(Translation))
        {
            language = translations[0].language;
            codePage = translations[0].codePage;
        }

        analysis.companyName = scanner::WideToUtf8(VersionValue(data, language, codePage, L"CompanyName"));
        analysis.productName = scanner::WideToUtf8(VersionValue(data, language, codePage, L"ProductName"));
        analysis.fileVersion = scanner::WideToUtf8(VersionValue(data, language, codePage, L"FileVersion"));
    }

    bool IsPrintableAscii(std::uint8_t value)
    {
        return value >= 0x20 && value <= 0x7e;
    }

    void AddUniqueString(std::vector<std::string>& values, std::string value)
    {
        constexpr std::size_t maximumEvidenceLength = 512;
        constexpr std::size_t maximumEvidenceItems = 20;
        if (value.size() > maximumEvidenceLength)
        {
            value.resize(maximumEvidenceLength);
            value += "...";
        }
        const std::string normalized = ToLowerAscii(value);
        const bool exists = std::any_of(values.begin(), values.end(), [&](const std::string& existing) {
            return ToLowerAscii(existing) == normalized;
        });
        if (!exists && values.size() < maximumEvidenceItems)
        {
            values.push_back(std::move(value));
        }
    }

    void ClassifyEmbeddedString(const std::string& value, scanner::DriverAnalysis& analysis)
    {
        const std::string normalized = ToLowerAscii(value);
        if (normalized.find("\\device\\") != std::string::npos)
        {
            AddUniqueString(analysis.deviceNames, value);
        }
        if (normalized.find("\\dosdevices\\") != std::string::npos ||
            normalized.find("\\global??\\") != std::string::npos ||
            normalized.rfind("\\??\\", 0) == 0)
        {
            AddUniqueString(analysis.symbolicLinks, value);
        }
        if ((normalized.find("d:p") != std::string::npos || normalized.find("d:(") != std::string::npos) &&
            (normalized.find("(a;") != std::string::npos || normalized.find("(d;") != std::string::npos))
        {
            AddUniqueString(analysis.securityDescriptors, value);
        }
        if (normalized.find("irp_mj_device_control") != std::string::npos ||
            normalized.find("evtiodevicecontrol") != std::string::npos ||
            normalized.rfind("ioctl_", 0) == 0)
        {
            AddUniqueString(analysis.requestHandlerClues, value);
        }
    }

    void ExtractEmbeddedEvidence(
        const std::vector<std::uint8_t>& bytes,
        scanner::DriverAnalysis& analysis)
    {
        constexpr std::size_t minimumStringLength = 5;

        for (std::size_t index = 0; index < bytes.size();)
        {
            if (!IsPrintableAscii(bytes[index]))
            {
                ++index;
                continue;
            }

            const std::size_t begin = index;
            while (index < bytes.size() && IsPrintableAscii(bytes[index])) ++index;
            if (index - begin >= minimumStringLength)
            {
                ClassifyEmbeddedString(std::string(
                    reinterpret_cast<const char*>(bytes.data() + begin), index - begin), analysis);
            }
        }

        for (std::size_t index = 0; index + 1 < bytes.size();)
        {
            if (!IsPrintableAscii(bytes[index]) || bytes[index + 1] != 0)
            {
                ++index;
                continue;
            }

            std::string value;
            std::size_t cursor = index;
            while (cursor + 1 < bytes.size() &&
                   IsPrintableAscii(bytes[cursor]) && bytes[cursor + 1] == 0)
            {
                value.push_back(static_cast<char>(bytes[cursor]));
                cursor += 2;
            }
            if (value.size() >= minimumStringLength)
            {
                ClassifyEmbeddedString(value, analysis);
            }
            index = cursor > index ? cursor : index + 1;
        }
    }

    bool IsHexString(const std::string& value, std::size_t requiredLength)
    {
        return value.size() == requiredLength &&
            std::all_of(value.begin(), value.end(), [](unsigned char character) {
                return std::isxdigit(character) != 0;
            });
    }

    std::string XmlAttribute(const std::string& line, const std::string& name)
    {
        const std::string marker = name + "=\"";
        const std::size_t begin = line.find(marker);
        if (begin == std::string::npos) return {};
        const std::size_t valueBegin = begin + marker.size();
        const std::size_t end = line.find('"', valueBegin);
        if (end == std::string::npos) return {};
        return line.substr(valueBegin, end - valueBegin);
    }

    bool HasPermissiveDeviceAce(const std::string& descriptor)
    {
        std::string value = descriptor;
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
            return static_cast<char>(std::toupper(character));
        });

        for (std::size_t begin = value.find('('); begin != std::string::npos;
             begin = value.find('(', begin + 1))
        {
            const std::size_t end = value.find(')', begin + 1);
            if (end == std::string::npos) break;
            const std::string ace = value.substr(begin + 1, end - begin - 1);
            std::vector<std::string> fields;
            std::size_t fieldBegin = 0;
            for (;;)
            {
                const std::size_t separator = ace.find(';', fieldBegin);
                fields.push_back(ace.substr(fieldBegin,
                    separator == std::string::npos ? std::string::npos : separator - fieldBegin));
                if (separator == std::string::npos) break;
                fieldBegin = separator + 1;
            }
            if (fields.size() < 6 || fields[0] != "A") continue;
            const std::string& rights = fields[2];
            const std::string& trustee = fields[5];
            const bool broadTrustee = trustee == "WD" || trustee == "BU" ||
                trustee == "AU" || trustee == "IU" || trustee == "AC";
            const bool writeCapable = rights.find("GA") != std::string::npos ||
                rights.find("GW") != std::string::npos;
            if (broadTrustee && writeCapable) return true;
        }
        return false;
    }

    bool DecodeModRm(
        const std::vector<std::uint8_t>& bytes,
        std::size_t modRmOffset,
        std::size_t end,
        std::size_t& operandEnd,
        std::int32_t& displacement,
        bool& hasDisplacement)
    {
        if (modRmOffset >= end || modRmOffset >= bytes.size()) return false;
        const std::uint8_t modRm = bytes[modRmOffset];
        const unsigned int mod = modRm >> 6;
        const unsigned int rm = modRm & 7;
        std::size_t cursor = modRmOffset + 1;
        bool sibBaseFive = false;
        if (mod != 3 && rm == 4)
        {
            if (cursor >= end) return false;
            sibBaseFive = (bytes[cursor] & 7) == 5;
            ++cursor;
        }

        std::size_t displacementSize = 0;
        if (mod == 0 && (rm == 5 || sibBaseFive)) displacementSize = 4;
        else if (mod == 1) displacementSize = 1;
        else if (mod == 2) displacementSize = 4;

        displacement = 0;
        hasDisplacement = displacementSize != 0;
        if (displacementSize == 1)
        {
            if (cursor >= end) return false;
            displacement = static_cast<std::int8_t>(bytes[cursor]);
        }
        else if (displacementSize == 4)
        {
            if (cursor > end || 4 > end - cursor ||
                !ReadValue(bytes, cursor, displacement)) return false;
        }
        if (cursor > end || displacementSize > end - cursor) return false;
        operandEnd = cursor + displacementSize;
        return true;
    }

    bool IsLikelyPrivateIoctl(std::uint32_t code)
    {
        const std::uint32_t deviceType = code >> 16;
        const std::uint32_t function = (code >> 2) & 0x0fff;
        if (function < 0x800 || deviceType == 0) return false;
        if (deviceType == FILE_DEVICE_UNKNOWN) return true;
        return deviceType >= 0x8000;
    }

    void AddIoctlEvidence(
        scanner::DriverAnalysis& analysis,
        std::uint32_t code,
        std::size_t fileOffset,
        const char* instruction)
    {
        constexpr std::size_t maximumIoctls = 64;
        if (analysis.ioctlEvidence.size() >= maximumIoctls || !IsLikelyPrivateIoctl(code)) return;
        const bool exists = std::any_of(analysis.ioctlEvidence.begin(), analysis.ioctlEvidence.end(),
            [code](const scanner::IoctlEvidence& evidence) { return evidence.code == code; });
        if (exists) return;

        scanner::IoctlEvidence evidence;
        evidence.code = code;
        evidence.deviceType = code >> 16;
        evidence.function = (code >> 2) & 0x0fff;
        evidence.method = code & 3;
        evidence.access = (code >> 14) & 3;
        evidence.fileOffset = fileOffset;
        evidence.instruction = instruction;
        analysis.ioctlEvidence.push_back(std::move(evidence));
    }

    void AnalyzeExecutableCode(
        const std::vector<std::uint8_t>& bytes,
        const std::vector<Section>& sections,
        bool is64Bit,
        scanner::DriverAnalysis& analysis)
    {
        for (const Section& section : sections)
        {
            if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 || section.rawSize == 0 ||
                section.rawOffset >= bytes.size()) continue;
            const std::size_t begin = section.rawOffset;
            const std::size_t end = std::min<std::size_t>(bytes.size(),
                static_cast<std::size_t>(section.rawOffset) + section.rawSize);

            for (std::size_t index = begin; index < end; ++index)
            {
                std::size_t opcodeOffset = index;
                if (is64Bit && bytes[opcodeOffset] >= 0x40 && bytes[opcodeOffset] <= 0x4f)
                {
                    ++opcodeOffset;
                    if (opcodeOffset >= end) break;
                }

                const std::uint8_t opcode = bytes[opcodeOffset];
                if (opcode == 0x3d && opcodeOffset + 5 <= end)
                {
                    std::uint32_t value = 0;
                    ReadValue(bytes, opcodeOffset + 1, value);
                    AddIoctlEvidence(analysis, value, index, "cmp-immediate");
                }
                else if (opcode == 0x81 && opcodeOffset + 2 <= end)
                {
                    const std::uint8_t modRm = bytes[opcodeOffset + 1];
                    const unsigned int operation = (modRm >> 3) & 7;
                    if (operation == 7 || operation == 5)
                    {
                        std::size_t immediateOffset = 0;
                        std::int32_t ignoredDisplacement = 0;
                        bool ignoredHasDisplacement = false;
                        if (DecodeModRm(bytes, opcodeOffset + 1, end, immediateOffset,
                                ignoredDisplacement, ignoredHasDisplacement) &&
                            immediateOffset + 4 <= end)
                        {
                            std::uint32_t value = 0;
                            ReadValue(bytes, immediateOffset, value);
                            AddIoctlEvidence(analysis, value, index,
                                operation == 7 ? "cmp-immediate" : "switch-base-immediate");
                        }
                    }
                }

                if (opcode == 0x89 && opcodeOffset + 2 <= end)
                {
                    const std::uint8_t modRm = bytes[opcodeOffset + 1];
                    if ((modRm >> 6) != 3)
                    {
                        std::size_t operandEnd = 0;
                        std::int32_t displacement = 0;
                        bool hasDisplacement = false;
                        if (DecodeModRm(bytes, opcodeOffset + 1, end, operandEnd,
                                displacement, hasDisplacement) && hasDisplacement)
                        {
                            const std::int32_t expectedOffset = is64Bit ? 0x00e0 : 0x0070;
                            if (displacement == expectedOffset)
                            {
                                analysis.ioControlDispatchPattern = true;
                            }
                        }
                    }
                }
            }
        }
    }

    void RetainCoherentIoctlFamilies(scanner::DriverAnalysis& analysis)
    {
        std::vector<scanner::IoctlEvidence> coherent;
        coherent.reserve(analysis.ioctlEvidence.size());
        for (const scanner::IoctlEvidence& candidate : analysis.ioctlEvidence)
        {
            const std::size_t nearbyFamilyPartners = static_cast<std::size_t>(std::count_if(
                analysis.ioctlEvidence.begin(), analysis.ioctlEvidence.end(),
                [&](const scanner::IoctlEvidence& other) {
                    const unsigned int functionDistance = other.function > candidate.function
                        ? other.function - candidate.function
                        : candidate.function - other.function;
                    return other.deviceType == candidate.deviceType &&
                        other.method == candidate.method && other.access == candidate.access &&
                        other.function != candidate.function && functionDistance <= 0x40;
                }));
            if (nearbyFamilyPartners >= 1) coherent.push_back(candidate);
        }
        analysis.ioctlEvidence = std::move(coherent);
    }

    fs::path FindInstalledDisassembler()
    {
        wchar_t programFiles[32768]{};
        const DWORD length = GetEnvironmentVariableW(L"ProgramFiles", programFiles, 32768);
        if (length == 0 || length >= 32768) return {};
        const fs::path root = fs::path(programFiles) / L"Microsoft Visual Studio";
        std::error_code error;
        const fs::directory_options options = fs::directory_options::skip_permission_denied;
        fs::path selected;
        // Resolve dumpbin from installed Visual Studio directories.
        for (fs::directory_iterator years(root, options, error), end; years != end && !error; years.increment(error))
        {
            const std::wstring year = years->path().filename().wstring();
            if (year.size() != 4 || !std::all_of(year.begin(), year.end(),
                    [](wchar_t character) { return character >= L'0' && character <= L'9'; })) continue;
            std::error_code editionError;
            for (fs::directory_iterator editions(years->path(), options, editionError), endEdition;
                 editions != endEdition && !editionError; editions.increment(editionError))
            {
                const fs::path versions = editions->path() / L"VC" / L"Tools" / L"MSVC";
                std::error_code versionError;
                for (fs::directory_iterator version(versions, options, versionError), endVersion;
                     version != endVersion && !versionError; version.increment(versionError))
                {
                    const fs::path executable = version->path() / L"bin" / L"Hostx64" / L"x64" / L"dumpbin.exe";
                    std::error_code existsError;
                    if (fs::is_regular_file(executable, existsError) && executable > selected) selected = executable;
                }
            }
        }
        return selected;
    }

    bool VerifyInstructionBoundaries(
        const std::vector<std::uint8_t>& bytes,
        const std::vector<Section>& sections,
        bool is64Bit,
        scanner::DriverAnalysis& analysis,
        const std::function<void(const std::string&)>& observer = {},
        const std::wstring& options = {},
        ULONGLONG timeoutMilliseconds = 30000)
    {
        const fs::path disassembler = scanner::DisassemblerPath();
        if (disassembler.empty())
        {
            analysis.codeAnalysis = "instruction verifier unavailable; install Visual Studio C++ tools for additional review coverage";
            return false;
        }

        std::int32_t peOffset = 0;
        ReadValue(bytes, 0x3c, peOffset);
        const std::size_t optionalOffset = static_cast<std::size_t>(peOffset) + 24;
        std::uint64_t imageBase = 0;
        if (is64Bit) ReadValue(bytes, optionalOffset + 24, imageBase);
        else
        {
            std::uint32_t base32 = 0;
            ReadValue(bytes, optionalOffset + 28, base32);
            imageBase = base32;
        }
        std::vector<std::uint64_t> addresses;
        for (const auto& evidence : analysis.ioctlEvidence)
        {
            std::uint64_t address = 0;
            for (const Section& section : sections)
            {
                if (evidence.fileOffset >= section.rawOffset &&
                    evidence.fileOffset - section.rawOffset < section.rawSize)
                {
                    address = imageBase + section.virtualAddress + evidence.fileOffset - section.rawOffset;
                    break;
                }
            }
            addresses.push_back(address);
        }

        SECURITY_ATTRIBUTES security{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
        HANDLE pipeRead = nullptr;
        HANDLE pipeWrite = nullptr;
        if (!CreatePipe(&pipeRead, &pipeWrite, &security, 65536))
        {
            analysis.codeAnalysis = "instruction verifier pipe creation failed";
            return false;
        }
        SetHandleInformation(pipeRead, HANDLE_FLAG_INHERIT, 0);
        HANDLE nullInput = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
        startup.hStdOutput = pipeWrite;
        startup.hStdError = pipeWrite;
        startup.hStdInput = nullInput;
        PROCESS_INFORMATION process{};
        std::wstring command = L"\"" + disassembler.wstring() + L"\" /NOLOGO /NOPDB /DISASM:NOBYTES " + options + L" \"" +
            analysis.path.wstring() + L"\"";
        const BOOL started = CreateProcessW(disassembler.c_str(), command.data(), nullptr, nullptr,
            TRUE, CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS, nullptr, nullptr, &startup, &process);
        CloseHandle(pipeWrite);
        if (nullInput != INVALID_HANDLE_VALUE) CloseHandle(nullInput);
        if (!started)
        {
            CloseHandle(pipeRead);
            analysis.codeAnalysis = "installed instruction verifier could not be started";
            return false;
        }
        CloseHandle(process.hThread);
        std::vector<bool> verified(addresses.size(), false);
        const auto inspectLine = [&](const std::string& line) {
            if (observer) { observer(line); return; }
            char* end = nullptr;
            const std::uint64_t address = std::strtoull(line.c_str(), &end, 16);
            if (end == line.c_str() || *end != ':' ||
                std::find(addresses.begin(), addresses.end(), address) == addresses.end()) return;
            ++end;
            while (*end == ' ' || *end == '\t') ++end;
            const bool comparison = std::strncmp(end, "cmp", 3) == 0;
            const bool subtraction = std::strncmp(end, "sub", 3) == 0;
            if ((!comparison && !subtraction) || (end[3] != ' ' && end[3] != '\t')) return;
            for (std::size_t index = 0; index < addresses.size(); ++index)
                if (address == addresses[index]) verified[index] = true;
        };

        std::string pending;
        std::size_t received = 0;
        const ULONGLONG start = GetTickCount64();
        bool failed = false;
        for (;;)
        {
            DWORD available = 0;
            if (!PeekNamedPipe(pipeRead, nullptr, 0, nullptr, &available, nullptr))
            {
                if (GetLastError() != ERROR_BROKEN_PIPE) failed = true;
                break;
            }
            if (available)
            {
                char buffer[65536];
                DWORD copied = 0;
                if (!ReadFile(pipeRead, buffer, std::min<DWORD>(available, sizeof(buffer)), &copied, nullptr))
                {
                    failed = true;
                    break;
                }
                pending.append(buffer, copied);
                received += copied;
                std::size_t begin = 0;
                for (std::size_t newline = pending.find('\n'); newline != std::string::npos;
                     newline = pending.find('\n', begin))
                {
                    inspectLine(pending.substr(begin, newline - begin));
                    begin = newline + 1;
                }
                pending.erase(0, begin);
            }
            else if (WaitForSingleObject(process.hProcess, 1) == WAIT_OBJECT_0)
            {
                // Drain pending output after the child exits.
                DWORD remaining = 0;
                if (!PeekNamedPipe(pipeRead, nullptr, 0, nullptr, &remaining, nullptr) || remaining == 0) break;
            }

            if (GetTickCount64() - start > timeoutMilliseconds || received > 128ULL * 1024ULL * 1024ULL || pending.size() > 65536)
            {
                failed = true;
                break;
            }
        }
        if (failed) TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 1000);
        DWORD exitCode = 1;
        GetExitCodeProcess(process.hProcess, &exitCode);
        CloseHandle(process.hProcess);
        CloseHandle(pipeRead);
        if (failed || exitCode != 0)
        {
            analysis.codeAnalysis = "instruction verification failed or exceeded resource limits";
            return false;
        }
        if (observer) return true;
        std::vector<scanner::IoctlEvidence> instructions;
        for (std::size_t index = 0; index < verified.size(); ++index)
            if (verified[index]) instructions.push_back(analysis.ioctlEvidence[index]);
        analysis.ioctlEvidence = std::move(instructions);
        RetainCoherentIoctlFamilies(analysis);
        analysis.instructionBoundariesVerified = true;
        analysis.codeAnalysis = "Visual Studio instruction boundaries checked; IOCTL provenance, reachability and validation unverified";
        return true;
    }

    void AnalyzeRequestFlows(
        const std::vector<std::uint8_t>& bytes,
        const std::vector<Section>& sections,
        std::vector<reverse::ImportSymbol> imports,
        scanner::DriverAnalysis& analysis)
    {
        std::int32_t peOffset = 0;
        ReadValue(bytes, 0x3c, peOffset);
        const std::size_t optional = static_cast<std::size_t>(peOffset) + 24;
        std::uint32_t entryRva = 0;
        std::uint32_t sizeOfHeaders = 0;
        std::uint32_t directoryCount = 0;
        reverse::Program program;
        const auto reverseStart = GetTickCount64();
        constexpr ULONGLONG reverseBudgetMilliseconds = 10000;
        program.timeBudgetExpired = [&] { return GetTickCount64() - reverseStart >= reverseBudgetMilliseconds; };
        ReadValue(bytes, optional + 16, entryRva);
        ReadValue(bytes, optional + 24, program.imageBase);
        ReadValue(bytes, optional + 60, sizeOfHeaders);
        ReadValue(bytes, optional + 108, directoryCount);
        program.entry = program.imageBase + entryRva;
        for (auto& imported : imports) imported.address += program.imageBase;
        program.imports = std::move(imports);

        std::vector<std::pair<std::uint32_t, std::uint32_t>> functions;
        std::uint16_t optionalSize = 0;
        ReadValue(bytes, static_cast<std::size_t>(peOffset) + 20, optionalSize);
        if (directoryCount > IMAGE_DIRECTORY_ENTRY_EXCEPTION && optionalSize >= 112 + 8 * (IMAGE_DIRECTORY_ENTRY_EXCEPTION + 1))
        {
            std::uint32_t exceptionRva = 0;
            std::uint32_t exceptionSize = 0;
            ReadValue(bytes, optional + 112 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8, exceptionRva);
            ReadValue(bytes, optional + 116 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8, exceptionSize);
            const auto offset = RvaToOffset(exceptionRva, sizeOfHeaders, sections, bytes.size());
            if (exceptionRva && offset && exceptionSize <= bytes.size() - *offset)
            {
                for (std::size_t index = 0; index < std::min<std::size_t>(exceptionSize / 12, 100000); ++index)
                {
                    std::uint32_t begin = 0;
                    std::uint32_t end = 0;
                    ReadValue(bytes, *offset + index * 12, begin);
                    ReadValue(bytes, *offset + index * 12 + 4, end);
                    if (begin < end) functions.emplace_back(begin, end);
                }
                std::sort(functions.begin(), functions.end());
            }
        }
        bool providerIncomplete = false;
        std::string providerError;
        program.fileOffset = [&](std::uint64_t address) -> std::size_t {
            if (address < program.imageBase || address - program.imageBase > 0xffffffff) return 0;
            const auto offset = RvaToOffset(static_cast<std::uint32_t>(address - program.imageBase), sizeOfHeaders, sections, bytes.size());
            return offset.value_or(0);
        };
        program.instructions = [&](std::uint64_t address) {
            std::vector<reverse::Instruction> instructions;
            if (program.timeBudgetExpired()) { providerIncomplete = true; return instructions; }
            if (address < program.imageBase || address - program.imageBase > 0xffffffff) return instructions;
            const auto rva = static_cast<std::uint32_t>(address - program.imageBase);
            std::uint64_t begin = address;
            std::uint64_t end = address;
            for (const Section& section : sections)
            {
                if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) && rva >= section.virtualAddress &&
                    static_cast<std::uint64_t>(rva) - section.virtualAddress < section.rawSize)
                {
                    end = program.imageBase + section.virtualAddress + section.rawSize;
                    break;
                }
            }
            if (end == address) return instructions;
            const auto function = std::upper_bound(functions.begin(), functions.end(),
                std::make_pair(rva, std::numeric_limits<std::uint32_t>::max()));
            if (function != functions.begin())
            {
                const auto& range = *std::prev(function);
                if (rva >= range.first && rva < range.second)
                {
                    begin = program.imageBase + range.first;
                    end = std::min<std::uint64_t>(end, program.imageBase + range.second);
                }
            }
            if (end - begin > 65536) { end = begin + 65536; providerIncomplete = true; }
            if (address >= end) return instructions;
            std::wostringstream options;
            options << L"/RANGE:0x" << std::hex << begin << L",0x" << end - 1;
            const auto observe = [&](const std::string& line) {
                char* text = nullptr;
                const std::uint64_t instructionAddress = std::strtoull(line.c_str(), &text, 16);
                if (text == line.c_str() || *text != ':' || instructionAddress < begin || instructionAddress >= end) return;
                ++text;
                std::istringstream row(text);
                reverse::Instruction instruction;
                instruction.address = instructionAddress;
                if (!(row >> instruction.mnemonic)) return;
                std::getline(row, instruction.operands);
                const auto first = instruction.operands.find_first_not_of(" \t");
                instruction.operands = first == std::string::npos ? "" : instruction.operands.substr(first);
                if (instructions.size() < 12000) instructions.push_back(std::move(instruction));
                else providerIncomplete = true;
            };
            const auto elapsed = GetTickCount64() - reverseStart;
            const auto remaining = elapsed < reverseBudgetMilliseconds ? reverseBudgetMilliseconds - elapsed : 1;
            if (!VerifyInstructionBoundaries(bytes, sections, true, analysis, observe, options.str(), remaining))
            {
                providerIncomplete = true;
                providerError = analysis.codeAnalysis;
                instructions.clear();
                return instructions;
            }
            for (std::size_t index = 1; index < instructions.size(); ++index)
                instructions[index - 1].next = instructions[index].address;
            return instructions;
        };
        reverse::AnalyzeWdmX64(program, analysis);
        analysis.reverseElapsedMilliseconds = GetTickCount64() - reverseStart;
        if (providerIncomplete)
        {
            analysis.reverseAnalysisIncomplete = true;
            analysis.reverseAnalysis += providerError.empty() ? " Disassembly region limit reached." : " " + providerError;
            analysis.reverseCoverageReasons.push_back(providerError.empty() ? "disassembly-region-budget" : "disassembler-failure:" + providerError);
        }
    }
}

std::filesystem::path scanner::DisassemblerPath()
{
    static const fs::path installed = FindInstalledDisassembler();
    return installed;
}

std::vector<scanner::KnownVulnerableDriver>
scanner::LoadMicrosoftVulnerableDriverBlocklist(std::string& source, std::string& error)
{
    source.clear();
    error.clear();
    std::vector<KnownVulnerableDriver> entries;

    std::vector<wchar_t> windowsDirectory(MAX_PATH + 1, L'\0');
    UINT length = GetWindowsDirectoryW(windowsDirectory.data(),
        static_cast<UINT>(windowsDirectory.size()));
    if (length == 0)
    {
        error = "GetWindowsDirectory failed";
        return entries;
    }
    if (length >= windowsDirectory.size())
    {
        windowsDirectory.resize(static_cast<std::size_t>(length) + 1, L'\0');
        length = GetWindowsDirectoryW(windowsDirectory.data(),
            static_cast<UINT>(windowsDirectory.size()));
        if (length == 0 || length >= windowsDirectory.size())
        {
            error = "Windows directory path is too long";
            return entries;
        }
    }

    const fs::path policyPath = fs::path(windowsDirectory.data()) /
        L"schemas" / L"CodeIntegrity" / L"ExamplePolicies" /
        L"RecommendedDriverBlock_Enforced.xml";
    std::ifstream input(policyPath, std::ios::binary);
    if (!input)
    {
        error = "Microsoft blocklist XML is not installed at " + WideToUtf8(policyPath.wstring());
        return entries;
    }
    source = WideToUtf8(policyPath.wstring());

    std::unordered_set<std::string> hashes;
    std::string line;
    while (std::getline(input, line))
    {
        if (line.find("<Deny ") == std::string::npos) continue;
        const std::string friendlyName = XmlAttribute(line, "FriendlyName");
        if (friendlyName.find("Hash Sha256") == std::string::npos ||
            friendlyName.find("Hash Page Sha256") != std::string::npos) continue;
        std::string hash = ToLowerAscii(XmlAttribute(line, "Hash"));
        if (!IsHexString(hash, 64) || !hashes.insert(hash).second) continue;
        entries.push_back({ std::move(hash), friendlyName, source });
    }

    if (!input.eof())
    {
        error = "Microsoft blocklist XML could not be read completely";
        entries.clear();
        return entries;
    }
    if (entries.empty()) error = "Microsoft blocklist contained no Authenticode SHA-256 deny rules";
    return entries;
}

bool scanner::DriverAnalysis::HasSensitiveCapability() const
{
    return std::any_of(matches.begin(), matches.end(), [](const ImportMatch& match) {
        return match.rule.kind == IndicatorKind::SensitiveCapability;
    });
}

bool scanner::DriverAnalysis::HasExposureSignal() const
{
    return std::any_of(matches.begin(), matches.end(), [](const ImportMatch& match) {
        return match.rule.kind == IndicatorKind::DeviceExposure;
    });
}

bool scanner::DriverAnalysis::HasRequestHandlingSignal() const
{
    const bool importSignal = std::any_of(matches.begin(), matches.end(), [](const ImportMatch& match) {
        return match.rule.kind == IndicatorKind::RequestHandling;
    });
    return importSignal || !requestHandlerClues.empty() ||
        ioControlDispatchPattern || !ioctlEvidence.empty();
}

bool scanner::DriverAnalysis::HasSafeguardSignal() const
{
    return std::any_of(matches.begin(), matches.end(), [](const ImportMatch& match) {
        return match.rule.kind == IndicatorKind::Safeguard;
    });
}

bool scanner::DriverAnalysis::HasRiskyIoctl() const
{
    return std::any_of(ioctlEvidence.begin(), ioctlEvidence.end(), [](const IoctlEvidence& evidence) {
        return evidence.access == FILE_ANY_ACCESS || evidence.method == METHOD_NEITHER;
    });
}

bool scanner::DriverAnalysis::HasIoctlFamily() const
{
    return ioctlEvidence.size() >= 2;
}

bool scanner::DriverAnalysis::HasDataflowCandidate() const
{
    return std::any_of(findings.begin(), findings.end(), [](const FlowFinding& finding) { return !finding.reviewOnly; });
}

bool scanner::DriverAnalysis::IsCandidate() const
{
    if (knownVulnerable) return true;
    if (HasDataflowCandidate()) return true;
    return HasSensitiveCapability() && HasExposureSignal() &&
        instructionBoundariesVerified && HasIoctlFamily() && HasRiskyIoctl() &&
        (unsafeUserBufferApi || permissiveSecurityDescriptor);
}

std::string scanner::DriverAnalysis::Assessment() const
{
    switch (Evidence())
    {
    case EvidenceCategory::AnalysisError: return "analysis-error";
    case EvidenceCategory::PolicyMatch: return "policy-hash-match";
    case EvidenceCategory::RequestFlow: return "request-flow-observed";
    case EvidenceCategory::QualifiedFlow: return "qualified-flow-observed";
    case EvidenceCategory::Pattern: return "pattern-lead";
    default: return "metadata-only";
    }
}

scanner::EvidenceCategory scanner::DriverAnalysis::Evidence() const
{
    if (!parseSucceeded) return EvidenceCategory::AnalysisError;
    if (knownVulnerable) return EvidenceCategory::PolicyMatch;
    if (HasDataflowCandidate()) return EvidenceCategory::RequestFlow;
    if (!findings.empty()) return EvidenceCategory::QualifiedFlow;
    if (IsCandidate()) return EvidenceCategory::Pattern;
    return EvidenceCategory::Metadata;
}

std::string scanner::DriverAnalysis::CoverageStatus() const
{
    if (!parseSucceeded) return "error";
    if (!reverseDecodedInstructions) return "unavailable";
    if (reverseAnalysisIncomplete || !instructionVerificationError.empty()) return "partial";
    return "bounded";
}

const char* scanner::EvidenceLabel(EvidenceCategory category)
{
    switch (category)
    {
    case EvidenceCategory::PolicyMatch: return "Policy match";
    case EvidenceCategory::RequestFlow: return "Request flow";
    case EvidenceCategory::QualifiedFlow: return "Qualified flow";
    case EvidenceCategory::Pattern: return "Pattern lead";
    case EvidenceCategory::Metadata: return "Metadata only";
    default: return "Analysis error";
    }
}

const char* scanner::EvidenceDescription(EvidenceCategory category)
{
    switch (category)
    {
    case EvidenceCategory::PolicyMatch: return "Exact Authenticode SHA-256 match against an installed deny rule. This identifies a listed image, not a new vulnerability.";
    case EvidenceCategory::RequestFlow: return "Request-derived data reaches a modeled memory operation. Effective caller access and runtime impact require validation.";
    case EvidenceCategory::QualifiedFlow: return "A request-flow trace includes observed guards or unresolved helpers. The adequacy of validation remains unresolved.";
    case EvidenceCategory::Pattern: return "Correlated imports and instruction patterns. A request-to-operation path has not been reconstructed.";
    case EvidenceCategory::Metadata: return "No actionable request-flow finding was recovered. Review coverage before drawing conclusions.";
    default: return "The image could not be analyzed. Consult the recorded error.";
    }
}

bool scanner::ReviewBefore(const DriverAnalysis& left, const DriverAnalysis& right)
{
    if (left.Evidence() != right.Evidence()) return left.Evidence() > right.Evidence();
    if (left.findings.size() != right.findings.size()) return left.findings.size() > right.findings.size();
    return left.path < right.path;
}

std::vector<fs::path> scanner::GetDriverFiles(
    const fs::path& root,
    bool recursive,
    std::vector<std::string>& discoveryErrors)
{
    std::vector<fs::path> files;
    const fs::directory_options options = fs::directory_options::skip_permission_denied;
    std::error_code error;

    auto consider = [&](const fs::directory_entry& entry) {
        std::error_code typeError;
        if (entry.is_regular_file(typeError) && ToLowerAscii(entry.path().extension().string()) == ".sys")
        {
            files.push_back(entry.path());
        }
    };

    if (recursive)
    {
        fs::recursive_directory_iterator iterator(root, options, error);
        const fs::recursive_directory_iterator end;
        if (error)
        {
            discoveryErrors.push_back(error.message());
            return files;
        }
        while (iterator != end)
        {
            consider(*iterator);
            iterator.increment(error);
            if (error)
            {
                discoveryErrors.push_back(error.message());
                error.clear();
            }
        }
    }
    else
    {
        fs::directory_iterator iterator(root, options, error);
        const fs::directory_iterator end;
        if (error)
        {
            discoveryErrors.push_back(error.message());
            return files;
        }
        while (iterator != end)
        {
            consider(*iterator);
            iterator.increment(error);
            if (error)
            {
                discoveryErrors.push_back(error.message());
                error.clear();
            }
        }
    }

    std::sort(files.begin(), files.end());
    return files;
}

scanner::DriverAnalysis scanner::AnalyzeDriver(
    const fs::path& driverPath,
    const std::vector<ImportRule>& rules,
    const std::vector<KnownVulnerableDriver>& knownDrivers)
{
    DriverAnalysis analysis;
    analysis.path = driverPath;

    // Prevent file changes during parsing, hashing, and metadata checks.
    ReadHandle sample;
    sample.value = CreateFileW(driverPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (sample.value == INVALID_HANDLE_VALUE)
    {
        analysis.parseError = "unable to open a stable read-only handle to the sample";
        return analysis;
    }

    std::vector<std::uint8_t> bytes;
    if (!ReadFileBytes(driverPath, bytes, analysis.parseError)) return analysis;

    analysis.sha256 = Sha256(bytes);
    analysis.signature = VerifySignature(driverPath, analysis);
    ReadVersionMetadata(driverPath, analysis);
    ExtractEmbeddedEvidence(bytes, analysis);

    std::vector<std::string> imports;
    bool is64Bit = false;
    std::uint16_t machine = 0;
    std::vector<Section> sections;
    std::vector<reverse::ImportSymbol> importedSymbols;
    if (!ParseImports(bytes, imports, is64Bit, machine, sections, importedSymbols, analysis.parseError)) return analysis;
    analysis.parseSucceeded = true;
    analysis.authenticodeSha256 = AuthenticodeSha256(sample.value, analysis.hashError);
    if ((machine == IMAGE_FILE_MACHINE_AMD64 && is64Bit) ||
        (machine == IMAGE_FILE_MACHINE_I386 && !is64Bit))
    {
        AnalyzeExecutableCode(bytes, sections, is64Bit, analysis);
        RetainCoherentIoctlFamilies(analysis);
        analysis.codeAnalysis = "byte-patterns-only; instruction boundaries and IOCTL data flow unverified";
    }
    else
    {
        analysis.codeAnalysis = "unsupported instruction set; imports and hash lookup only";
    }

    for (const std::string& descriptor : analysis.securityDescriptors)
    {
        if (HasPermissiveDeviceAce(descriptor))
        {
            analysis.permissiveSecurityDescriptor = true;
            break;
        }
    }

    const std::string normalizedHash = ToLowerAscii(analysis.authenticodeSha256);
    const auto known = std::find_if(knownDrivers.begin(), knownDrivers.end(),
        [&](const KnownVulnerableDriver& entry) {
            return !normalizedHash.empty() && normalizedHash == ToLowerAscii(entry.sha256);
        });
    if (known != knownDrivers.end())
    {
        analysis.knownVulnerable = true;
        analysis.knownVulnerableLabel = known->label;
        analysis.knownVulnerableSource = known->source;
    }

    std::unordered_set<std::string> importedNames;
    for (const std::string& name : imports) importedNames.insert(ToLowerAscii(name));

    std::unordered_set<std::string> matchedRules;
    for (const ImportRule& rule : rules)
    {
        const std::string normalizedRule = ToLowerAscii(rule.name);
        if (importedNames.find(normalizedRule) == importedNames.end() ||
            !matchedRules.insert(normalizedRule).second)
        {
            continue;
        }
        analysis.matches.push_back({ rule, rule.name });
    }

    analysis.unsafeUserBufferApi =
        importedNames.find("wdfrequestretrieveunsafeuserinputbuffer") != importedNames.end() ||
        importedNames.find("wdfrequestretrieveunsafeuseroutputbuffer") != importedNames.end();

    if (analysis.HasSensitiveCapability() && analysis.HasExposureSignal() &&
        analysis.HasIoctlFamily() && analysis.HasRiskyIoctl() &&
        (analysis.unsafeUserBufferApi || analysis.permissiveSecurityDescriptor))
    {
        VerifyInstructionBoundaries(bytes, sections, is64Bit, analysis);
        if (!analysis.instructionBoundariesVerified)
            analysis.instructionVerificationError = analysis.codeAnalysis;
    }

    // ParseImports validates IMAGE_SUBSYSTEM_NATIVE before dispatch analysis.
    if (machine == IMAGE_FILE_MACHINE_AMD64 && is64Bit)
        AnalyzeRequestFlows(bytes, sections, std::move(importedSymbols), analysis);
    else
    {
        analysis.reverseAnalysis = "Request-flow analysis requires a Windows x64 native image; this does not establish safety.";
        analysis.reverseAnalysisIncomplete = true;
        analysis.reverseCoverageReasons.push_back("unsupported-architecture-or-subsystem");
    }
    if (importedNames.count("wdfversionbind"))
    {
        analysis.reverseAnalysisIncomplete = true;
        analysis.reverseCoverageReasons.push_back("kmdf-runtime-callbacks-unmodeled");
    }

    std::sort(analysis.matches.begin(), analysis.matches.end(), [](const ImportMatch& left, const ImportMatch& right) {
        if (left.rule.weight != right.rule.weight) return left.rule.weight > right.rule.weight;
        return left.rule.name < right.rule.name;
    });
    return analysis;
}

std::vector<scanner::ImportRule> scanner::DefaultRules()
{
    return {
        { "MmMapIoSpace", "physical-memory mapping", "Maps device or physical address ranges into kernel virtual memory.", 5, IndicatorKind::SensitiveCapability },
        { "MmMapIoSpaceEx", "physical-memory mapping", "Maps device or physical address ranges with explicit protection.", 5, IndicatorKind::SensitiveCapability },
        { "ZwMapViewOfSection", "section mapping", "Maps a section view; review whether user input can select a privileged section or range.", 5, IndicatorKind::SensitiveCapability },
        { "ZwOpenSection", "section mapping", "Opens a section object; review access checks and object-name control.", 3, IndicatorKind::SensitiveCapability },
        { "MmGetPhysicalAddress", "address translation", "Translates a valid virtual address to a physical address.", 4, IndicatorKind::SensitiveCapability },
        { "MmCopyMemory", "physical-memory access", "Can copy from virtual or physical address sources depending on flags.", 5, IndicatorKind::SensitiveCapability },
        { "MmMapLockedPagesSpecifyCache", "MDL mapping", "Maps locked pages into an address space with a selected cache policy.", 4, IndicatorKind::SensitiveCapability },
        { "MmAllocatePagesForMdl", "MDL allocation", "Allocates physical pages described by an MDL.", 3, IndicatorKind::SensitiveCapability },
        { "MmAllocatePagesForMdlEx", "MDL allocation", "Allocates physical pages described by an MDL with additional controls.", 3, IndicatorKind::SensitiveCapability },
        { "IoAllocateMdl", "MDL handling", "Creates an MDL for a caller-supplied virtual buffer.", 2, IndicatorKind::SensitiveCapability },
        { "MmCopyVirtualMemory", "cross-process memory", "Copies memory between process address spaces.", 5, IndicatorKind::SensitiveCapability },
        { "ZwReadVirtualMemory", "cross-process memory", "Reads a process virtual address range through a process handle.", 5, IndicatorKind::SensitiveCapability },
        { "ZwWriteVirtualMemory", "cross-process memory", "Writes a process virtual address range through a process handle.", 5, IndicatorKind::SensitiveCapability },
        { "KeStackAttachProcess", "process attachment", "Temporarily executes in another process address space.", 3, IndicatorKind::SensitiveCapability },
        { "HalTranslateBusAddress", "bus address translation", "Translates a bus-relative address to a system physical address.", 3, IndicatorKind::SensitiveCapability },

        { "IoCreateDevice", "device exposure", "Creates a device object; inspect its ACL, namespace, and dispatch routines.", 1, IndicatorKind::DeviceExposure },
        { "IoCreateDeviceSecure", "device exposure", "Creates a named device object with an explicit security descriptor.", 1, IndicatorKind::DeviceExposure },
        { "WdmlibIoCreateDeviceSecure", "device exposure", "Creates a named device object with an explicit security descriptor.", 1, IndicatorKind::DeviceExposure },
        { "IoCreateSymbolicLink", "device exposure", "May expose a device name to user-mode callers.", 2, IndicatorKind::DeviceExposure },
        { "IoCreateUnprotectedSymbolicLink", "device exposure", "Creates a symbolic link without normal protection; review namespace access closely.", 3, IndicatorKind::DeviceExposure },
        { "IoRegisterDeviceInterface", "device exposure", "Registers a device interface that user mode may discover.", 2, IndicatorKind::DeviceExposure },
        { "WdfControlDeviceInitAllocate", "device exposure", "Initializes a KMDF control device that can receive user-mode requests.", 2, IndicatorKind::DeviceExposure },
        { "WdfDeviceCreate", "device exposure", "Creates a WDF device object; inspect device-init security configuration.", 1, IndicatorKind::DeviceExposure },
        { "WdfDeviceCreateSymbolicLink", "device exposure", "Creates a WDF symbolic link that may be reachable from user mode.", 2, IndicatorKind::DeviceExposure },
        { "WdfDeviceCreateDeviceInterface", "device exposure", "Creates a discoverable WDF device interface.", 2, IndicatorKind::DeviceExposure },

        { "WdfIoQueueCreate", "request handling", "Creates a WDF I/O queue whose callbacks may handle IOCTL requests.", 2, IndicatorKind::RequestHandling },
        { "WdfRequestRetrieveInputBuffer", "request handling", "Retrieves a request input buffer for a WDF callback.", 1, IndicatorKind::RequestHandling },
        { "WdfRequestRetrieveOutputBuffer", "request handling", "Retrieves a request output buffer for a WDF callback.", 1, IndicatorKind::RequestHandling },
        { "WdfRequestRetrieveUnsafeUserInputBuffer", "request handling", "Retrieves an unvalidated user input pointer; inspect probing and locking.", 3, IndicatorKind::RequestHandling },
        { "WdfRequestRetrieveUnsafeUserOutputBuffer", "request handling", "Retrieves an unvalidated user output pointer; inspect probing and locking.", 3, IndicatorKind::RequestHandling },

        { "IoValidateDeviceIoControlAccess", "observed safeguard", "Can enforce access stricter than the IOCTL RequiredAccess bits; confirm it covers sensitive requests.", 0, IndicatorKind::Safeguard },
        { "ProbeForRead", "observed safeguard", "Can validate a user-mode read range; confirm exception handling and TOCTOU safety.", 0, IndicatorKind::Safeguard },
        { "ProbeForWrite", "observed safeguard", "Can validate a user-mode write range; confirm exception handling and TOCTOU safety.", 0, IndicatorKind::Safeguard },
        { "SeSinglePrivilegeCheck", "observed safeguard", "Can enforce a caller privilege check; confirm the result gates the sensitive operation.", 0, IndicatorKind::Safeguard },
        { "SePrivilegeCheck", "observed safeguard", "Can enforce caller privilege requirements; confirm the result gates the sensitive operation.", 0, IndicatorKind::Safeguard },
        { "WdfRequestProbeAndLockUserBufferForRead", "observed safeguard", "Can validate and lock a user buffer for device reads.", 0, IndicatorKind::Safeguard },
        { "WdfRequestProbeAndLockUserBufferForWrite", "observed safeguard", "Can validate and lock a user buffer for device writes.", 0, IndicatorKind::Safeguard }
    };
}

const char* scanner::IndicatorKindText(IndicatorKind kind)
{
    switch (kind)
    {
    case IndicatorKind::SensitiveCapability: return "sensitive-capability";
    case IndicatorKind::DeviceExposure: return "device-exposure";
    case IndicatorKind::RequestHandling: return "request-handling";
    case IndicatorKind::Safeguard: return "observed-safeguard";
    default: return "unknown";
    }
}

const char* scanner::SignatureStatusText(SignatureStatus status)
{
    switch (status)
    {
    case SignatureStatus::Valid: return "valid";
    case SignatureStatus::Unsigned: return "not-verified";
    case SignatureStatus::Invalid: return "invalid";
    default: return "check-error";
    }
}

const char* scanner::CertificateStatusText(const DriverAnalysis& analysis)
{
    if (!analysis.parseSucceeded) return "Unavailable";
    if (analysis.signature == SignatureStatus::Valid)
        return analysis.certificatePresent ? (analysis.certificateTimeValid ? "Valid (offline)" : "Expired / not yet valid") : "Signer unavailable";
    if (analysis.signature == SignatureStatus::Invalid) return "Invalid / untrusted";
    if (analysis.signature == SignatureStatus::Unsigned) return "No signature found";
    return "Check inconclusive";
}

const char* scanner::IoctlMethodText(unsigned int method)
{
    switch (method)
    {
    case METHOD_BUFFERED: return "METHOD_BUFFERED";
    case METHOD_IN_DIRECT: return "METHOD_IN_DIRECT";
    case METHOD_OUT_DIRECT: return "METHOD_OUT_DIRECT";
    case METHOD_NEITHER: return "METHOD_NEITHER";
    default: return "unknown";
    }
}

const char* scanner::IoctlAccessText(unsigned int access)
{
    switch (access)
    {
    case FILE_ANY_ACCESS: return "FILE_ANY_ACCESS";
    case FILE_READ_ACCESS: return "FILE_READ_ACCESS";
    case FILE_WRITE_ACCESS: return "FILE_WRITE_ACCESS";
    case FILE_READ_ACCESS | FILE_WRITE_ACCESS: return "FILE_READ_WRITE_ACCESS";
    default: return "unknown";
    }
}

std::string scanner::WideToUtf8(const std::wstring& value)
{
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};

    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        value.c_str(), static_cast<int>(value.size()), result.data(), required, nullptr, nullptr);
    return result;
}
