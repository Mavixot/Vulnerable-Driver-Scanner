#pragma once

#define DRIVER_SCANNER_VERSION_TUPLE 0,2,0,0
#define DRIVER_SCANNER_VERSION_STRING "0.2.0"

#ifndef RC_INVOKED
namespace app
{
    inline constexpr wchar_t Name[] = L"Driver Scanner";
    inline constexpr wchar_t Version[] = L"0.2.0";
    inline constexpr char VersionUtf8[] = "0.2.0";
    inline constexpr int ReportSchema = 2;
}
#endif
