#pragma once

#include <Windows.h>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>

namespace pe
{
    inline std::string machine_type_to_string(WORD machine)
    {
        switch (machine) {
            case IMAGE_FILE_MACHINE_AMD64: return "x64 (AMD64)";
            case IMAGE_FILE_MACHINE_I386: return "x86 (i386)";
            case IMAGE_FILE_MACHINE_ARM: return "ARM";
            case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
            case IMAGE_FILE_MACHINE_IA64: return "IA-64";
            case IMAGE_FILE_MACHINE_ARMNT: return "ARM Thumb-2";
            default: {
                std::ostringstream out;
                out << "Unknown (0x" << std::hex << std::setfill('0') << std::setw(4) << machine << ")";
                return out.str();
            }
        }
    }

    inline std::string subsystem_to_string(WORD subsystem)
    {
        switch (subsystem) {
            case IMAGE_SUBSYSTEM_NATIVE: return "Native";
            case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "Windows GUI";
            case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "Windows Console";
            case IMAGE_SUBSYSTEM_OS2_CUI: return "OS/2 Console";
            case IMAGE_SUBSYSTEM_POSIX_CUI: return "POSIX Console";
            case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: return "Windows CE GUI";
            case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "EFI Application";
            case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI Boot Service Driver";
            case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "EFI Runtime Driver";
            case IMAGE_SUBSYSTEM_XBOX: return "Xbox";
            case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "Windows Boot Application";
            default: {
                std::ostringstream out;
                out << "Unknown (" << subsystem << ")";
                return out.str();
            }
        }
    }

    inline std::string timestamp_to_string(DWORD timestamp)
    {
        if (timestamp == 0) {
            return "N/A";
        }

        std::time_t time = static_cast<std::time_t>(timestamp);
        std::tm tm_buf = {};
        gmtime_s(&tm_buf, &time);

        std::ostringstream out;
        out << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S UTC");
        return out.str();
    }

    inline std::string characteristics_to_string(DWORD characteristics)
    {
        std::string result;

        struct flag_entry
        {
            DWORD flag;
            const char* name;
        };

        static const flag_entry flags[] = {
            {IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED"},
            {IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE"},
            {IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED"},
            {IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED"},
            {IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESSIVE_WS_TRIM"},
            {IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE"},
            {IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED"},
            {IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP"},
            {IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP"},
            {IMAGE_FILE_SYSTEM, "SYSTEM"},
            {IMAGE_FILE_DLL, "DLL"},
            {IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY"},
        };

        for (const auto& entry : flags) {
            if (characteristics & entry.flag) {
                if (!result.empty()) {
                    result += " | ";
                }
                result += entry.name;
            }
        }

        return result.empty() ? "NONE" : result;
    }

    inline std::string section_flags_to_string(DWORD characteristics)
    {
        std::string result;

        struct flag_entry
        {
            DWORD flag;
            const char* name;
        };

        static const flag_entry flags[] = {
            {IMAGE_SCN_CNT_CODE, "CODE"},
            {IMAGE_SCN_CNT_INITIALIZED_DATA, "INITIALIZED_DATA"},
            {IMAGE_SCN_CNT_UNINITIALIZED_DATA, "UNINITIALIZED_DATA"},
            {IMAGE_SCN_MEM_EXECUTE, "EXECUTE"},
            {IMAGE_SCN_MEM_READ, "READ"},
            {IMAGE_SCN_MEM_WRITE, "WRITE"},
            {IMAGE_SCN_MEM_SHARED, "SHARED"},
            {IMAGE_SCN_MEM_NOT_PAGED, "NOT_PAGED"},
            {IMAGE_SCN_MEM_NOT_CACHED, "NOT_CACHED"},
            {IMAGE_SCN_MEM_DISCARDABLE, "DISCARDABLE"},
            {IMAGE_SCN_LNK_NRELOC_OVFL, "NRELOC_OVFL"},
        };

        for (const auto& entry : flags) {
            if (characteristics & entry.flag) {
                if (!result.empty()) {
                    result += " | ";
                }
                result += entry.name;
            }
        }

        return result.empty() ? "NONE" : result;
    }

    inline std::string dll_characteristics_to_string(WORD characteristics)
    {
        std::string result;

        struct flag_entry
        {
            WORD flag;
            const char* name;
        };

        static const flag_entry flags[] = {
            {IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA"},
            {IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "DYNAMIC_BASE"},
            {IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "FORCE_INTEGRITY"},
            {IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "NX_COMPAT"},
            {IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "NO_ISOLATION"},
            {IMAGE_DLLCHARACTERISTICS_NO_SEH, "NO_SEH"},
            {IMAGE_DLLCHARACTERISTICS_NO_BIND, "NO_BIND"},
            {IMAGE_DLLCHARACTERISTICS_APPCONTAINER, "APPCONTAINER"},
            {IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "WDM_DRIVER"},
            {IMAGE_DLLCHARACTERISTICS_GUARD_CF, "GUARD_CF"},
            {IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TERMINAL_SERVER_AWARE"},
        };

        for (const auto& entry : flags) {
            if (characteristics & entry.flag) {
                if (!result.empty()) {
                    result += " | ";
                }
                result += entry.name;
            }
        }

        return result.empty() ? "NONE" : result;
    }

    inline std::string data_directory_name(DWORD index)
    {
        static const char* names[] = {
            "Export Table",      "Import Table",       "Resource Table",    "Exception Table",
            "Certificate Table", "Base Relocation",   "Debug",             "Architecture",
            "Global Ptr",        "TLS Table",         "Load Config",       "Bound Import",
            "IAT",               "Delay Import",      "CLR Runtime",       "Reserved",
        };

        if (index < _countof(names)) {
            return names[index];
        }

        return "Unknown";
    }

    inline std::string relocation_type_to_string(BYTE type)
    {
        switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE: return "ABSOLUTE";
            case IMAGE_REL_BASED_HIGH: return "HIGH";
            case IMAGE_REL_BASED_LOW: return "LOW";
            case IMAGE_REL_BASED_HIGHLOW: return "HIGHLOW";
            case IMAGE_REL_BASED_HIGHADJ: return "HIGHADJ";
            case IMAGE_REL_BASED_DIR64: return "DIR64";
            default: {
                std::ostringstream out;
                out << "UNKNOWN(" << static_cast<int>(type) << ")";
                return out.str();
            }
        }
    }

    inline std::string debug_type_to_string(DWORD type)
    {
        switch (type) {
            case IMAGE_DEBUG_TYPE_UNKNOWN: return "Unknown";
            case IMAGE_DEBUG_TYPE_COFF: return "COFF";
            case IMAGE_DEBUG_TYPE_CODEVIEW: return "CodeView";
            case IMAGE_DEBUG_TYPE_FPO: return "FPO";
            case IMAGE_DEBUG_TYPE_MISC: return "Misc";
            case IMAGE_DEBUG_TYPE_EXCEPTION: return "Exception";
            case IMAGE_DEBUG_TYPE_FIXUP: return "Fixup";
            case IMAGE_DEBUG_TYPE_BORLAND: return "Borland";
            case IMAGE_DEBUG_TYPE_REPRO: return "Reproducible";
            case IMAGE_DEBUG_TYPE_POGO: return "POGO";
            case IMAGE_DEBUG_TYPE_ILTCG: return "ILTCG";
            case IMAGE_DEBUG_TYPE_MPX: return "MPX";
            case 17: return "SPGO";
            case 19: return "PDBChecksum";
            case 21: return "EX_DLLCHARACTERISTICS";
            default: {
                std::ostringstream out;
                out << "Unknown (" << type << ")";
                return out.str();
            }
        }
    }

    inline std::string resource_type_to_string(DWORD id)
    {
        switch (id) {
            case 1: return "CURSOR";
            case 2: return "BITMAP";
            case 3: return "ICON";
            case 4: return "MENU";
            case 5: return "DIALOG";
            case 6: return "STRING";
            case 7: return "FONTDIR";
            case 8: return "FONT";
            case 9: return "ACCELERATOR";
            case 10: return "RCDATA";
            case 11: return "MESSAGETABLE";
            case 12: return "GROUP_CURSOR";
            case 14: return "GROUP_ICON";
            case 16: return "VERSION";
            case 17: return "DLGINCLUDE";
            case 19: return "PLUGPLAY";
            case 20: return "VXD";
            case 21: return "ANICURSOR";
            case 22: return "ANIICON";
            case 23: return "HTML";
            case 24: return "MANIFEST";
            default: {
                std::ostringstream out;
                out << "Custom (" << id << ")";
                return out.str();
            }
        }
    }

    inline std::string guard_flags_to_string(DWORD flags)
    {
        std::string result;

        struct flag_entry
        {
            DWORD flag;
            const char* name;
        };

        static const flag_entry entries[] = {
            {IMAGE_GUARD_CF_INSTRUMENTED, "CF_INSTRUMENTED"},
            {IMAGE_GUARD_CFW_INSTRUMENTED, "CFW_INSTRUMENTED"},
            {IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, "CF_FUNCTION_TABLE_PRESENT"},
            {IMAGE_GUARD_SECURITY_COOKIE_UNUSED, "SECURITY_COOKIE_UNUSED"},
            {IMAGE_GUARD_PROTECT_DELAYLOAD_IAT, "PROTECT_DELAYLOAD_IAT"},
            {IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION, "DELAYLOAD_IAT_IN_OWN_SECTION"},
            {IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT, "CF_EXPORT_SUPPRESSION"},
            {IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION, "CF_ENABLE_EXPORT_SUPPRESSION"},
            {IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT, "CF_LONGJUMP_TABLE_PRESENT"},
            {IMAGE_GUARD_RF_INSTRUMENTED, "RF_INSTRUMENTED"},
            {IMAGE_GUARD_RF_ENABLE, "RF_ENABLE"},
            {IMAGE_GUARD_RF_STRICT, "RF_STRICT"},
            {IMAGE_GUARD_RETPOLINE_PRESENT, "RETPOLINE_PRESENT"},
        };

        for (const auto& entry : entries) {
            if (flags & entry.flag) {
                if (!result.empty()) {
                    result += " | ";
                }
                result += entry.name;
            }
        }

        return result.empty() ? "NONE" : result;
    }
}
