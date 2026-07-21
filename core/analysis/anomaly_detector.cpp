#include "anomaly_detector.hpp"
#include <core/pe/pe_common.hpp>

#include <algorithm>
#include <cstring>
#include <set>

namespace analysis
{
    namespace
    {
        const std::set<std::string> known_section_names = {
            ".text", ".rdata", ".data", ".bss", ".rsrc", ".reloc", ".pdata",
            ".idata", ".edata", ".tls", ".CRT", ".gfids", ".00cfg",
            ".debug", ".didat", ".xdata", ".retplne", ".voltbl",
        };

        const std::set<std::string> packer_section_names = {
            "UPX0",  "UPX1",  "UPX2",  ".UPX",  ".aspack", ".adata",
            ".nsp0", ".nsp1", ".nsp2", "nsp0",   "nsp1",    "nsp2",
            ".MPRESS1", ".MPRESS2", ".perplex", ".packed",
            "MEW",   ".yP",   ".petite", ".spack", ".RLPack",
            ".themida", ".vmp0", ".vmp1", ".vmp2", "VProtect",
        };
    }

    anomaly_detector::anomaly_detector(const pe::pe_file& file)
        : m_file(file)
    {
    }

    void anomaly_detector::run()
    {
        m_anomalies.clear();

        if (!m_file.is_valid()) {
            return;
        }

        check_entry_point();
        check_section_names();
        check_section_permissions();
        check_section_sizes();
        check_import_count();
        check_tls_callbacks();
        check_data_directories();
        check_header_values();
    }

    void anomaly_detector::check_entry_point()
    {
        const DWORD entry_rva = static_cast<DWORD>(m_file.optional_header()->AddressOfEntryPoint);

        if (entry_rva == 0) {
            add_anomaly(anomaly_severity::info, "entry_point", "entry point is zero (may be a DLL or resource-only PE)");
            return;
        }

        auto* section = m_file.get_section_by_rva(entry_rva);

        if (!section) {
            add_anomaly(anomaly_severity::suspicious, "entry_point", "entry point is outside any section");
            return;
        }

        if (!(section->Characteristics & IMAGE_SCN_CNT_CODE)) {
            std::string name = m_file.section_name_string(section);
            add_anomaly(anomaly_severity::suspicious, "entry_point",
                        "entry point is in non-code section '" + name + "'");
        }

        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            std::string name = m_file.section_name_string(section);
            add_anomaly(anomaly_severity::suspicious, "entry_point",
                        "entry point is in non-executable section '" + name + "'");
        }

        auto* text = m_file.get_section_by_name(".text");
        if (text && section != text) {
            std::string name = m_file.section_name_string(section);
            add_anomaly(anomaly_severity::warning, "entry_point",
                        "entry point is in '" + name + "' rather than '.text'");
        }
    }

    void anomaly_detector::check_section_names()
    {
        for (DWORD i = 0; i < m_file.number_of_sections(); ++i) {
            auto* section = m_file.get_section(i);
            std::string name = m_file.section_name_string(section);

            if (packer_section_names.count(name)) {
                add_anomaly(anomaly_severity::suspicious, "packer",
                            "section '" + name + "' is associated with a known packer");
            }
            else if (!known_section_names.count(name) && !name.empty()) {
                bool all_printable = true;
                for (char ch : name) {
                    if (ch != '\0' && (ch < 0x20 || ch > 0x7E)) {
                        all_printable = false;
                        break;
                    }
                }

                if (!all_printable) {
                    add_anomaly(anomaly_severity::suspicious, "section_name",
                                "section " + std::to_string(i) + " has non-printable characters in name");
                }
                else {
                    add_anomaly(anomaly_severity::info, "section_name",
                                "non-standard section name '" + name + "'");
                }
            }
        }
    }

    void anomaly_detector::check_section_permissions()
    {
        for (DWORD i = 0; i < m_file.number_of_sections(); ++i) {
            auto* section = m_file.get_section(i);
            std::string name = m_file.section_name_string(section);
            const DWORD chars = section->Characteristics;

            const bool writable = (chars & IMAGE_SCN_MEM_WRITE) != 0;
            const bool executable = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;

            if (writable && executable) {
                add_anomaly(anomaly_severity::suspicious, "permissions",
                            "section '" + name + "' is both writable and executable (W+X)");
            }
        }
    }

    void anomaly_detector::check_section_sizes()
    {
        for (DWORD i = 0; i < m_file.number_of_sections(); ++i) {
            auto* section = m_file.get_section(i);
            std::string name = m_file.section_name_string(section);

            const DWORD virtual_size = section->Misc.VirtualSize;
            const DWORD raw_size = section->SizeOfRawData;

            if (raw_size > 0 && virtual_size > raw_size * 10) {
                add_anomaly(anomaly_severity::suspicious, "packing",
                            "section '" + name + "' virtual size is " +
                                std::to_string(virtual_size / raw_size) +
                                "x larger than raw size (possible unpacking stub)");
            }

            if (virtual_size > 0 && raw_size == 0) {
                if (!(section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)) {
                    add_anomaly(anomaly_severity::warning, "section_size",
                                "section '" + name +
                                    "' has zero raw data but non-zero virtual size without BSS flag");
                }
            }

            if (section->Characteristics & IMAGE_SCN_CNT_CODE && raw_size == 0 && virtual_size == 0) {
                add_anomaly(anomaly_severity::warning, "section_size",
                            "code section '" + name + "' is empty");
            }
        }
    }

    void anomaly_detector::check_import_count()
    {
        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)) {
            const bool is_dll = (m_file.file_header()->Characteristics & IMAGE_FILE_DLL) != 0;
            if (!is_dll) {
                add_anomaly(anomaly_severity::suspicious, "imports",
                            "no import directory (possible manual import resolution or static linking)");
            }
            return;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        auto* base = m_file.rva_to_pointer(dir->VirtualAddress);

        if (!base) {
            return;
        }

        auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base);
        const auto* dir_end = base + dir->Size;

        DWORD module_count = 0;
        while (reinterpret_cast<const BYTE*>(descriptor + 1) <= dir_end && descriptor->Name != 0) {
            ++module_count;
            ++descriptor;
        }

        if (module_count <= 1) {
            add_anomaly(anomaly_severity::warning, "imports",
                        "very few imported modules (" + std::to_string(module_count) +
                            ") — possible manual import resolution");
        }
    }

    void anomaly_detector::check_tls_callbacks()
    {
        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_TLS)) {
            return;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_TLS);
        auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(m_file.rva_to_pointer(dir->VirtualAddress));

        if (!tls || !tls->AddressOfCallBacks) {
            return;
        }

        const ULONGLONG image_base = m_file.optional_header()->ImageBase;
        const DWORD callbacks_rva = static_cast<DWORD>(tls->AddressOfCallBacks - image_base);
        auto* callbacks = reinterpret_cast<const ULONGLONG*>(m_file.rva_to_pointer(callbacks_rva));

        if (callbacks) {
            DWORD count = 0;
            while (m_file.is_offset_valid(
                       static_cast<DWORD>(reinterpret_cast<const BYTE*>(&callbacks[count]) - m_file.raw_data()),
                       sizeof(ULONGLONG)) &&
                   callbacks[count] != 0) {
                ++count;
            }

            add_anomaly(anomaly_severity::warning, "tls",
                        std::to_string(count) +
                            " TLS callback(s) detected (commonly used for anti-debug or early initialization)");
        }
    }

    void anomaly_detector::check_data_directories()
    {
        const DWORD num_dirs = m_file.optional_header()->NumberOfRvaAndSizes;

        if (num_dirs != IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
            add_anomaly(anomaly_severity::warning, "data_directories",
                        "non-standard number of data directories: " + std::to_string(num_dirs) +
                            " (expected " + std::to_string(IMAGE_NUMBEROF_DIRECTORY_ENTRIES) + ")");
        }

        if (m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)) {
            add_anomaly(anomaly_severity::info, "dotnet", ".NET CLR runtime header present");
        }
    }

    void anomaly_detector::check_header_values()
    {
        auto* optional = m_file.optional_header();

        if (optional->SizeOfHeaders > optional->SizeOfImage) {
            add_anomaly(anomaly_severity::suspicious, "headers",
                        "SizeOfHeaders exceeds SizeOfImage");
        }

        if (optional->FileAlignment == 0 || (optional->FileAlignment & (optional->FileAlignment - 1)) != 0) {
            add_anomaly(anomaly_severity::suspicious, "alignment",
                        "FileAlignment is not a power of 2");
        }

        if (optional->SectionAlignment == 0 || (optional->SectionAlignment & (optional->SectionAlignment - 1)) != 0) {
            add_anomaly(anomaly_severity::suspicious, "alignment",
                        "SectionAlignment is not a power of 2");
        }

        if (optional->SizeOfImage == 0) {
            add_anomaly(anomaly_severity::suspicious, "headers", "SizeOfImage is zero");
        }

        const DWORD checksum = optional->CheckSum;
        if (checksum == 0) {
            add_anomaly(anomaly_severity::info, "checksum", "PE checksum is zero (not verified by loader for most EXEs)");
        }
    }

    void anomaly_detector::add_anomaly(anomaly_severity severity, const std::string& category,
                                        const std::string& description)
    {
        anomaly a;
        a.severity = severity;
        a.category = category;
        a.description = description;
        m_anomalies.push_back(std::move(a));
    }
}
