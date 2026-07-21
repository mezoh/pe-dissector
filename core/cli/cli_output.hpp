#pragma once

#include <core/pe/pe_file.hpp>
#include <core/pe/pe_common.hpp>
#include <core/utils/utils.hpp>
#include <core/analysis/import_table.hpp>
#include <core/analysis/export_table.hpp>
#include <core/analysis/relocation_table.hpp>
#include <core/analysis/tls_directory.hpp>
#include <core/analysis/debug_directory.hpp>
#include <core/analysis/load_config.hpp>
#include <core/analysis/resource_table.hpp>
#include <core/analysis/signature_info.hpp>
#include <core/analysis/rich_header.hpp>
#include <core/analysis/anomaly_detector.hpp>

#include <cstdio>

namespace cli
{
    inline void print_separator(const char* title)
    {
        std::printf("\n================================================================================\n");
        std::printf("  %s\n", title);
        std::printf("================================================================================\n\n");
    }

    inline void print_field(const char* name, const std::string& value, int name_width = 36)
    {
        std::printf("  %-*s %s\n", name_width, name, value.c_str());
    }

    inline void print_field(const char* name, DWORD value, int name_width = 36)
    {
        std::printf("  %-*s %s (%u)\n", name_width, name, utils::format_hex(value).c_str(), value);
    }

    inline void print_field_64(const char* name, ULONGLONG value, int name_width = 36)
    {
        std::printf("  %-*s %s\n", name_width, name, utils::format_hex(value, 16).c_str());
    }

    inline void print_headers(const pe::pe_file& file)
    {
        print_separator("PE HEADERS");

        auto* dos = file.dos_header();
        auto* fh = file.file_header();
        auto* opt = file.optional_header();

        std::printf("  --- DOS Header ---\n");
        print_field("  Magic:", "MZ");
        print_field("  PE Header Offset:", static_cast<DWORD>(dos->e_lfanew));

        std::printf("\n  --- File Header ---\n");
        print_field("  Machine:", pe::machine_type_to_string(fh->Machine));
        print_field("  Number of Sections:", static_cast<DWORD>(fh->NumberOfSections));
        print_field("  Timestamp:", pe::timestamp_to_string(fh->TimeDateStamp));
        print_field("  Characteristics:", pe::characteristics_to_string(fh->Characteristics));

        std::printf("\n  --- Optional Header ---\n");
        print_field("  Magic:", "PE32+ (64-bit)");
        print_field("  Linker Version:",
                     std::to_string(opt->MajorLinkerVersion) + "." + std::to_string(opt->MinorLinkerVersion));
        print_field("  Entry Point:", static_cast<DWORD>(opt->AddressOfEntryPoint));
        print_field_64("  Image Base:", opt->ImageBase);
        print_field("  Section Alignment:", opt->SectionAlignment);
        print_field("  File Alignment:", opt->FileAlignment);
        print_field("  OS Version:",
                     std::to_string(opt->MajorOperatingSystemVersion) + "." +
                         std::to_string(opt->MinorOperatingSystemVersion));
        print_field("  Image Version:",
                     std::to_string(opt->MajorImageVersion) + "." + std::to_string(opt->MinorImageVersion));
        print_field("  Subsystem:", pe::subsystem_to_string(opt->Subsystem));
        print_field("  DLL Characteristics:", pe::dll_characteristics_to_string(opt->DllCharacteristics));
        print_field("  Size of Image:", opt->SizeOfImage);
        print_field("  Size of Headers:", opt->SizeOfHeaders);
        print_field("  Checksum:", opt->CheckSum);

        std::printf("\n  --- Data Directories ---\n");
        for (DWORD i = 0; i < opt->NumberOfRvaAndSizes && i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            auto* dir = file.get_data_directory(i);
            if (dir->VirtualAddress != 0 || dir->Size != 0) {
                std::printf("  %-24s RVA: %-12s Size: %s\n",
                            pe::data_directory_name(i).c_str(),
                            utils::format_hex(dir->VirtualAddress).c_str(),
                            utils::format_hex(dir->Size).c_str());
            }
        }
    }

    inline void print_sections(const pe::pe_file& file)
    {
        print_separator("SECTIONS");

        std::printf("  %-8s %-12s %-12s %-12s %-12s %s\n",
                     "Name", "VirtAddr", "VirtSize", "RawOffset", "RawSize", "Flags");
        std::printf("  %-8s %-12s %-12s %-12s %-12s %s\n",
                     "----", "--------", "--------", "---------", "-------", "-----");

        for (DWORD i = 0; i < file.number_of_sections(); ++i) {
            auto* section = file.get_section(i);
            std::string name = file.section_name_string(section);

            std::printf("  %-8s %-12s %-12s %-12s %-12s %s\n",
                         name.c_str(),
                         utils::format_hex(section->VirtualAddress).c_str(),
                         utils::format_hex(section->Misc.VirtualSize).c_str(),
                         utils::format_hex(section->PointerToRawData).c_str(),
                         utils::format_hex(section->SizeOfRawData).c_str(),
                         pe::section_flags_to_string(section->Characteristics).c_str());
        }
    }

    inline void print_imports(const analysis::import_table& imports)
    {
        print_separator("IMPORTS");

        const auto& modules = imports.get_modules();

        if (modules.empty()) {
            std::printf("  No imports found.\n");
            return;
        }

        std::printf("  %zu module(s), %zu function(s) total\n\n",
                     modules.size(), imports.total_function_count());

        for (const auto& mod : modules) {
            std::printf("  [%s] (%zu functions)\n", mod.name.c_str(), mod.functions.size());

            for (const auto& func : mod.functions) {
                if (func.is_ordinal) {
                    std::printf("    Ordinal #%u\n", func.ordinal);
                }
                else {
                    std::printf("    %s (hint: %u)\n", func.name.c_str(), func.hint);
                }
            }

            std::printf("\n");
        }
    }

    inline void print_exports(const analysis::export_table& exports)
    {
        print_separator("EXPORTS");

        const auto& functions = exports.get_functions();

        if (functions.empty()) {
            std::printf("  No exports found.\n");
            return;
        }

        if (!exports.dll_name().empty()) {
            print_field("DLL Name:", exports.dll_name());
            print_field("Ordinal Base:", exports.ordinal_base());
            std::printf("\n");
        }

        std::printf("  %-8s %-12s %-40s %s\n", "Ordinal", "RVA", "Name", "Forward");
        std::printf("  %-8s %-12s %-40s %s\n", "-------", "---", "----", "-------");

        for (const auto& func : functions) {
            std::printf("  %-8u %-12s %-40s %s\n",
                         func.ordinal,
                         utils::format_hex(func.rva).c_str(),
                         func.name.empty() ? "(by ordinal)" : func.name.c_str(),
                         func.is_forwarded ? func.forwarded_name.c_str() : "");
        }
    }

    inline void print_relocations(const analysis::relocation_table& relocs)
    {
        print_separator("RELOCATIONS");

        const auto& blocks = relocs.get_blocks();

        if (blocks.empty()) {
            std::printf("  No relocations found.\n");
            return;
        }

        std::printf("  %zu block(s), %zu relocation(s) total\n\n",
                     blocks.size(), relocs.total_entry_count());

        for (const auto& block : blocks) {
            std::printf("  Block at %s (%zu entries, %u bytes)\n",
                         utils::format_hex(block.page_rva).c_str(),
                         block.entries.size(),
                         block.block_size);

            for (const auto& entry : block.entries) {
                std::printf("    %s  %s\n",
                             utils::format_hex(entry.rva, 8).c_str(),
                             pe::relocation_type_to_string(entry.type).c_str());
            }

            std::printf("\n");
        }
    }

    inline void print_tls(const analysis::tls_directory& tls)
    {
        print_separator("TLS DIRECTORY");

        if (!tls.has_tls()) {
            std::printf("  No TLS directory found.\n");
            return;
        }

        const auto& info = tls.get_info();

        print_field_64("Raw Data Start:", info.raw_data_start);
        print_field_64("Raw Data End:", info.raw_data_end);
        print_field_64("Address of Index:", info.address_of_index);
        print_field_64("Address of Callbacks:", info.address_of_callbacks);
        print_field("Size of Zero Fill:", info.size_of_zero_fill);
        print_field("Characteristics:", info.characteristics);

        if (!info.callback_rvas.empty()) {
            std::printf("\n  TLS Callbacks (%zu):\n", info.callback_rvas.size());
            for (std::size_t i = 0; i < info.callback_rvas.size(); ++i) {
                std::printf("    [%zu] %s\n", i, utils::format_hex(info.callback_rvas[i], 16).c_str());
            }
        }
    }

    inline void print_debug(const analysis::debug_directory& debug)
    {
        print_separator("DEBUG DIRECTORY");

        const auto& entries = debug.get_entries();

        if (entries.empty()) {
            std::printf("  No debug entries found.\n");
            return;
        }

        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];

            std::printf("  Entry %zu:\n", i);
            print_field("  Type:", pe::debug_type_to_string(entry.type));
            print_field("  Timestamp:", pe::timestamp_to_string(entry.timestamp));
            print_field("  Version:",
                         std::to_string(entry.major_version) + "." + std::to_string(entry.minor_version));
            print_field("  Data RVA:", entry.data_rva);
            print_field("  Data Size:", entry.data_size);

            if (entry.has_codeview) {
                std::printf("\n  CodeView (PDB 7.0):\n");
                print_field("    GUID:", entry.codeview.guid);
                print_field("    Age:", static_cast<DWORD>(entry.codeview.age));
                print_field("    PDB Path:", entry.codeview.pdb_path);
            }

            std::printf("\n");
        }
    }

    inline void print_load_config(const analysis::load_config& config)
    {
        print_separator("LOAD CONFIGURATION");

        if (!config.has_load_config()) {
            std::printf("  No load configuration found.\n");
            return;
        }

        const auto& info = config.get_info();

        print_field("Size:", info.size);
        print_field("Timestamp:", pe::timestamp_to_string(info.timestamp));
        print_field("Version:",
                     std::to_string(info.major_version) + "." + std::to_string(info.minor_version));
        print_field_64("Security Cookie:", info.security_cookie);

        if (info.se_handler_table) {
            print_field_64("SEH Handler Table:", info.se_handler_table);
            print_field("SEH Handler Count:", static_cast<DWORD>(info.se_handler_count));
        }

        if (info.guard_cf_check_function_pointer || info.guard_cf_function_table) {
            std::printf("\n  --- Control Flow Guard ---\n");
            print_field_64("  CF Check Function Pointer:", info.guard_cf_check_function_pointer);
            print_field_64("  CF Dispatch Function Pointer:", info.guard_cf_dispatch_function_pointer);
            print_field_64("  CF Function Table:", info.guard_cf_function_table);
            print_field("  CF Function Count:", static_cast<DWORD>(info.guard_cf_function_count));
            print_field("  Guard Flags:", pe::guard_flags_to_string(info.guard_flags));

            if (!info.cfg_function_rvas.empty()) {
                const std::size_t display_count = (info.cfg_function_rvas.size() > 20) ? 20 : info.cfg_function_rvas.size();
                std::printf("\n  CFG Valid Targets (first %zu of %zu):\n",
                             display_count, info.cfg_function_rvas.size());

                for (std::size_t i = 0; i < display_count; ++i) {
                    std::printf("    %s\n", utils::format_hex(info.cfg_function_rvas[i], 8).c_str());
                }

                if (info.cfg_function_rvas.size() > 20) {
                    std::printf("    ... (%zu more)\n", info.cfg_function_rvas.size() - 20);
                }
            }
        }
    }

    inline void print_resources(const analysis::resource_table& resources)
    {
        print_separator("RESOURCES");

        const auto& entries = resources.get_entries();

        if (entries.empty()) {
            std::printf("  No resources found.\n");
            return;
        }

        std::printf("  %zu resource(s)\n\n", entries.size());
        std::printf("  %-16s %-16s %-10s %-12s %s\n", "Type", "Name/ID", "Language", "Size", "RVA");
        std::printf("  %-16s %-16s %-10s %-12s %s\n", "----", "-------", "--------", "----", "---");

        for (const auto& entry : entries) {
            std::string name_str = entry.name.empty()
                                       ? ("#" + std::to_string(entry.name_id))
                                       : entry.name;

            std::printf("  %-16s %-16s %-10u %-12s %s\n",
                         entry.type_name.c_str(),
                         name_str.c_str(),
                         entry.language_id,
                         utils::format_size(entry.data_size).c_str(),
                         utils::format_hex(entry.data_rva).c_str());
        }
    }

    inline void print_signature(const analysis::signature_info& sig)
    {
        print_separator("AUTHENTICODE SIGNATURE");

        if (!sig.is_signed()) {
            std::printf("  Not signed.\n");
            return;
        }

        const auto& certs = sig.get_certificates();
        std::printf("  %zu certificate(s) found\n\n", certs.size());

        for (std::size_t i = 0; i < certs.size(); ++i) {
            const auto& cert = certs[i];
            std::printf("  Certificate %zu:\n", i);
            print_field("  Length:", cert.length);
            print_field("  Revision:",
                         cert.revision == WIN_CERT_REVISION_1_0 ? "1.0" :
                         cert.revision == WIN_CERT_REVISION_2_0 ? "2.0" : "Unknown");
            print_field("  Type:",
                         cert.certificate_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA ? "PKCS#7 SignedData" :
                         cert.certificate_type == WIN_CERT_TYPE_X509 ? "X.509" : "Unknown");
            std::printf("\n");
        }
    }

    inline void print_rich_header(const analysis::rich_header& rich)
    {
        print_separator("RICH HEADER");

        if (!rich.has_rich_header()) {
            std::printf("  No Rich header found.\n");
            return;
        }

        const auto& info = rich.get_info();

        print_field("XOR Key:", info.xor_key);
        print_field("Checksum:", info.checksum);
        print_field("Checksum Match:",
                     info.xor_key == info.checksum ? "Yes" : "No");

        std::printf("\n  %-8s %-10s %-10s %s\n", "Product", "Build", "Count", "Tool");
        std::printf("  %-8s %-10s %-10s %s\n", "-------", "-----", "-----", "----");

        for (const auto& entry : info.entries) {
            std::printf("  %-8u %-10u %-10u %s\n",
                         entry.product_id,
                         entry.build_id,
                         entry.use_count,
                         analysis::rich_header::product_id_to_string(entry.product_id).c_str());
        }
    }

    inline void print_anomalies(const analysis::anomaly_detector& detector)
    {
        print_separator("ANOMALY SCAN");

        const auto& anomalies = detector.get_anomalies();

        if (anomalies.empty()) {
            std::printf("  No anomalies detected.\n");
            return;
        }

        std::printf("  %zu finding(s)\n\n", anomalies.size());

        for (const auto& a : anomalies) {
            const char* severity_str = "INFO";
            if (a.severity == analysis::anomaly_severity::warning) {
                severity_str = "WARN";
            }
            else if (a.severity == analysis::anomaly_severity::suspicious) {
                severity_str = "SUSP";
            }

            std::printf("  [%-4s] [%-16s] %s\n", severity_str, a.category.c_str(), a.description.c_str());
        }
    }
}
