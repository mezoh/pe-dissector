#include "export_table.hpp"

namespace analysis
{
    export_table::export_table(const pe::pe_file& file)
        : m_file(file),
          m_ordinal_base(0)
    {
    }

    bool export_table::parse()
    {
        m_functions.clear();

        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)) {
            return true;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);
        auto* export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(m_file.rva_to_pointer(dir->VirtualAddress));

        if (!export_dir) {
            m_last_error = "failed to resolve export directory RVA";
            return false;
        }

        if (export_dir->Name) {
            auto* name_ptr = reinterpret_cast<const char*>(m_file.rva_to_pointer(export_dir->Name));
            if (name_ptr) {
                m_dll_name = name_ptr;
            }
        }

        m_ordinal_base = export_dir->Base;

        auto* function_rvas = reinterpret_cast<const DWORD*>(
            m_file.rva_to_pointer(export_dir->AddressOfFunctions));

        auto* name_rvas = reinterpret_cast<const DWORD*>(
            m_file.rva_to_pointer(export_dir->AddressOfNames));

        auto* ordinals = reinterpret_cast<const WORD*>(
            m_file.rva_to_pointer(export_dir->AddressOfNameOrdinals));

        if (!function_rvas) {
            m_last_error = "failed to resolve function address table";
            return false;
        }

        const DWORD functions_rva = export_dir->AddressOfFunctions;
        if (!m_file.is_rva_valid(functions_rva, export_dir->NumberOfFunctions * sizeof(DWORD))) {
            m_last_error = "function address table extends beyond file";
            return false;
        }

        if (name_rvas && !m_file.is_rva_valid(export_dir->AddressOfNames,
                                               export_dir->NumberOfNames * sizeof(DWORD))) {
            name_rvas = nullptr;
        }

        if (ordinals && !m_file.is_rva_valid(export_dir->AddressOfNameOrdinals,
                                              export_dir->NumberOfNames * sizeof(WORD))) {
            ordinals = nullptr;
        }

        const DWORD export_start = dir->VirtualAddress;
        const DWORD export_end = export_start + dir->Size;

        for (DWORD i = 0; i < export_dir->NumberOfFunctions; ++i) {
            if (function_rvas[i] == 0) {
                continue;
            }

            exported_function func = {};
            func.ordinal = m_ordinal_base + i;
            func.rva = function_rvas[i];

            if (func.rva >= export_start && func.rva < export_end) {
                auto* fwd_name = reinterpret_cast<const char*>(m_file.rva_to_pointer(func.rva));
                if (fwd_name && m_file.is_rva_valid(func.rva, 1)) {
                    func.forwarded_name = fwd_name;
                    func.is_forwarded = true;
                }
            }

            if (name_rvas && ordinals) {
                for (DWORD j = 0; j < export_dir->NumberOfNames; ++j) {
                    if (ordinals[j] == i) {
                        if (m_file.is_rva_valid(name_rvas[j], 1)) {
                            auto* name_ptr = reinterpret_cast<const char*>(m_file.rva_to_pointer(name_rvas[j]));
                            if (name_ptr) {
                                func.name = name_ptr;
                            }
                        }
                        break;
                    }
                }
            }

            m_functions.push_back(std::move(func));
        }

        return true;
    }
}
