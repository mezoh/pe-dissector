#include "import_table.hpp"

namespace analysis
{
    import_table::import_table(const pe::pe_file& file)
        : m_file(file)
    {
    }

    bool import_table::parse()
    {
        m_modules.clear();

        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)) {
            return true;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        auto* base = m_file.rva_to_pointer(dir->VirtualAddress);

        if (!base) {
            m_last_error = "failed to resolve import directory RVA";
            return false;
        }

        auto* descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(const_cast<BYTE*>(base));
        const auto* dir_end = base + dir->Size;

        while (reinterpret_cast<const BYTE*>(descriptor + 1) <= dir_end && descriptor->Name != 0) {
            auto* name_ptr = reinterpret_cast<const char*>(m_file.rva_to_pointer(descriptor->Name));
            if (!name_ptr) {
                break;
            }

            imported_module mod;
            mod.name = name_ptr;

            const DWORD thunk_rva = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk
                                                                   : descriptor->FirstThunk;

            auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(m_file.rva_to_pointer(thunk_rva));
            if (!thunk) {
                ++descriptor;
                continue;
            }

            while (m_file.is_rva_valid(static_cast<DWORD>(
                       reinterpret_cast<const BYTE*>(thunk) - m_file.raw_data()), sizeof(IMAGE_THUNK_DATA64)) &&
                   thunk->u1.AddressOfData != 0) {
                imported_function func = {};

                if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                    func.is_ordinal = true;
                    func.ordinal = static_cast<WORD>(IMAGE_ORDINAL64(thunk->u1.Ordinal));
                }
                else {
                    auto* by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        m_file.rva_to_pointer(static_cast<DWORD>(thunk->u1.AddressOfData)));

                    if (by_name) {
                        func.name = reinterpret_cast<const char*>(by_name->Name);
                        func.hint = by_name->Hint;
                    }

                    func.is_ordinal = false;
                }

                mod.functions.push_back(func);
                ++thunk;
            }

            m_modules.push_back(std::move(mod));
            ++descriptor;
        }

        return true;
    }

    std::size_t import_table::total_function_count() const
    {
        std::size_t count = 0;
        for (const auto& mod : m_modules) {
            count += mod.functions.size();
        }
        return count;
    }
}
