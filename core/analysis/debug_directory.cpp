#include "debug_directory.hpp"
#include <core/utils/utils.hpp>

namespace analysis
{
    namespace
    {
        constexpr DWORD RSDS_SIGNATURE = 0x53445352;

        struct cv_info_pdb70
        {
            DWORD signature;
            BYTE guid[16];
            DWORD age;
            char pdb_file_name[1];
        };
    }

    debug_directory::debug_directory(const pe::pe_file& file)
        : m_file(file)
    {
    }

    bool debug_directory::parse()
    {
        m_entries.clear();

        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)) {
            return true;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_DEBUG);
        auto* debug_dir = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
            m_file.rva_to_pointer(dir->VirtualAddress));

        if (!debug_dir) {
            m_last_error = "failed to resolve debug directory RVA";
            return false;
        }

        DWORD entry_count = dir->Size / sizeof(IMAGE_DEBUG_DIRECTORY);

        if (!m_file.is_rva_valid(dir->VirtualAddress, entry_count * sizeof(IMAGE_DEBUG_DIRECTORY))) {
            m_last_error = "debug directory extends beyond file";
            return false;
        }

        for (DWORD i = 0; i < entry_count; ++i) {
            const auto& raw = debug_dir[i];

            debug_entry entry = {};
            entry.type = raw.Type;
            entry.timestamp = raw.TimeDateStamp;
            entry.major_version = raw.MajorVersion;
            entry.minor_version = raw.MinorVersion;
            entry.data_rva = raw.AddressOfRawData;
            entry.data_size = raw.SizeOfData;
            entry.raw_data_offset = raw.PointerToRawData;
            entry.has_codeview = false;

            if (raw.Type == IMAGE_DEBUG_TYPE_CODEVIEW && raw.PointerToRawData > 0 && raw.SizeOfData > 0) {
                if (m_file.is_offset_valid(raw.PointerToRawData, raw.SizeOfData)) {
                    const BYTE* data = m_file.raw_data() + raw.PointerToRawData;
                    parse_codeview(entry, data, raw.SizeOfData);
                }
            }

            m_entries.push_back(std::move(entry));
        }

        return true;
    }

    bool debug_directory::parse_codeview(debug_entry& entry, const BYTE* data, DWORD size)
    {
        if (size < sizeof(cv_info_pdb70)) {
            return false;
        }

        auto* cv = reinterpret_cast<const cv_info_pdb70*>(data);

        if (cv->signature != RSDS_SIGNATURE) {
            return false;
        }

        entry.has_codeview = true;
        entry.codeview.guid = utils::format_guid(cv->guid);
        entry.codeview.age = cv->age;

        const std::size_t name_offset = offsetof(cv_info_pdb70, pdb_file_name);
        if (name_offset < size) {
            entry.codeview.pdb_path = std::string(cv->pdb_file_name, size - name_offset);
            const auto null_pos = entry.codeview.pdb_path.find('\0');
            if (null_pos != std::string::npos) {
                entry.codeview.pdb_path.resize(null_pos);
            }
        }

        return true;
    }
}
