#include "resource_table.hpp"
#include <core/pe/pe_common.hpp>
#include <core/utils/utils.hpp>

namespace analysis
{
    resource_table::resource_table(const pe::pe_file& file)
        : m_file(file)
    {
    }

    bool resource_table::parse()
    {
        m_entries.clear();

        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)) {
            return true;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE);
        auto* resource_base = m_file.rva_to_pointer(dir->VirtualAddress);

        if (!resource_base) {
            m_last_error = "failed to resolve resource directory RVA";
            return false;
        }

        auto* root_dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(resource_base);
        parse_directory(resource_base, root_dir, 0, 0, "", 0, "");

        return true;
    }

    void resource_table::parse_directory(const BYTE* resource_base, const IMAGE_RESOURCE_DIRECTORY* dir,
                                         int level, DWORD type_id, const std::string& type_name,
                                         DWORD name_id, const std::string& name)
    {
        if (level > 3) {
            return;
        }

        auto* dir_data = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE);
        const DWORD resource_size = dir_data->Size;

        auto in_bounds = [&](const void* ptr, std::size_t size) -> bool {
            auto offset = static_cast<std::size_t>(reinterpret_cast<const BYTE*>(ptr) - resource_base);
            return (offset + size) <= resource_size;
        };

        if (!in_bounds(dir, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
            return;
        }

        const DWORD total_entries = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
        auto* entries = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
            reinterpret_cast<const BYTE*>(dir) + sizeof(IMAGE_RESOURCE_DIRECTORY));

        for (DWORD i = 0; i < total_entries; ++i) {
            if (!in_bounds(&entries[i], sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))) {
                break;
            }

            const auto& raw = entries[i];

            DWORD current_id = 0;
            std::string current_name;

            if (raw.NameIsString) {
                current_name = read_resource_string(resource_base, raw.NameOffset);
            }
            else {
                current_id = raw.Id;
            }

            if (raw.DataIsDirectory) {
                auto* sub_dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(
                    resource_base + raw.OffsetToDirectory);

                if (!in_bounds(sub_dir, sizeof(IMAGE_RESOURCE_DIRECTORY))) {
                    continue;
                }

                if (level == 0) {
                    std::string resolved_type = current_name.empty()
                                                    ? pe::resource_type_to_string(current_id)
                                                    : current_name;
                    parse_directory(resource_base, sub_dir, level + 1, current_id, resolved_type, 0, "");
                }
                else if (level == 1) {
                    parse_directory(resource_base, sub_dir, level + 1, type_id, type_name, current_id, current_name);
                }
            }
            else {
                auto* data_entry = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(
                    resource_base + raw.OffsetToData);

                if (!in_bounds(data_entry, sizeof(IMAGE_RESOURCE_DATA_ENTRY))) {
                    continue;
                }

                resource_entry entry = {};
                entry.type_id = type_id;
                entry.type_name = type_name;
                entry.name_id = (level >= 1) ? name_id : current_id;
                entry.name = (level >= 1) ? name : current_name;
                entry.language_id = current_id;
                entry.data_rva = data_entry->OffsetToData;
                entry.data_size = data_entry->Size;
                entry.code_page = data_entry->CodePage;

                m_entries.push_back(std::move(entry));
            }
        }
    }

    std::string resource_table::read_resource_string(const BYTE* resource_base, DWORD offset) const
    {
        auto* dir_data = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE);
        if (offset + sizeof(WORD) > dir_data->Size) {
            return "";
        }

        auto* str = reinterpret_cast<const IMAGE_RESOURCE_DIR_STRING_U*>(resource_base + offset);
        const std::size_t required = sizeof(WORD) + static_cast<std::size_t>(str->Length) * sizeof(wchar_t);

        if (offset + required > dir_data->Size) {
            return "";
        }

        return utils::wide_to_narrow(str->NameString, str->Length);
    }
}
