#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    struct resource_entry
    {
        std::string type_name;
        DWORD type_id;
        std::string name;
        DWORD name_id;
        DWORD language_id;
        DWORD data_rva;
        DWORD data_size;
        DWORD code_page;
    };

    class resource_table
    {
    public:
        explicit resource_table(const pe::pe_file& file);

        bool parse();

        const std::vector<resource_entry>& get_entries() const { return m_entries; }

        const std::string& last_error() const { return m_last_error; }

    private:
        void parse_directory(const BYTE* resource_base, const IMAGE_RESOURCE_DIRECTORY* dir,
                             int level, DWORD type_id, const std::string& type_name,
                             DWORD name_id, const std::string& name);

        std::string read_resource_string(const BYTE* resource_base, DWORD offset) const;

        const pe::pe_file& m_file;
        std::vector<resource_entry> m_entries;
        std::string m_last_error;
    };
}
