#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    struct rich_entry
    {
        WORD build_id;
        WORD product_id;
        DWORD use_count;
    };

    struct rich_header_info
    {
        DWORD xor_key;
        DWORD checksum;
        std::vector<rich_entry> entries;
    };

    class rich_header
    {
    public:
        explicit rich_header(const pe::pe_file& file);

        bool parse();

        bool has_rich_header() const { return m_has_rich; }
        const rich_header_info& get_info() const { return m_info; }

        const std::string& last_error() const { return m_last_error; }

        static std::string product_id_to_string(WORD id);

    private:
        const pe::pe_file& m_file;
        rich_header_info m_info;
        bool m_has_rich;
        std::string m_last_error;
    };
}
