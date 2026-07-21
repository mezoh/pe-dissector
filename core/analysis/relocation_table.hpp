#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    struct relocation_entry
    {
        DWORD rva;
        BYTE type;
    };

    struct relocation_block
    {
        DWORD page_rva;
        DWORD block_size;
        std::vector<relocation_entry> entries;
    };

    class relocation_table
    {
    public:
        explicit relocation_table(const pe::pe_file& file);

        bool parse();

        const std::vector<relocation_block>& get_blocks() const { return m_blocks; }
        std::size_t total_entry_count() const;

        const std::string& last_error() const { return m_last_error; }

    private:
        const pe::pe_file& m_file;
        std::vector<relocation_block> m_blocks;
        std::string m_last_error;
    };
}
