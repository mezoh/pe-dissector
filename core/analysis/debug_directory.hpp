#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    struct codeview_info
    {
        std::string guid;
        DWORD age;
        std::string pdb_path;
    };

    struct debug_entry
    {
        DWORD type;
        DWORD timestamp;
        WORD major_version;
        WORD minor_version;
        DWORD data_rva;
        DWORD data_size;
        DWORD raw_data_offset;

        bool has_codeview;
        codeview_info codeview;
    };

    class debug_directory
    {
    public:
        explicit debug_directory(const pe::pe_file& file);

        bool parse();

        const std::vector<debug_entry>& get_entries() const { return m_entries; }

        const std::string& last_error() const { return m_last_error; }

    private:
        bool parse_codeview(debug_entry& entry, const BYTE* data, DWORD size);

        const pe::pe_file& m_file;
        std::vector<debug_entry> m_entries;
        std::string m_last_error;
    };
}
