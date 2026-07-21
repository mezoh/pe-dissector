#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    struct exported_function
    {
        std::string name;
        DWORD ordinal;
        DWORD rva;
        std::string forwarded_name;
        bool is_forwarded;
    };

    class export_table
    {
    public:
        explicit export_table(const pe::pe_file& file);

        bool parse();

        const std::string& dll_name() const { return m_dll_name; }
        DWORD ordinal_base() const { return m_ordinal_base; }
        const std::vector<exported_function>& get_functions() const { return m_functions; }

        const std::string& last_error() const { return m_last_error; }

    private:
        const pe::pe_file& m_file;
        std::vector<exported_function> m_functions;
        std::string m_dll_name;
        DWORD m_ordinal_base;
        std::string m_last_error;
    };
}
