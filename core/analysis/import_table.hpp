#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    struct imported_function
    {
        std::string name;
        WORD hint;
        WORD ordinal;
        bool is_ordinal;
    };

    struct imported_module
    {
        std::string name;
        std::vector<imported_function> functions;
    };

    class import_table
    {
    public:
        explicit import_table(const pe::pe_file& file);

        bool parse();

        const std::vector<imported_module>& get_modules() const { return m_modules; }
        std::size_t total_function_count() const;

        const std::string& last_error() const { return m_last_error; }

    private:
        const pe::pe_file& m_file;
        std::vector<imported_module> m_modules;
        std::string m_last_error;
    };
}
