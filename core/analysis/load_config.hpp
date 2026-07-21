#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    struct load_config_info
    {
        DWORD size;
        DWORD timestamp;
        WORD major_version;
        WORD minor_version;
        ULONGLONG security_cookie;
        ULONGLONG se_handler_table;
        ULONGLONG se_handler_count;
        ULONGLONG guard_cf_check_function_pointer;
        ULONGLONG guard_cf_dispatch_function_pointer;
        ULONGLONG guard_cf_function_table;
        ULONGLONG guard_cf_function_count;
        DWORD guard_flags;

        std::vector<DWORD> cfg_function_rvas;
    };

    class load_config
    {
    public:
        explicit load_config(const pe::pe_file& file);

        bool parse();

        bool has_load_config() const { return m_has_config; }
        const load_config_info& get_info() const { return m_info; }

        const std::string& last_error() const { return m_last_error; }

    private:
        const pe::pe_file& m_file;
        load_config_info m_info;
        bool m_has_config;
        std::string m_last_error;
    };
}
