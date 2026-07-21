#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    struct tls_info
    {
        ULONGLONG raw_data_start;
        ULONGLONG raw_data_end;
        ULONGLONG address_of_index;
        ULONGLONG address_of_callbacks;
        DWORD size_of_zero_fill;
        DWORD characteristics;
        std::vector<ULONGLONG> callback_rvas;
    };

    class tls_directory
    {
    public:
        explicit tls_directory(const pe::pe_file& file);

        bool parse();

        bool has_tls() const { return m_has_tls; }
        const tls_info& get_info() const { return m_info; }

        const std::string& last_error() const { return m_last_error; }

    private:
        const pe::pe_file& m_file;
        tls_info m_info;
        bool m_has_tls;
        std::string m_last_error;
    };
}
