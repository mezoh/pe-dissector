#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    struct certificate_entry
    {
        DWORD length;
        WORD revision;
        WORD certificate_type;
    };

    class signature_info
    {
    public:
        explicit signature_info(const pe::pe_file& file);

        bool parse();

        bool is_signed() const { return m_is_signed; }
        const std::vector<certificate_entry>& get_certificates() const { return m_certificates; }

        const std::string& last_error() const { return m_last_error; }

    private:
        const pe::pe_file& m_file;
        std::vector<certificate_entry> m_certificates;
        bool m_is_signed;
        std::string m_last_error;
    };
}
