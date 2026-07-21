#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace pe
{
    class pe_file
    {
    public:
        pe_file();
        ~pe_file();

        pe_file(const pe_file&) = delete;
        pe_file& operator=(const pe_file&) = delete;

        bool load_from_file(const std::string& path);
        bool load_from_buffer(const BYTE* data, std::size_t size);

        bool is_valid() const { return m_valid; }
        bool is_64bit() const { return m_is_64bit; }

        const BYTE* raw_data() const { return m_buffer.data(); }
        std::size_t raw_size() const { return m_buffer.size(); }

        PIMAGE_DOS_HEADER dos_header() const { return m_dos_header; }
        PIMAGE_NT_HEADERS64 nt_headers() const { return m_nt_headers; }
        PIMAGE_FILE_HEADER file_header() const { return m_file_header; }
        PIMAGE_OPTIONAL_HEADER64 optional_header() const { return m_optional_header; }

        DWORD number_of_sections() const;
        PIMAGE_SECTION_HEADER get_section(DWORD index) const;
        PIMAGE_SECTION_HEADER get_section_by_name(const char* name) const;
        PIMAGE_SECTION_HEADER get_section_by_rva(DWORD rva) const;
        std::vector<PIMAGE_SECTION_HEADER> get_all_sections() const;

        PIMAGE_DATA_DIRECTORY get_data_directory(DWORD index) const;
        bool has_data_directory(DWORD index) const;

        DWORD rva_to_offset(DWORD rva) const;
        const BYTE* rva_to_pointer(DWORD rva) const;

        bool is_rva_valid(DWORD rva, DWORD size = 0) const;
        bool is_offset_valid(DWORD offset, DWORD size = 0) const;

        std::string section_name_string(PIMAGE_SECTION_HEADER section) const;

        const std::string& file_path() const { return m_file_path; }
        const std::string& last_error() const { return m_last_error; }

    private:
        bool parse();
        void set_last_error(const std::string& message);

        std::vector<BYTE> m_buffer;
        std::string m_file_path;
        std::string m_last_error;
        bool m_valid;
        bool m_is_64bit;

        PIMAGE_DOS_HEADER m_dos_header;
        PIMAGE_NT_HEADERS64 m_nt_headers;
        PIMAGE_FILE_HEADER m_file_header;
        PIMAGE_OPTIONAL_HEADER64 m_optional_header;
    };
}
