#include "pe_file.hpp"
#include <core/utils/utils.hpp>

#include <cstring>

namespace pe
{
    pe_file::pe_file()
        : m_valid(false),
          m_is_64bit(false),
          m_dos_header(nullptr),
          m_nt_headers(nullptr),
          m_file_header(nullptr),
          m_optional_header(nullptr)
    {
    }

    pe_file::~pe_file()
    {
    }

    bool pe_file::load_from_file(const std::string& path)
    {
        m_file_path = path;

        if (!utils::load_file(path, m_buffer)) {
            set_last_error("failed to read file: " + path);
            return false;
        }

        return parse();
    }

    bool pe_file::load_from_buffer(const BYTE* data, std::size_t size)
    {
        if (!data || size == 0) {
            set_last_error("invalid buffer");
            return false;
        }

        m_buffer.assign(data, data + size);
        m_file_path = "<buffer>";

        return parse();
    }

    bool pe_file::parse()
    {
        m_valid = false;

        if (m_buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
            set_last_error("file too small for DOS header");
            return false;
        }

        m_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_buffer.data());

        if (m_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            set_last_error("invalid DOS signature (expected MZ)");
            return false;
        }

        const DWORD pe_offset = m_dos_header->e_lfanew;
        if (pe_offset + sizeof(IMAGE_NT_HEADERS64) > m_buffer.size()) {
            set_last_error("PE header offset extends beyond file");
            return false;
        }

        m_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_buffer.data() + pe_offset);

        if (m_nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            set_last_error("invalid PE signature (expected PE\\0\\0)");
            return false;
        }

        m_file_header = &m_nt_headers->FileHeader;
        const WORD magic = m_nt_headers->OptionalHeader.Magic;

        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            m_is_64bit = true;
            m_optional_header = &m_nt_headers->OptionalHeader;
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            set_last_error("PE32 (32-bit) files are not supported — this tool targets PE32+ (64-bit) only");
            return false;
        }
        else {
            set_last_error("unrecognized optional header magic");
            return false;
        }

        const DWORD sections_offset = pe_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                                      m_file_header->SizeOfOptionalHeader;

        const std::size_t sections_end = sections_offset +
                                         (m_file_header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

        if (sections_end > m_buffer.size()) {
            set_last_error("section headers extend beyond file");
            return false;
        }

        m_valid = true;
        return true;
    }

    DWORD pe_file::number_of_sections() const
    {
        return m_file_header ? m_file_header->NumberOfSections : 0;
    }

    PIMAGE_SECTION_HEADER pe_file::get_section(DWORD index) const
    {
        if (!m_valid || index >= number_of_sections()) {
            return nullptr;
        }

        const DWORD pe_offset = m_dos_header->e_lfanew;
        const DWORD sections_offset = pe_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                                      m_file_header->SizeOfOptionalHeader;

        auto* sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(m_buffer.data() + sections_offset);
        return &sections[index];
    }

    PIMAGE_SECTION_HEADER pe_file::get_section_by_name(const char* name) const
    {
        if (!m_valid || !name) {
            return nullptr;
        }

        for (DWORD i = 0; i < number_of_sections(); ++i) {
            auto* section = get_section(i);
            if (std::strncmp(reinterpret_cast<const char*>(section->Name), name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
                return section;
            }
        }

        return nullptr;
    }

    PIMAGE_SECTION_HEADER pe_file::get_section_by_rva(DWORD rva) const
    {
        if (!m_valid) {
            return nullptr;
        }

        for (DWORD i = 0; i < number_of_sections(); ++i) {
            auto* section = get_section(i);
            const DWORD section_start = section->VirtualAddress;
            const DWORD section_size = section->Misc.VirtualSize;

            if (rva >= section_start && rva < section_start + section_size) {
                return section;
            }
        }

        return nullptr;
    }

    std::vector<PIMAGE_SECTION_HEADER> pe_file::get_all_sections() const
    {
        std::vector<PIMAGE_SECTION_HEADER> sections;

        for (DWORD i = 0; i < number_of_sections(); ++i) {
            sections.push_back(get_section(i));
        }

        return sections;
    }

    PIMAGE_DATA_DIRECTORY pe_file::get_data_directory(DWORD index) const
    {
        if (!m_valid || !m_optional_header) {
            return nullptr;
        }

        if (index >= m_optional_header->NumberOfRvaAndSizes) {
            return nullptr;
        }

        return &m_optional_header->DataDirectory[index];
    }

    bool pe_file::has_data_directory(DWORD index) const
    {
        auto* dir = get_data_directory(index);
        return dir && dir->VirtualAddress != 0 && dir->Size != 0;
    }

    DWORD pe_file::rva_to_offset(DWORD rva) const
    {
        if (!m_valid) {
            return 0;
        }

        auto* section = get_section_by_rva(rva);
        if (!section) {
            return rva;
        }

        return rva - section->VirtualAddress + section->PointerToRawData;
    }

    const BYTE* pe_file::rva_to_pointer(DWORD rva) const
    {
        const DWORD offset = rva_to_offset(rva);
        if (offset >= m_buffer.size()) {
            return nullptr;
        }

        return m_buffer.data() + offset;
    }

    bool pe_file::is_rva_valid(DWORD rva, DWORD size) const
    {
        const DWORD offset = rva_to_offset(rva);
        return is_offset_valid(offset, size);
    }

    bool pe_file::is_offset_valid(DWORD offset, DWORD size) const
    {
        if (static_cast<std::size_t>(offset) >= m_buffer.size()) {
            return false;
        }

        if (size > 0 && (static_cast<std::size_t>(offset) + static_cast<std::size_t>(size)) > m_buffer.size()) {
            return false;
        }

        return true;
    }

    std::string pe_file::section_name_string(PIMAGE_SECTION_HEADER section) const
    {
        if (!section) {
            return "";
        }

        char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
        std::memcpy(name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
        return std::string(name);
    }

    void pe_file::set_last_error(const std::string& message)
    {
        m_last_error = message;
    }
}
