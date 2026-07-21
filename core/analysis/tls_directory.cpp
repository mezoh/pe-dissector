#include "tls_directory.hpp"

namespace analysis
{
    tls_directory::tls_directory(const pe::pe_file& file)
        : m_file(file),
          m_info{},
          m_has_tls(false)
    {
    }

    bool tls_directory::parse()
    {
        m_has_tls = false;
        m_info = {};

        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_TLS)) {
            return true;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_TLS);
        auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(m_file.rva_to_pointer(dir->VirtualAddress));

        if (!tls) {
            m_last_error = "failed to resolve TLS directory RVA";
            return false;
        }

        m_has_tls = true;
        m_info.raw_data_start = tls->StartAddressOfRawData;
        m_info.raw_data_end = tls->EndAddressOfRawData;
        m_info.address_of_index = tls->AddressOfIndex;
        m_info.address_of_callbacks = tls->AddressOfCallBacks;
        m_info.size_of_zero_fill = tls->SizeOfZeroFill;
        m_info.characteristics = tls->Characteristics;

        if (tls->AddressOfCallBacks) {
            const ULONGLONG image_base = m_file.optional_header()->ImageBase;
            const DWORD callbacks_rva = static_cast<DWORD>(tls->AddressOfCallBacks - image_base);
            auto* callbacks = reinterpret_cast<const ULONGLONG*>(m_file.rva_to_pointer(callbacks_rva));

            if (callbacks) {
                while (m_file.is_offset_valid(
                           static_cast<DWORD>(reinterpret_cast<const BYTE*>(callbacks) - m_file.raw_data()),
                           sizeof(ULONGLONG)) &&
                       *callbacks != 0) {
                    m_info.callback_rvas.push_back(*callbacks - image_base);
                    ++callbacks;
                }
            }
        }

        return true;
    }
}
