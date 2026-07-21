#include "signature_info.hpp"

namespace analysis
{
    signature_info::signature_info(const pe::pe_file& file)
        : m_file(file),
          m_is_signed(false)
    {
    }

    bool signature_info::parse()
    {
        m_certificates.clear();
        m_is_signed = false;

        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)) {
            return true;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY);

        // security directory uses raw file offsets, not RVAs
        if (!m_file.is_offset_valid(dir->VirtualAddress, dir->Size)) {
            m_last_error = "certificate table offset is outside file bounds";
            return false;
        }

        const BYTE* cert_data = m_file.raw_data() + dir->VirtualAddress;
        DWORD offset = 0;

        while (offset + sizeof(WIN_CERTIFICATE) <= dir->Size) {
            auto* cert = reinterpret_cast<const WIN_CERTIFICATE*>(cert_data + offset);

            if (cert->dwLength < sizeof(WIN_CERTIFICATE)) {
                break;
            }

            certificate_entry entry = {};
            entry.length = cert->dwLength;
            entry.revision = cert->wRevision;
            entry.certificate_type = cert->wCertificateType;

            m_certificates.push_back(entry);
            m_is_signed = true;

            offset += cert->dwLength;
            offset = (offset + 7) & ~7;
        }

        return true;
    }
}
