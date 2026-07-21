#include "rich_header.hpp"

#include <bit>

namespace analysis
{
    namespace
    {
        constexpr DWORD RICH_SIGNATURE = 0x68636952; // "Rich"
        constexpr DWORD DANS_SIGNATURE = 0x536E6144; // "DanS"
    }

    rich_header::rich_header(const pe::pe_file& file)
        : m_file(file),
          m_info{},
          m_has_rich(false)
    {
    }

    bool rich_header::parse()
    {
        m_has_rich = false;
        m_info = {};

        const BYTE* data = m_file.raw_data();
        const DWORD pe_offset = m_file.dos_header()->e_lfanew;

        // rich header sits between the DOS stub and the PE signature
        DWORD rich_offset = 0;

        if (pe_offset < sizeof(IMAGE_DOS_HEADER) + 8) {
            return true;
        }

        for (DWORD i = pe_offset - 4; i >= sizeof(IMAGE_DOS_HEADER); i -= 4) {
            auto* dword = reinterpret_cast<const DWORD*>(data + i);
            if (*dword == RICH_SIGNATURE) {
                rich_offset = i;
                break;
            }
        }

        if (rich_offset == 0) {
            return true;
        }

        // the DWORD after "Rich" is the XOR key
        auto* xor_key_ptr = reinterpret_cast<const DWORD*>(data + rich_offset + 4);
        const DWORD xor_key = *xor_key_ptr;
        m_info.xor_key = xor_key;

        // scan backwards from "Rich" to find "DanS" (XOR'd with the key)
        DWORD dans_offset = 0;

        for (DWORD i = rich_offset - 4; i >= sizeof(IMAGE_DOS_HEADER); i -= 4) {
            auto* dword = reinterpret_cast<const DWORD*>(data + i);
            if ((*dword ^ xor_key) == DANS_SIGNATURE) {
                dans_offset = i;
                break;
            }
        }

        if (dans_offset == 0) {
            return true;
        }

        m_has_rich = true;

        // entries start after "DanS" + 3 padding DWORDs (all XOR'd)
        const DWORD entries_start = dans_offset + 16;
        const DWORD entries_end = rich_offset;

        for (DWORD offset = entries_start; offset + 8 <= entries_end; offset += 8) {
            auto* raw = reinterpret_cast<const DWORD*>(data + offset);

            const DWORD comp_id = raw[0] ^ xor_key;
            const DWORD use_count = raw[1] ^ xor_key;

            rich_entry entry = {};
            entry.build_id = static_cast<WORD>(comp_id & 0xFFFF);
            entry.product_id = static_cast<WORD>((comp_id >> 16) & 0xFFFF);
            entry.use_count = use_count;

            m_info.entries.push_back(entry);
        }

        // compute checksum for verification
        DWORD checksum = dans_offset;

        for (DWORD i = 0; i < dans_offset; ++i) {
            if (i >= 0x3C && i < 0x40) {
                continue; // skip e_lfanew field
            }
            checksum += std::rotl(static_cast<DWORD>(data[i]), static_cast<int>(i % 32));
        }

        for (const auto& entry : m_info.entries) {
            DWORD comp_id = (static_cast<DWORD>(entry.product_id) << 16) | entry.build_id;
            checksum += std::rotl(comp_id, static_cast<int>(entry.use_count % 32));
        }

        m_info.checksum = checksum;

        return true;
    }

    std::string rich_header::product_id_to_string(WORD id)
    {
        switch (id) {
            case 1: return "Import0";
            case 2: return "Linker510";
            case 3: return "Cvtomf510";
            case 4: return "Linker600";
            case 5: return "Cvtomf600";
            case 6: return "Cvtres500";
            case 7: return "Utc11_Basic";
            case 8: return "Utc11_C";
            case 9: return "Utc12_Basic";
            case 10: return "Utc12_C";
            case 11: return "Utc12_CPP";
            case 15: return "Linker622";
            case 16: return "Cvtomf622";
            case 19: return "Linker700";
            case 20: return "Cvtomf700";
            case 21: return "Utc12_C_Std";
            case 22: return "Utc12_CPP_Std";
            case 23: return "Utc12_C_Book";
            case 24: return "Utc12_CPP_Book";
            case 25: return "Implib700";
            case 26: return "Cvtomf700";
            case 45: return "Utc13_C";
            case 46: return "Utc13_CPP";
            case 47: return "Linker710";
            case 48: return "Cvtomf710";
            case 50: return "Utc13_C_Std";
            case 51: return "Utc13_CPP_Std";
            case 83: return "Linker800";
            case 84: return "Cvtomf800";
            case 85: return "Utc14_C";
            case 86: return "Utc14_CPP";
            case 104: return "Linker900";
            case 105: return "Masm900";
            case 106: return "Utc15_C";
            case 107: return "Utc15_CPP";
            case 255: return "Linker1400";
            case 256: return "Masm1400";
            case 257: return "Utc1900_C";
            case 258: return "Utc1900_CPP";
            case 259: return "Utc1900_CVTCIL_C";
            case 260: return "Utc1900_CVTCIL_CPP";
            case 261: return "Linker1410";
            default: return "Unknown";
        }
    }
}
