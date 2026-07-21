#include "relocation_table.hpp"

namespace analysis
{
    relocation_table::relocation_table(const pe::pe_file& file)
        : m_file(file)
    {
    }

    bool relocation_table::parse()
    {
        m_blocks.clear();

        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)) {
            return true;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        auto* base = m_file.rva_to_pointer(dir->VirtualAddress);

        if (!base) {
            m_last_error = "failed to resolve base relocation RVA";
            return false;
        }

        const DWORD dir_rva = dir->VirtualAddress;
        const DWORD dir_size = dir->Size;

        if (!m_file.is_rva_valid(dir_rva, dir_size)) {
            m_last_error = "relocation directory extends beyond file";
            return false;
        }

        DWORD offset = 0;

        while (offset + sizeof(IMAGE_BASE_RELOCATION) <= dir_size) {
            auto* block_header = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(base + offset);

            if (block_header->SizeOfBlock == 0 || block_header->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
                break;
            }

            if (offset + block_header->SizeOfBlock > dir_size) {
                break;
            }

            relocation_block block;
            block.page_rva = block_header->VirtualAddress;
            block.block_size = block_header->SizeOfBlock;

            const DWORD entry_count = (block_header->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto* entries = reinterpret_cast<const WORD*>(
                reinterpret_cast<const BYTE*>(block_header) + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < entry_count; ++i) {
                const BYTE type = static_cast<BYTE>(entries[i] >> 12);
                const WORD entry_offset = entries[i] & 0x0FFF;

                if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue;
                }

                relocation_entry entry;
                entry.rva = block.page_rva + entry_offset;
                entry.type = type;
                block.entries.push_back(entry);
            }

            m_blocks.push_back(std::move(block));
            offset += block_header->SizeOfBlock;
        }

        return true;
    }

    std::size_t relocation_table::total_entry_count() const
    {
        std::size_t count = 0;
        for (const auto& block : m_blocks) {
            count += block.entries.size();
        }
        return count;
    }
}
