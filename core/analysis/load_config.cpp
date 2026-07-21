#include "load_config.hpp"

namespace analysis
{
    load_config::load_config(const pe::pe_file& file)
        : m_file(file),
          m_info{},
          m_has_config(false)
    {
    }

    bool load_config::parse()
    {
        m_has_config = false;
        m_info = {};

        if (!m_file.has_data_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)) {
            return true;
        }

        auto* dir = m_file.get_data_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
        auto* config = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY64*>(
            m_file.rva_to_pointer(dir->VirtualAddress));

        if (!config) {
            m_last_error = "failed to resolve load config directory RVA";
            return false;
        }

        m_has_config = true;
        m_info.size = config->Size;
        m_info.timestamp = config->TimeDateStamp;
        m_info.major_version = config->MajorVersion;
        m_info.minor_version = config->MinorVersion;
        m_info.security_cookie = config->SecurityCookie;

        if (config->Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SEHandlerTable) + sizeof(ULONGLONG)) {
            m_info.se_handler_table = config->SEHandlerTable;
            m_info.se_handler_count = config->SEHandlerCount;
        }

        if (config->Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFCheckFunctionPointer) + sizeof(ULONGLONG)) {
            m_info.guard_cf_check_function_pointer = config->GuardCFCheckFunctionPointer;
            m_info.guard_cf_dispatch_function_pointer = config->GuardCFDispatchFunctionPointer;
            m_info.guard_cf_function_table = config->GuardCFFunctionTable;
            m_info.guard_cf_function_count = config->GuardCFFunctionCount;
            m_info.guard_flags = config->GuardFlags;
        }

        const ULONGLONG image_base = m_file.optional_header()->ImageBase;

        if (m_info.guard_cf_function_table && m_info.guard_cf_function_count > 0) {
            const DWORD table_rva = static_cast<DWORD>(m_info.guard_cf_function_table - image_base);
            auto* table = reinterpret_cast<const DWORD*>(m_file.rva_to_pointer(table_rva));

            if (table) {
                const DWORD stride = (m_info.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>
                                     IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
                const DWORD entry_size = stride > 0 ? (4 + stride) : 4;

                for (ULONGLONG i = 0; i < m_info.guard_cf_function_count && i < 10000; ++i) {
                    const std::size_t byte_offset = static_cast<std::size_t>(i) * entry_size;
                    auto* entry_ptr = reinterpret_cast<const BYTE*>(table) + byte_offset;
                    const DWORD file_offset = static_cast<DWORD>(entry_ptr - m_file.raw_data());

                    if (!m_file.is_offset_valid(file_offset, sizeof(DWORD))) {
                        break;
                    }

                    m_info.cfg_function_rvas.push_back(*reinterpret_cast<const DWORD*>(entry_ptr));
                }
            }
        }

        return true;
    }
}
