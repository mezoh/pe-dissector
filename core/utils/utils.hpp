#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

namespace utils
{
    bool load_file(const std::string& path, std::vector<BYTE>& out_buffer);

    std::string format_hex(ULONGLONG value, int width = 0);
    std::string format_size(ULONGLONG size);
    std::string format_guid(const BYTE* guid);

    void print_hex_dump(const BYTE* data, std::size_t size, ULONGLONG base_offset = 0, std::size_t max_rows = 16);

    std::string to_lower(const std::string& str);

    std::string wide_to_narrow(const wchar_t* wide, std::size_t max_len = 0);
}
