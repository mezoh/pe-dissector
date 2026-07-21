#include "utils.hpp"

#include <fstream>
#include <iostream>
#include <algorithm>

namespace utils
{
    bool load_file(const std::string& path, std::vector<BYTE>& out_buffer)
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return false;
        }

        const auto file_size = file.tellg();
        if (file_size <= 0) {
            return false;
        }

        out_buffer.resize(static_cast<std::size_t>(file_size));
        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char*>(out_buffer.data()), file_size);

        return file.good();
    }

    std::string format_hex(ULONGLONG value, int width)
    {
        std::ostringstream out;
        out << "0x" << std::hex << std::uppercase;

        if (width > 0) {
            out << std::setfill('0') << std::setw(width);
        }

        out << value;
        return out.str();
    }

    std::string format_size(ULONGLONG size)
    {
        std::ostringstream out;

        if (size >= 1024 * 1024) {
            out << std::fixed << std::setprecision(2) << (static_cast<double>(size) / (1024.0 * 1024.0)) << " MB";
        }
        else if (size >= 1024) {
            out << std::fixed << std::setprecision(2) << (static_cast<double>(size) / 1024.0) << " KB";
        }
        else {
            out << size << " bytes";
        }

        return out.str();
    }

    std::string format_guid(const BYTE* guid)
    {
        std::ostringstream out;
        out << std::hex << std::uppercase << std::setfill('0');

        const auto* dw = reinterpret_cast<const DWORD*>(guid);
        const auto* w = reinterpret_cast<const WORD*>(guid + 4);

        out << std::setw(8) << dw[0] << "-";
        out << std::setw(4) << w[0] << "-";
        out << std::setw(4) << w[1] << "-";
        out << std::setw(2) << static_cast<int>(guid[8]) << std::setw(2) << static_cast<int>(guid[9]) << "-";

        for (int i = 10; i < 16; ++i) {
            out << std::setw(2) << static_cast<int>(guid[i]);
        }

        return out.str();
    }

    void print_hex_dump(const BYTE* data, std::size_t size, ULONGLONG base_offset, std::size_t max_rows)
    {
        const std::size_t bytes_per_row = 16;
        const std::size_t total_rows = (size + bytes_per_row - 1) / bytes_per_row;
        const std::size_t rows_to_print = (max_rows > 0 && total_rows > max_rows) ? max_rows : total_rows;

        for (std::size_t row = 0; row < rows_to_print; ++row) {
            const std::size_t offset = row * bytes_per_row;

            std::printf("  %08llX  ", base_offset + offset);

            for (std::size_t col = 0; col < bytes_per_row; ++col) {
                if (offset + col < size) {
                    std::printf("%02X ", data[offset + col]);
                }
                else {
                    std::printf("   ");
                }

                if (col == 7) {
                    std::printf(" ");
                }
            }

            std::printf(" |");
            for (std::size_t col = 0; col < bytes_per_row; ++col) {
                if (offset + col < size) {
                    const BYTE ch = data[offset + col];
                    std::printf("%c", (ch >= 0x20 && ch < 0x7F) ? ch : '.');
                }
                else {
                    std::printf(" ");
                }
            }
            std::printf("|\n");
        }

        if (rows_to_print < total_rows) {
            std::printf("  ... (%zu more rows)\n", total_rows - rows_to_print);
        }
    }

    std::string to_lower(const std::string& str)
    {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return result;
    }

    std::string wide_to_narrow(const wchar_t* wide, std::size_t max_len)
    {
        std::string result;
        for (std::size_t i = 0; wide[i] != L'\0'; ++i) {
            if (max_len > 0 && i >= max_len) {
                break;
            }
            result += static_cast<char>(wide[i] & 0xFF);
        }
        return result;
    }
}
