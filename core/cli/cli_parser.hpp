#pragma once

#include <string>
#include <vector>

namespace cli
{
    struct cli_options
    {
        std::string file_path;

        bool show_headers = false;
        bool show_sections = false;
        bool show_imports = false;
        bool show_exports = false;
        bool show_relocations = false;
        bool show_tls = false;
        bool show_debug = false;
        bool show_load_config = false;
        bool show_resources = false;
        bool show_signature = false;
        bool show_rich = false;
        bool show_anomalies = false;
        bool show_all = false;

        bool show_help = false;
        bool show_version = false;
    };

    inline bool parse_args(int argc, char* argv[], cli_options& opts)
    {
        if (argc < 2) {
            opts.show_help = true;
            return true;
        }

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];

            if (arg == "--help" || arg == "-h") {
                opts.show_help = true;
                return true;
            }
            else if (arg == "--version" || arg == "-v") {
                opts.show_version = true;
                return true;
            }
            else if (arg == "--all" || arg == "-a") {
                opts.show_all = true;
            }
            else if (arg == "--headers") {
                opts.show_headers = true;
            }
            else if (arg == "--sections") {
                opts.show_sections = true;
            }
            else if (arg == "--imports") {
                opts.show_imports = true;
            }
            else if (arg == "--exports") {
                opts.show_exports = true;
            }
            else if (arg == "--relocations" || arg == "--relocs") {
                opts.show_relocations = true;
            }
            else if (arg == "--tls") {
                opts.show_tls = true;
            }
            else if (arg == "--debug") {
                opts.show_debug = true;
            }
            else if (arg == "--load-config" || arg == "--cfg") {
                opts.show_load_config = true;
            }
            else if (arg == "--resources" || arg == "--rsrc") {
                opts.show_resources = true;
            }
            else if (arg == "--signature" || arg == "--sig") {
                opts.show_signature = true;
            }
            else if (arg == "--rich") {
                opts.show_rich = true;
            }
            else if (arg == "--anomalies" || arg == "--scan") {
                opts.show_anomalies = true;
            }
            else if (arg[0] == '-') {
                std::fprintf(stderr, "unknown option: %s\n", arg.c_str());
                return false;
            }
            else {
                if (opts.file_path.empty()) {
                    opts.file_path = arg;
                }
                else {
                    std::fprintf(stderr, "unexpected argument: %s\n", arg.c_str());
                    return false;
                }
            }
        }

        if (opts.file_path.empty() && !opts.show_help && !opts.show_version) {
            std::fprintf(stderr, "error: no input file specified\n");
            return false;
        }

        bool any_selected = opts.show_headers || opts.show_sections || opts.show_imports ||
                            opts.show_exports || opts.show_relocations || opts.show_tls ||
                            opts.show_debug || opts.show_load_config || opts.show_resources ||
                            opts.show_signature || opts.show_rich || opts.show_anomalies;

        if (!any_selected && !opts.show_all) {
            opts.show_all = true;
        }

        return true;
    }

    inline void print_usage()
    {
        std::printf("pe-dissector - PE file analysis tool\n\n");
        std::printf("Usage: pe-dissector [options] <file>\n\n");
        std::printf("Options:\n");
        std::printf("  -h, --help          Show this help message\n");
        std::printf("  -v, --version       Show version\n");
        std::printf("  -a, --all           Show all information (default)\n");
        std::printf("  --headers           PE headers (DOS, File, Optional)\n");
        std::printf("  --sections          Section table\n");
        std::printf("  --imports           Import directory\n");
        std::printf("  --exports           Export directory\n");
        std::printf("  --relocations       Base relocation table\n");
        std::printf("  --tls               TLS directory and callbacks\n");
        std::printf("  --debug             Debug directory and PDB info\n");
        std::printf("  --load-config       Load configuration and CFG info\n");
        std::printf("  --resources         Resource directory tree\n");
        std::printf("  --signature         Authenticode signature info\n");
        std::printf("  --rich              Rich header (build tool info)\n");
        std::printf("  --anomalies         Heuristic anomaly scan\n");
    }

    inline void print_version()
    {
        std::printf("pe-dissector 1.0.0\n");
    }
}
