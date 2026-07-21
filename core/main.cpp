#include <core/pe/pe_file.hpp>
#include <core/cli/cli_parser.hpp>
#include <core/cli/cli_output.hpp>
#include <core/analysis/import_table.hpp>
#include <core/analysis/export_table.hpp>
#include <core/analysis/relocation_table.hpp>
#include <core/analysis/tls_directory.hpp>
#include <core/analysis/debug_directory.hpp>
#include <core/analysis/load_config.hpp>
#include <core/analysis/resource_table.hpp>
#include <core/analysis/signature_info.hpp>
#include <core/analysis/rich_header.hpp>
#include <core/analysis/anomaly_detector.hpp>
#include <core/utils/utils.hpp>

#include <cstdio>

int main(int argc, char* argv[])
{
    cli::cli_options opts;

    if (!cli::parse_args(argc, argv, opts)) {
        std::printf("\nRun 'pe-dissector --help' for usage.\n");
        return 1;
    }

    if (opts.show_help) {
        cli::print_usage();
        return 0;
    }

    if (opts.show_version) {
        cli::print_version();
        return 0;
    }

    pe::pe_file file;

    if (!file.load_from_file(opts.file_path)) {
        std::fprintf(stderr, "error: %s\n", file.last_error().c_str());
        return 1;
    }

    std::printf("pe-dissector | %s\n", opts.file_path.c_str());
    std::printf("File size: %s | Format: PE32+ (64-bit)\n",
                 utils::format_size(file.raw_size()).c_str());

    if (opts.show_all || opts.show_headers) {
        cli::print_headers(file);
    }

    if (opts.show_all || opts.show_sections) {
        cli::print_sections(file);
    }

    if (opts.show_all || opts.show_imports) {
        analysis::import_table imports(file);
        if (imports.parse()) {
            cli::print_imports(imports);
        }
        else {
            std::fprintf(stderr, "  warning: %s\n", imports.last_error().c_str());
        }
    }

    if (opts.show_all || opts.show_exports) {
        analysis::export_table exports(file);
        if (exports.parse()) {
            cli::print_exports(exports);
        }
        else {
            std::fprintf(stderr, "  warning: %s\n", exports.last_error().c_str());
        }
    }

    if (opts.show_all || opts.show_relocations) {
        analysis::relocation_table relocs(file);
        if (relocs.parse()) {
            cli::print_relocations(relocs);
        }
        else {
            std::fprintf(stderr, "  warning: %s\n", relocs.last_error().c_str());
        }
    }

    if (opts.show_all || opts.show_tls) {
        analysis::tls_directory tls(file);
        if (tls.parse()) {
            cli::print_tls(tls);
        }
        else {
            std::fprintf(stderr, "  warning: %s\n", tls.last_error().c_str());
        }
    }

    if (opts.show_all || opts.show_debug) {
        analysis::debug_directory debug(file);
        if (debug.parse()) {
            cli::print_debug(debug);
        }
        else {
            std::fprintf(stderr, "  warning: %s\n", debug.last_error().c_str());
        }
    }

    if (opts.show_all || opts.show_load_config) {
        analysis::load_config config(file);
        if (config.parse()) {
            cli::print_load_config(config);
        }
        else {
            std::fprintf(stderr, "  warning: %s\n", config.last_error().c_str());
        }
    }

    if (opts.show_all || opts.show_resources) {
        analysis::resource_table resources(file);
        if (resources.parse()) {
            cli::print_resources(resources);
        }
        else {
            std::fprintf(stderr, "  warning: %s\n", resources.last_error().c_str());
        }
    }

    if (opts.show_all || opts.show_signature) {
        analysis::signature_info sig(file);
        if (sig.parse()) {
            cli::print_signature(sig);
        }
        else {
            std::fprintf(stderr, "  warning: %s\n", sig.last_error().c_str());
        }
    }

    if (opts.show_all || opts.show_rich) {
        analysis::rich_header rich(file);
        if (rich.parse()) {
            cli::print_rich_header(rich);
        }
        else {
            std::fprintf(stderr, "  warning: %s\n", rich.last_error().c_str());
        }
    }

    if (opts.show_all || opts.show_anomalies) {
        analysis::anomaly_detector detector(file);
        detector.run();
        cli::print_anomalies(detector);
    }

    std::printf("\n");
    return 0;
}
