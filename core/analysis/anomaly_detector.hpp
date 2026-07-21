#pragma once

#include <core/pe/pe_file.hpp>

#include <string>
#include <vector>

namespace analysis
{
    enum class anomaly_severity
    {
        info,
        warning,
        suspicious
    };

    struct anomaly
    {
        anomaly_severity severity;
        std::string category;
        std::string description;
    };

    class anomaly_detector
    {
    public:
        explicit anomaly_detector(const pe::pe_file& file);

        void run();

        const std::vector<anomaly>& get_anomalies() const { return m_anomalies; }

    private:
        void check_entry_point();
        void check_section_names();
        void check_section_permissions();
        void check_section_sizes();
        void check_import_count();
        void check_tls_callbacks();
        void check_data_directories();
        void check_header_values();

        void add_anomaly(anomaly_severity severity, const std::string& category, const std::string& description);

        const pe::pe_file& m_file;
        std::vector<anomaly> m_anomalies;
    };
}
