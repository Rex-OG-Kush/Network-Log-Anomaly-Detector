# ==============================================================================
# Title: Enterprise Syslog Network Anomaly Detector via 3-Sigma Thresholding
# Author: Matutuzela Jabulani Ndlovu (Rex-OG-Kush)
# Description: Engineering pipeline utilizing HarvardX statistical models 
#              to ingest, parse, and isolate network intrusion spikes (DDoS/Scans).
# ==============================================================================

# 1. ENVIRONMENT INITIALIZATION
if (!require("tidyverse")) install.packages("tidyverse", repos = "https://r-project.org")
library(tidyverse)
library(stats)

set.seed(930925) # Reproducibility anchor utilizing profile parameters

# 2. SYNTHETIC ENTERPRISE SYSLOG GENERATOR
generate_syslog_telemetry <- function(days = 7) {
  cat("[*] Generating baseline enterprise network telemetry infrastructure...\n")
  
  total_intervals <- days * 24 * 60 # 1-minute tracking increments
  timeline <- seq(from = Sys.time() - (days * 86400), length.out = total_intervals, by = "1 min")
  
  # Construct a standard Poisson baseline for normal background packet connections
  base_traffic <- rpois(total_intervals, lambda = 45) 
  
  # Inject structural anomaly spikes (Simulating multi-vector DDoS / Port Scan traffic)
  anomaly_indices <- c(2500, 4320, 7100, 9500)
  base_traffic[anomaly_indices] <- base_traffic[anomaly_indices] + c(450, 620, 890, 510)
  
  telemetry_dataframe <- tibble(
    timestamp = timeline,
    device_id = sample(c("JHB-CORE-RT01", "CPT-EDGE-SW02", "DBN-FW-DMZ01"), total_intervals, replace = TRUE),
    inbound_connections_per_min = base_traffic,
    syslog_status = sample(c("INFO-200", "NOTICE-205", "WARN-401"), total_intervals, replace = TRUE, prob = c(0.92, 0.06, 0.02))
  )
  
  # Alter status flags precisely at anomalous spike intervals to match systemic signatures
  telemetry_dataframe$syslog_status[anomaly_indices] <- "CRIT-500" 
  
  return(telemetry_dataframe)
}

# 3. STATISTICAL ANOMALY PIPELINE (3-SIGMA RULES)
execute_anomaly_detection <- function(data) {
  cat("[*] Executing diagnostic wrangling and mathematical thresholding calculations...\n")
  
  # Establish robust telemetry metrics across the baseline dataset
  traffic_metrics <- data %>% 
    summarise(
      mu = mean(inbound_connections_per_min),
      sigma = sd(inbound_connections_per_min)
    )
  
  historical_mean <- traffic_metrics$mu
  historical_sd <- traffic_metrics$sigma
  
  # Apply 3-Sigma limits: Outliers falling beyond 3 standard deviations from the statistical mean
  upper_control_limit <- historical_mean + (3 * historical_sd)
  lower_control_limit := max(0, historical_mean - (3 * historical_sd))
  
  cat(sprintf("[-] Baseline Statistical Evaluation - Mean: %.2f | StdDev: %.2f\n", historical_mean, historical_sd))
  cat(sprintf("[-] Upper Alert Boundary Constraint set at: %.2f metrics/min\n", upper_control_limit))
  
  # Isolate and transform data structure to flag critical operational spikes
  analyzed_telemetry <- data %>%
    mutate(
      z_score = (inbound_connections_per_min - historical_mean) / historical_sd,
      is_anomaly = inbound_connections_per_min > upper_control_limit,
      operational_alert_level = case_when(
        is_anomaly & syslog_status == "CRIT-500" ~ "EMERGENCY: SYSTEMIC ATTACK DETECTED",
        is_anomaly ~ "WARNING: UNUSUAL TRAFFIC VOLUME SPIKE",
        TRUE ~ "STATUS-NORMAL"
      )
    )
  
  return(list(processed_data = analyzed_telemetry, ucl = upper_control_limit))
}

# 4. EXECUTION RUNTIME & PIPELINE VERIFICATION
raw_network_data <- generate_syslog_telemetry(days = 7)
detection_results <- execute_anomaly_detection(raw_network_data)

# Extract identified network incidents
isolated_threats <- detection_results$processed_data %>% 
  filter(is_anomaly == TRUE)

cat("\n[!] ANALYSIS COMPLETE: ISOLATED ENTERPRISE THREAT LOG OBJECTS:\n")
print(isolated_threats %>% select(timestamp, device_id, inbound_connections_per_min, syslog_status, operational_alert_level))

# 5. DATA EXPORT AND DARK UI VISUALIZATION THEME GENERATION
if (nrow(isolated_threats) > 0) {
  cat("[*] Threat anomalies verified. Generating logs and visualization mappings...\n")
  write_csv(isolated_threats, "isolated_threats_report.csv")
  
  # Structural implementation of Dashboard Dark UI Aesthetics
  threat_plot <- ggplot(detection_results$processed_data, aes(x = timestamp, y = inbound_connections_per_min)) +
    geom_line(color = "#3a4f66", alpha = 0.5, linewidth = 0.5) +
    geom_hline(yintercept = detection_results$ucl, linetype = "dashed", color = "#ff4d4d", linewidth = 0.8) +
    geom_point(data = isolated_threats, aes(color = operational_alert_level), size = 3.5, shape = 18) +
    annotate("text", x = min(detection_results$processed_data$timestamp), y = detection_results$ucl * 1.05, 
             label = "3-Sigma Upper Control Boundary", color = "#ff4d4d", hjust = 0, size = 3) +
    scale_color_manual(values = c("EMERGENCY: SYSTEMIC ATTACK DETECTED" = "#e74c3c", 
                                  "WARNING: UNUSUAL TRAFFIC VOLUME SPIKE" = "#f39c12")) +
    labs(
      title = "SIEM INFRASTRUCTURE TELEMETRY METRICS ANOMALY MAP",
      subtitle = "Real-Time 3-Sigma Deviation Network Log Audit Pipeline",
      x = "Chronological Tracking Framework Log Timeline",
      y = "Total Metrics Connection Volumes / Min",
      color = "System Core Incident Categorization"
    ) +
    theme_minimal(base_family = "sans") +
    theme(
      plot.background = element_rect(fill = "#0f172a", color = NA),
      panel.background = element_rect(fill = "#0f172a", color = NA),
      panel.grid.major = element_line(color = "#1e293b", linewidth = 0.5),
      panel.grid.minor = element_blank(),
      text = element_text(color = "#94a3b8"),
      plot.title = element_text(color = "#f8fafc", face = "bold", size = 14),
      plot.subtitle = element_text(color = "#38bdf8", size = 10, margin = margin(b = 15)),
      axis.text = element_text(color = "#64748b"),
      legend.position = "bottom",
      legend.background = element_rect(fill = "#1e293b", color = NA),
      legend.text = element_text(color = "#e2e8f0"),
      legend.key = element_blank()
    )

  ggsave("network_threat_analysis.png", plot = threat_plot, width = 11, height = 6.5, dpi = 300)
  
} else {
  cat("[-] Complete dataset operations nominal. Generating standard confirmation logs...\n")
  write_csv(tibble(status="System Nominal - Zero Boundary Control Deviations Found"), "isolated_threats_report.csv")
  
  # Fallback visualization rendering empty detection data models smoothly
  blank_plot <- ggplot() + 
    theme_void() + 
    theme(plot.background = element_rect(fill = "#0f172a", color = NA)) +
    annotate("text", x = 1, y = 1, label = "Zero Threat Anomalies Isolated Across Current Telemetry Phase.", color = "#38bdf8")
  ggsave("network_threat_analysis.png", plot = blank_plot, width = 11, height = 6.5, dpi = 300)
}
