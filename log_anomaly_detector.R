# ==============================================================================
# PROJECT: LIGHTWEIGHT NETWORK SYSLOG ANOMALY DETECTOR
# AUTHOR: MATUTUZELA JABULANI NDLOVU
# PURPOSE: Parses raw network connection data and flags statistical anomalies
# ==============================================================================

# Load core HarvardX data wrangling libraries
library(dplyr)
library(ggplot2)

# 1. SIMULATE RAW FIREWALL/ROUTER LOG DATA
set.seed(930925) # Anchored with your birthdate seed for uniqueness
network_logs <- data.frame(
  timestamp = seq(from = as.POSIXct("2026-09-21 00:00:00"), by = "10 min", length.out = 144),
  source_ip = sample(c("192.168.1.50", "192.168.1.60", "10.0.0.15", "45.22.11.4"), 144, replace = TRUE),
  destination_port = sample(c(80, 443, 22, 8080, 23), 144, replace = TRUE),
  packets_transferred = rpois(144, lambda = 15) # Simulating baseline standard traffic
)

# Introduce artificial anomalies (Simulating a port scan / DDoS traffic spike)
network_logs$packets_transferred[c(25, 72, 115)] <- c(450, 612, 580)
network_logs$destination_port[c(25, 72, 115)] <- 23 # Dangerous Telnet port spikes

# 2. THE STATISTICAL DETECTION LAYER (Applying Data Science training)
# Calculate baseline thresholds using standard deviation bounds
mean_packets <- mean(network_logs$packets_transferred)
sd_packets   <- sd(network_logs$packets_transferred)
threshold    <- mean_packets + (3 * sd_packets) # 3-Sigma rule for anomaly detection

# Filter and flag anomalous rows
flagged_threats <- network_logs %>%
  filter(packets_transferred > threshold) %>%
  select(timestamp, source_ip, destination_port, packets_transferred)

# 3. OUTPUT THE DIAGNOSTIC RESULTS
cat("=== ENTERPRISE NETWORK SECURITY AUDIT REPORT ===\n")
cat("Baseline Mean Packets:", round(mean_packets, 2), "\n")
cat("Anomaly Threshold (3-Sigma Value):", round(threshold, 2), "\n")
cat("Number of High-Risk Threat Alerts Detected:", nrow(flagged_threats), "\n\n")
print(flagged_threats)
