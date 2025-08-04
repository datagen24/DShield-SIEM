# DShield-SIEM Project File Index

This document provides a comprehensive index of all files in the DShield-SIEM project with brief descriptions for easy navigation and reference.

## Root Directory Files

### Core Configuration Files
- **docker-compose.yml** - Main Docker Compose orchestration file defining all Elastic Stack services, networks, volumes, and dependencies for the SIEM deployment.
- **.env** - Environment variables configuration file containing Elasticsearch passwords, TLS settings, and other deployment-specific parameters.
- **README.md** - Primary project documentation with installation instructions, architecture overview, and quick start guide for the DShield-SIEM system.
- **LICENSE** - Project license file defining terms of use and distribution rights for the DShield-SIEM codebase.

## Documentation Directory (/docs)

### Project Documentation
- **product_requirements_document.md** - Comprehensive PRD defining project scope, features, user flows, tech stack, and non-functional requirements for the SIEM system.
- **security_guideline_document.md** - Security best practices, controls, and mandatory requirements for secure deployment and operation of the DShield-SIEM platform.
- **file_index.md** - This file: comprehensive index of all project files with descriptions for navigation and reference.

## Add-On Documentation (/AddOn)

### Installation and Setup Guides
- **Backup_DShield_Sensor_Logs.md** - Instructions for setting up automated backup of Cowrie, webhoneypot, and firewall logs from DShield sensors using cron jobs.
- **Build_a_Docker_Partition.md** - Step-by-step guide for creating a dedicated 300GB partition for Docker storage using LVM and XFS filesystem.
- **Configure-Elastic-Agent.md** - Complete setup guide for installing and configuring Elastic Agent on DShield sensors for centralized log collection and monitoring.
- **Configure_Arkime.md** - Installation and configuration guide for Arkime packet capture and analysis system integration with the SIEM platform.
- **Configure_Zeek_DShield_Sensor.md** - Setup instructions for installing Zeek network security monitor on DShield sensors for enhanced network traffic analysis.
- **LXC_Container_DShield-SIEM.md** - Proxmox LXC container setup guide for deploying DShield-SIEM in a virtualized environment with proper resource allocation.

### Security and Integration
- **ISC_threatintel.md** - Configuration guide for integrating Internet Storm Center threat intelligence feeds into the SIEM for enhanced threat detection.
- **virustotal_cowrie_malware_enrichment.md** - Setup instructions for VirusTotal API integration to enrich Cowrie honeypot malware detections with threat intelligence.
- **Workstation_Browser_CA_Certificate.md** - Guide for installing CA certificates on workstation browsers to access Kibana and other SIEM components securely.
- **Viewing_TTY_Logs_with_Lighttpd.md** - Instructions for setting up Lighttpd web server to view and analyze Cowrie honeypot TTY session logs through a web interface.

### Network Analysis
- **packet_capture.md** - Documentation for packet capture capabilities and integration with the SIEM for deep packet inspection and analysis.
- **packet_capture.tgz** - Compressed archive containing packet capture configuration files and scripts for network traffic analysis.
- **startelk.tgz** - Compressed archive containing startup scripts and configuration files for initializing the ELK stack components.

## Add-On Scripts (/AddOnScripts)

### Automation Scripts
- **change_perms.sh** - Script for setting proper file permissions and ownership for SIEM components, including Elasticsearch data directories and log files.
- **get_iscipintel.sh** - Automated script for downloading and processing ISC threat intelligence data, including top 5000 malicious IPs and Rosti feeds.
- **parsing_tty.sh** - Script for parsing and processing Cowrie honeypot TTY session logs for analysis and visualization in Kibana.
- **rename_arkime_pcap.sh** - Script for renaming and processing pcap files from DShield sensors for import into Arkime packet analysis system.
- **swapmem.sh** - Script for configuring swap memory settings to optimize system performance for Elasticsearch and other memory-intensive components.

## Scripts Directory (/scripts)

### Setup and Configuration Scripts
- **cowrie-setup.sh** - Main setup script for configuring Cowrie honeypot integration, including index templates, dashboards, and threat intelligence enrichment.
- **cowrie-index.json** - Elasticsearch index template for Cowrie honeypot logs with proper field mappings and settings for optimal search performance.
- **cowrie-policy.json** - Index lifecycle management policy for Cowrie logs defining retention periods, rollover settings, and data tiering strategies.
- **cowrie-dshield-index.json** - Index template for DShield-specific Cowrie log fields and custom mappings for enhanced analysis capabilities.
- **cowrie-dshield-policy.json** - ILM policy for DShield Cowrie logs with customized retention and rollover settings for sensor data.
- **cowrie-webhoneypot-index.json** - Index template for webhoneypot logs with field mappings optimized for web attack analysis and visualization.
- **cowrie-webhoneypot-policy.json** - ILM policy for webhoneypot logs defining data retention and management strategies for web attack data.
- **cowrie.vt_data-index.json** - Index template for VirusTotal enrichment data with field mappings for malware analysis and threat intelligence correlation.
- **cowrie.vt_data-policy.json** - ILM policy for VirusTotal data with retention settings optimized for malware intelligence storage and access.

### Threat Intelligence Configuration
- **ti.iscintel-index.json** - Index template for ISC threat intelligence data with field mappings for IP reputation and threat scoring analysis.
- **ti.iscintel-policy.json** - ILM policy for ISC threat intelligence with retention settings for maintaining current threat data and historical analysis.
- **ti.rostiintel-index.json** - Index template for Rosti threat intelligence feeds with field mappings for enhanced threat correlation and analysis.
- **ti.rostiintel-policy.json** - ILM policy for Rosti threat intelligence data with retention and management settings for threat feed integration.

### Dashboard and Visualization Data
- **dshield_sensor_8.17.8.ndjson** - Kibana saved objects export containing dashboards, visualizations, and index patterns for DShield sensor data analysis.
- **Threat_Intel_Indicator_Match_Cowrie.ndjson** - Kibana saved objects for threat intelligence indicator matching dashboards and visualizations.
- **threat_Intel_IP_Address_Indicator_Match_ISC_ThreatIntel.ndjson** - Kibana saved objects for ISC threat intelligence IP address matching and correlation dashboards.

## Logstash Configuration (/logstash)

### Pipeline Configuration (/logstash/pipeline)
- **logstash-100-input.conf** - Input configuration for receiving logs from Filebeat and other data sources with proper SSL/TLS settings.
- **logstash-200-filter-cowrie.conf** - Main filter pipeline for parsing and enriching Cowrie honeypot logs with field extraction and normalization.
- **logstash-201-filter-iptables.conf** - Filter pipeline for processing iptables firewall logs with IP address parsing and action classification.
- **logstash-202-filter-cowrie-webhoneypot.conf** - Filter pipeline for processing webhoneypot logs with HTTP request parsing and attack pattern detection.
- **logstash-203-filter-cowrie-virustotal.conf** - Filter pipeline for enriching Cowrie logs with VirusTotal API lookups for malware hash analysis.
- **logstash-204-filter-cowrie-iscintel.conf** - Filter pipeline for enriching Cowrie logs with ISC threat intelligence for IP reputation scoring.
- **logstash-205-filter-cowrie-rosti.conf** - Filter pipeline for enriching Cowrie logs with Rosti threat intelligence feeds for enhanced threat correlation.
- **logstash-900-output-elastic.conf** - Output configuration for sending processed logs to Elasticsearch with proper bulk indexing and retry settings.

### Logstash Configuration (/logstash/config)
- **logstash.yml** - Main Logstash configuration file defining node settings, pipeline configuration, and monitoring options.
- **pipelines.yml** - Pipeline configuration file defining the order and settings for all Logstash processing pipelines.
- **jvm.options** - JVM configuration options for Logstash including heap size, garbage collection, and performance tuning settings.
- **log4j2.properties** - Logging configuration for Logstash with log levels, appenders, and output formatting settings.
- **log4j2.file.properties** - File-based logging configuration for Logstash with log rotation and retention policies.
- **startup.options** - Startup configuration options for Logstash including memory settings, system limits, and initialization parameters.
- **logstash-sample.conf** - Sample Logstash configuration file demonstrating basic input, filter, and output plugin usage.

## Beats Configuration

### Filebeat Configuration (/filebeat)
- **filebeat.yml** - Main Filebeat configuration for collecting logs from DShield sensors with SSL/TLS settings and output configuration.

### Filebeat01 Configuration (/filebeat01)
- **filebeat.yml** - Alternative Filebeat configuration for secondary log collection with different input sources and processing settings.

### Metricbeat Configuration (/metricbeat)
- **metricbeat.yml** - Metricbeat configuration for collecting system and Docker metrics with enabled modules and output settings.
- **modules.d/beat-xpack.yml** - X-Pack enabled Beat monitoring configuration for collecting metrics from other Beat agents.
- **modules.d/docker.yml** - Docker monitoring module configuration for collecting container metrics and performance data.
- **modules.d/elasticsearch-xpack.yml** - Elasticsearch monitoring module with X-Pack features for cluster health and performance metrics.
- **modules.d/kibana-xpack.yml** - Kibana monitoring module with X-Pack features for dashboard and visualization performance metrics.
- **modules.d/logstash-xpack.yml** - Logstash monitoring module with X-Pack features for pipeline performance and processing metrics.
- **modules.d/system.yml.disabled** - Disabled system monitoring module (can be enabled for host-level metrics collection).

### Heartbeat Configuration (/heartbeat)
- **heartbeat.yml** - Heartbeat configuration for monitoring service availability and uptime with HTTP/HTTPS checks and alerting.

### Elastic Agent Configuration (/elastic-agent)
- **elastic-agent.yml** - Elastic Agent configuration for unified data collection with Fleet integration and centralized management.

## Troubleshooting Directory (/Troubleshooting)

### Documentation and Guides
- **Troubleshooting_SIEM_and_Sensor.md** - Comprehensive troubleshooting guide covering common issues, solutions, and diagnostic procedures for SIEM and sensor connectivity.
- **docker_useful_commands..md** - Collection of useful Docker commands for managing containers, viewing logs, and troubleshooting deployment issues.
- **Recreate_SSL_Certificates.md** - Step-by-step guide for regenerating SSL certificates for secure communication between SIEM components.
- **ELK_VMware_Workstation.md** - Specific troubleshooting guide for running DShield-SIEM in VMware Workstation environment with resource allocation tips.
- **Managing_Elastic_Indices.md** - Guide for managing Elasticsearch indices including backup, restore, and maintenance procedures.
- **Manually_Update_Management_Kibana_Saved_Objects.md** - Instructions for manually updating Kibana dashboards and saved objects when automated updates fail.

### Reference Data
- **fleet-server-examples.txt** - Example configurations and commands for Fleet Server setup and Elastic Agent enrollment procedures.
- **dshield_sensor_8.13.0.ndjson** - Kibana saved objects export for DShield sensor version 8.13.0 compatibility.
- **dshield_sensor_8.14.0.ndjson** - Kibana saved objects export for DShield sensor version 8.14.0 compatibility.
- **dshield_sensor_8.15.0.ndjson** - Kibana saved objects export for DShield sensor version 8.15.0 compatibility.
- **dshield_sensor_8.15.3.ndjson** - Kibana saved objects export for DShield sensor version 8.15.3 compatibility.
- **dshield_sensor_8.17.8.ndjson** - Kibana saved objects export for DShield sensor version 8.17.8 compatibility.

### Visual Documentation
- **DShield-SIEM-Flow.png** - Architecture diagram showing data flow between DShield sensors, Logstash, Elasticsearch, and Kibana components.
- **DShield_Sensor_Port_Forwardng_Example.PNG** - Network diagram illustrating port forwarding configuration for DShield sensor connectivity to SIEM.

## Cursor Rules (.cursor/rules)

### Project Rules and Guidelines
- **CLAUDE.md** - Claude MCPs quick guide for AI-assisted development and project configuration.
- **backend_structure_document.mdc** - Backend architecture documentation defining containerized services, data pipeline patterns, and infrastructure components.
- **cursor_project_rules.mdc** - Project-specific rules and guidelines for development, including directory structure, tech stack requirements, and best practices.
- **frontend_guidelines_document.mdc** - Frontend development guidelines for Kibana dashboards, EUI components, and user interface design principles.
- **project_requirements_document.mdc** - Project requirements document defining scope, features, user flows, and technical specifications.
- **security_guideline_document.mdc** - Security guidelines and mandatory controls for secure deployment and operation of the SIEM platform.
- **setup.md** - Project setup instructions and implementation tasks for getting started with development.
- **tech_stack_document.mdc** - Technology stack documentation explaining technology choices, integrations, and infrastructure components.

---

## File Categories Summary

### Configuration Files (15 files)
Core configuration files for Docker Compose, environment variables, and service settings.

### Documentation Files (25 files)
Comprehensive documentation covering installation, security, troubleshooting, and integration guides.

### Scripts and Automation (18 files)
Setup scripts, configuration scripts, and automation tools for deployment and maintenance.

### Logstash Pipelines (8 files)
Data processing pipelines for parsing, enriching, and forwarding logs to Elasticsearch.

### Beats Configuration (6 files)
Configuration files for various Beat agents (Filebeat, Metricbeat, Heartbeat, Elastic Agent).

### Kibana Saved Objects (8 files)
Dashboard exports, visualizations, and index patterns for data analysis and visualization.

### Troubleshooting Resources (12 files)
Troubleshooting guides, reference data, and diagnostic tools for system maintenance.

### Project Rules (8 files)
Development guidelines, project rules, and architectural documentation for maintainers.

**Total Files Indexed: 100+ files**

This index provides a comprehensive overview of all files in the DShield-SIEM project, organized by directory and function for easy navigation and reference during development and maintenance activities. 