# Project Requirements Document (PRD): DShield-SIEM v2.0

## 1. Project Overview

DShield-SIEM is a specialized Security Information and Event Management system built on the Elastic Stack (Elasticsearch, Logstash, Kibana, Beats). Its core purpose is to collect, parse, enrich, store, and visualize security logs—especially from DShield sensors including Cowrie honeypots, webhoneypots, firewall (iptables), and Zeek network monitors. By unifying diverse log types and integrating external threat intelligence feeds (ISC, Rosti, VirusTotal), it helps security analysts detect, investigate, and respond to incidents faster.

This system provides incident responders and network administrators a turnkey solution for threat hunting, real-time alerting, and long-tail analysis. Success will be measured by:

*   Timely ingestion and enrichment of DShield and related logs with preserved timestamps
*   Clear, interactive dashboards in Kibana that cover honeypot activity, network flows, and IOC matches
*   Intelligent alerting on patterns above "background radiation" noise levels
*   Ease of deployment via Docker Compose with migration path to K8s
*   Secure message queue isolation between honeypots and SIEM

## 2. Phased Implementation Strategy

### Phase 1.0: Docker Compose Foundation (Current)
**Maintains compatibility with professor's existing architecture**

*   Data ingestion from DShield sensors (Cowrie SSH/Telnet honeypot, webhoneypot), iptables, Zeek logs
*   Direct sensor-to-SIEM connection via NAT (Filebeat/Elastic Agent)
*   Log parsing and enrichment via Logstash pipelines (Grok, GeoIP, threat Intel lookups)
*   Threat intelligence integration: ISC IP Intel, Rosti Intel, VirusTotal API
*   Storage in single-node Elasticsearch with LogsDB mode and ILM
*   Prebuilt Kibana dashboards with version control via Git
*   Basic alerting rules focusing on anomalies above baseline
*   MCP server via stdio for single-analyst access
*   Containerized deployment using Docker + Docker Compose
*   Shell scripts for initial setup (certificate creation, index templates, dashboard import)

### Phase 1.5: Security Hardening & Automation (Next 3-6 months)
**Enhanced security and operational capabilities**

*   Message queue isolation (Cribl Stream/Edge, Confluent Kafka, or AWS Kinesis)
*   Service accounts with RBAC instead of root access
*   Automated honeypot deployment via Terraform/Ansible
*   AWX for centralized management (optional for advanced users)
*   Write-back capability for metadata enrichment
*   Separate enrichment indices with versioned workflows
*   Enhanced bulk data recovery with proper timestamp preservation

### Phase 2.0: Multi-User & Kubernetes Scale (6-12 months)
**Enterprise-ready features**

*   K8s/K3s deployment via Helm charts (maintaining Docker Compose compatibility)
*   MCP server over network sockets for multi-analyst support
*   Redis cache for ML enrichment functions
*   Integration with dsheild-mcp for enhanced analysis
*   MISP integration for threat intelligence sharing
*   Elastic enrichment processor pipelines
*   High-availability Elasticsearch cluster options

### Phase 3.0: Advanced Analytics (Future)
**Next-generation capabilities**

*   iPhone app for alerts and mobile dashboards
*   Deep packet capture with Arkime integration
*   Custom ML models via dshield-coordination-engine
*   Elastic Cloud deployment option
*   Cross-honeypot correlation and analysis
*   Automated threat hunting playbooks

## 3. User Flow

A security analyst logs into the Kibana web interface using their service account credentials. Upon landing, they see a home dashboard that summarizes the overall security posture, including event rates above baseline, top offending IPs, and recent alert history. From the left-hand menu, they navigate to the "Honeypot Activity" dashboard, which breaks down Cowrie SSH/Telnet login attempts, executed commands, and file transfer events. The analyst can click on any graph or table entry to drill into raw log details in the Discover view, using Kibana Query Language (KQL) to refine the search.

When investigating specific threats, the analyst opens their Claude/Cursor IDE with the DShield-MCP integration. The MCP server provides session-aware event streaming, automatically grouping related events and providing context about expected query latencies based on the data volume. The analyst can perform campaign analysis, correlating indicators across multiple honeypots and time periods.

For long-tail analysis, the analyst switches to the "Threat Intelligence" tab to review enriched IOC data—events are automatically enriched with data from ISC, VirusTotal, and custom enrichment indices. Critical alerts (patterns significantly above background radiation) appear in the Alerts panel with intelligent grouping to reduce noise.

## 4. Core Features

### Log Collection & Ingestion
*   **Phase 1.0**: Direct ingestion via Filebeat/Elastic Agent with NAT traversal
*   **Phase 1.5**: Message queue isolation (Cribl/Kafka/Kinesis) with configurable backends
*   Host and container metrics via Metricbeat
*   Uptime monitoring via Heartbeat
*   Secure TLS forwarding with certificate management
*   Automated timestamp normalization (sensor timezone → UTC)

### Log Processing & Enrichment
*   Logstash pipelines with modular configuration per log type
*   Intelligent field mapping (handles ECS and legacy field names)
*   GeoIP enrichment with MaxMind database updates
*   Threat intelligence lookups with caching:
    - ISC IP reputation (6-hour cache)
    - VirusTotal hash checks (365-day cache)
    - Rosti feed integration (12-hour cache)
*   Elastic enrichment processor for continuous enrichment
*   Preservation of original timestamps with ingestion time tracking

### Data Storage & Indexing
*   Elasticsearch with LogsDB mode for optimized log storage
*   Index patterns: `cowrie.dshield-*` with proper templates
*   ILM policies: Hot (90d) → Warm (90d) → Frozen (S3/Azure)
*   Separate enrichment indices with Git-versioned schemas
*   Runtime field mappings for flexible analysis
*   1-year enrichment cache for historical correlation

### Visualization & Analysis
*   Prebuilt dashboards covering:
    - Honeypot activity (SSH, web, commands)
    - Network flows and connections
    - Geographic attack distribution
    - IOC matches and threat intelligence
    - Campaign timelines and correlations
*   Custom visualizations with consistent design language
*   Discover view with saved searches
*   Dashboard versioning via Git with migration scripts

### Threat Detection & Alerting
*   Intelligent baseline detection (background radiation filtering)
*   IOC-based rules with confidence scoring
*   Behavioral anomaly detection:
    - Unusual command sequences
    - Atypical geographic patterns
    - Session-based attack correlation
*   Multi-channel alerting (email, webhook, future iPhone app)
*   Alert suppression and deduplication

### MCP Integration & Analysis
*   Session-aware event streaming with intelligent chunking
*   Campaign analysis with multi-stage correlation
*   Performance optimization for large datasets
*   Query complexity estimation and fallback strategies
*   LaTeX report generation for formal documentation
*   Comprehensive threat intelligence correlation

### Deployment & Management
*   Docker Compose for easy deployment
*   Kubernetes-ready architecture (Helm charts in Phase 2.0)
*   Automated setup scripts with error handling
*   Secret management integration (1Password, Vault, Azure Key Vault)
*   Certificate generation and rotation
*   Bulk data import with timestamp preservation
*   Disaster recovery procedures

## 5. Technical Architecture

### Data Pipeline Options

#### Phase 1.0 (Current)
```
Honeypot → Filebeat/Agent → [NAT] → Elasticsearch → Kibana
                                ↓
                            Logstash
                                ↓
                          Enrichment
```

#### Phase 1.5 (Message Queue)
```
Honeypot → Filebeat → Message Queue → Logstash → Elasticsearch
                     (Choose one:)        ↓          ↓
                     - Cribl Stream   Enrichment   Kibana
                     - Cribl Edge
                     - Confluent
                     - Kinesis
```

### Message Queue Comparison
| Solution | Cost Model | Pros | Cons |
|----------|------------|------|------|
| Cribl Edge | $0.21/GB | Familiar, powerful transforms | Requires edge agents |
| Cribl Stream | $0.32/GB | Cloud-native, full features | Slightly higher cost |
| Confluent | $0.05/GB | Cost-effective, Kafka ecosystem | More complex setup |
| AWS Kinesis | Pay-per-shard | AWS integration, serverless | AWS lock-in |

### Index Structure
*   **Event indices**: `cowrie.dshield-YYYY.MM.DD` (LogsDB mode)
*   **Enrichment indices**: `enrichment-ip-*`, `enrichment-hash-*`
*   **Campaign indices**: `campaigns-*` (Phase 2.0)
*   **Alert indices**: `.alerts-security-*`

### Field Mapping Strategy
Supports multiple field name formats via intelligent mapping:
- ECS standard: `source.ip`, `destination.port`
- Legacy formats: `src_ip`, `dst_port`, `sourceip`
- Runtime field resolution for flexibility

## 6. Non-Functional Requirements

### Performance
*   **Ingestion**: 100-200 events/sec sustained per honeypot
*   **Burst capacity**: 500 events/sec for 30 seconds
*   **Query latency**: Varies by complexity (MCP provides expectations)
*   **Dashboard load**: < 3 seconds for standard views
*   **Enrichment**: Real-time for IPs, cached for hashes

### Scalability
*   **Phase 1.0**: Single-node up to 10 honeypots (~650GB/year)
*   **Phase 2.0**: Horizontal scaling via K8s
*   **Data retention**: 90 days hot, 90 days warm, unlimited frozen
*   **Resource estimation**: ~65GB/year per honeypot + 20% enrichment

### Security
*   TLS 1.2+ for all communications
*   Service accounts with minimal privileges (no root in Phase 1.5+)
*   Message queue isolation prevents honeypot → SIEM compromise
*   Certificate-based authentication for honeypots
*   Secrets in external managers (never in config files)

### Reliability & Availability
*   Docker Compose auto-restart policies
*   Health checks at all layers
*   Message queue buffering for connection failures
*   Automated backup of raw logs for disaster recovery
*   99.5% uptime target for Phase 1.0

### Compliance & Privacy
*   90-day hot retention for active investigation
*   180-day warm retention for correlation
*   Frozen tier for long-term compliance
*   PII masking capabilities for GDPR compliance
*   Audit logging for all configuration changes

## 7. Constraints & Assumptions

*   **Phase 1.0**: Single-node Elasticsearch acceptable for <10 honeypots
*   Docker and Docker Compose available on deployment hosts
*   Threat intelligence APIs require valid keys with rate limits
*   Analysts familiar with basic Kibana and KQL usage
*   UTC timezone standardization across all components
*   Git available for version control of configurations

## 8. Testing Strategy

### Unit Tests (75% coverage target)
*   Python components (pytest)
*   Logstash pipeline tests
*   Enrichment logic validation

### Integration Tests
*   Docker Compose test stack
*   Synthetic honeypot data generators
*   End-to-end data flow validation
*   Timestamp preservation verification

### Performance Tests
*   Load testing with realistic event rates
*   Query performance benchmarks
*   Resource utilization monitoring

### CI/CD Pipeline
*   GitHub Actions for automated testing
*   Container image building and scanning
*   Configuration validation
*   Dashboard syntax checking

## 9. Success Metrics

*   **Data Quality**: 100% timestamp preservation accuracy
*   **Enrichment**: 90%+ cache hit rate for threat intelligence
*   **Performance**: <5 minute end-to-end latency for alerting
*   **Reliability**: <1% data loss during normal operations
*   **Usability**: Analysts can identify campaigns within 15 minutes
*   **Automation**: 80% reduction in manual honeypot management

## 10. Risk Mitigation

### API Rate Limits
*   Intelligent caching with TTLs based on data volatility
*   Exponential backoff for retries
*   Local enrichment database fallback

### Honeypot Compromise
*   Message queue isolation (Phase 1.5)
*   Read-only honeypot credentials
*   Automated rebuild procedures
*   Network segmentation

### Data Volume Growth
*   ILM policies with automatic rollover
*   Frozen tier for cost-effective long-term storage
*   Aggregation fallback for massive queries
*   Smart query optimization in MCP

### Configuration Drift
*   Git-based configuration management
*   Automated deployment scripts
*   Version pinning for all components
*   Regular configuration audits

This PRD provides a clear evolution path from the current single-node deployment to a scalable, secure, multi-analyst platform while maintaining backward compatibility and professor collaboration.