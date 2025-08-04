# DShield-SIEM Security Guidelines v2.0

This document outlines mandatory security controls and best practices for the design, deployment, and operation of the DShield-SIEM solution across all implementation phases. Adherence to these principles ensures confidentiality, integrity, and availability of security logs, analytics, and the overall Elastic Stack while protecting against honeypot compromise.

## 1. Security Architecture & Threat Model

### Primary Threats
*   **Honeypot Compromise**: Attackers gaining control of honeypot and pivoting to SIEM
*   **Data Exfiltration**: Unauthorized access to collected attack intelligence
*   **Log Poisoning**: Malicious log injection to hide attacks or cause DoS
*   **Credential Theft**: Compromise of API keys or service accounts
*   **Supply Chain**: Compromised dependencies or container images

### Security Zones
```
Internet ← [Honeypot] ← Firewall/NAT ← [Message Queue] ← [SIEM Core] ← [Analyst Access]
         Untrusted Zone            DMZ              Trusted Zone      Restricted Zone
```

### Phase-Specific Security Posture
*   **Phase 1.0**: Basic isolation via NAT, TLS encryption
*   **Phase 1.5**: Message queue isolation, service accounts
*   **Phase 2.0**: Full RBAC, network policies, multi-tenancy

## 2. Access Control & Authentication

### Service Account Architecture
```yaml
# Phase 1.0 (Transition from root)
elasticsearch_accounts:
  beats_writer:
    privileges: ["write:cowrie.dshield-*", "create_index:cowrie.dshield-*"]
  logstash_writer:
    privileges: ["write:*", "manage:enrichment-*"]
  mcp_reader:
    privileges: ["read:*", "monitor"]

# Phase 1.5+ (Full RBAC)
honeypot_identity:
  type: "certificate_based"
  privileges: ["write:queue_only"]
  
analyst_roles:
  junior_analyst:
    - read:cowrie.dshield-*
    - read:enrichment-*
    - create:saved_searches
  senior_analyst:
    - all_of:junior_analyst
    - write:enrichment-*
    - manage:alerts
    - execute:mcp_tools
  admin:
    - all_privileges
```

### Authentication Requirements
*   **Elasticsearch/Kibana**: Native realm with strong passwords
*   **Phase 2.0**: SSO integration with MFA requirement
*   **Honeypots**: Certificate-based authentication only
*   **API Keys**: Scoped, rotatable, with expiration dates
*   **MCP Access**: Tied to analyst credentials, audit logged

### Session Security
```yaml
kibana_config:
  xpack.security.session:
    idleTimeout: "30m"
    lifespan: "8h"
    cleanupInterval: "1h"
  xpack.security.sameSiteCookies: "Strict"
  xpack.security.secureCookies: true
```

## 3. Network Security & Encryption

### TLS Configuration
```yaml
# Minimum TLS 1.2, prefer 1.3
elasticsearch:
  xpack.security.transport.ssl:
    enabled: true
    verification_mode: certificate
    client_authentication: required
    supported_protocols: ["TLSv1.2", "TLSv1.3"]
    cipher_suites: 
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_AES_128_GCM_SHA256"
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"

# Certificate management
certificates:
  ca: "Dedicated CA for SIEM infrastructure"
  honeypot_certs: "Unique per honeypot, 1-year validity"
  service_certs: "90-day rotation for internal services"
```

### Network Segmentation
*   **Honeypot Network**: Isolated VLAN, egress only to message queue
*   **Message Queue**: DMZ placement, strict firewall rules
*   **SIEM Core**: Internal network, no direct internet access
*   **Management Network**: Separate for AWX/Ansible operations

### Firewall Rules
```
# Phase 1.0
Honeypot → SIEM: TCP/5044 (Beats), TCP/9200 (Elasticsearch)

# Phase 1.5+
Honeypot → Message Queue: TCP/443 (HTTPS API)
Message Queue → Logstash: TCP/6379 (Redis) or TCP/9092 (Kafka)
Logstash → Elasticsearch: TCP/9200
Analyst → Kibana: TCP/5601
MCP → Elasticsearch: TCP/9200 (localhost only in Phase 1.0)
```

## 4. Data Protection

### Encryption at Rest
*   **Elasticsearch data**: LUKS encryption on Docker volumes
*   **Phase 2.0**: Kubernetes encrypted storage classes
*   **Backup encryption**: AES-256 with separate key management
*   **Enrichment data**: Encrypted indices with field-level security

### Sensitive Data Handling
```yaml
logstash_filters:
  # PII Masking
  mutate:
    gsub: 
      - ["user.email", "^(.{3}).*@", "\1****@"]
      - ["source.ip", "(\d+\.\d+\.)\d+\.\d+", "\1***.**"]  # For specific indices
  
  # Password removal
  prune:
    whitelist_names: ["^(?!.*password).*"]
```

### Data Classification
*   **Public**: Aggregated statistics, sanitized reports
*   **Internal**: Raw honeypot logs, IP addresses
*   **Restricted**: Enrichment data, campaign analysis
*   **Confidential**: API keys, certificates, analyst queries

## 5. Secret Management

### Secret Storage Architecture
```yaml
# Modular backend configuration
secrets_backend:
  provider: "1password"  # or "vault", "azure_keyvault"
  config:
    vault_url: "{{ SECRETS_VAULT_URL }}"
    service_account: "dshield-siem"
    
required_secrets:
  - elastic_password
  - kibana_system_password
  - logstash_system_password
  - beats_writer_password
  - threat_intel_api_keys:
      - isc_api_key
      - virustotal_api_key
      - rosti_api_key
  - message_queue_credentials
  - honeypot_certificates
```

### Secret Rotation Policy
*   **API Keys**: 90-day rotation
*   **Service Passwords**: 180-day rotation
*   **Certificates**: 1-year for honeypots, 90-day for services
*   **Threat Intel Keys**: As required by provider
*   **Automated rotation via CI/CD pipeline**

## 6. Input Validation & Sanitization

### Logstash Pipeline Hardening
```ruby
filter {
  # Strict field validation
  if [source][ip] !~ /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/ {
    mutate {
      add_tag => ["invalid_source_ip"]
      remove_field => ["[source][ip]"]
    }
  }
  
  # Command injection prevention
  mutate {
    gsub => [
      "message", "[`$(){}<>]", "_",
      "user.name", "[^a-zA-Z0-9._-]", "_"
    ]
  }
  
  # Size limits
  truncate {
    fields => ["message", "event.original"]
    length_bytes => 10240  # 10KB max
  }
  
  # Drop suspicious events
  if [event][size] > 1048576 {  # 1MB
    drop { }
  }
}
```

### Grok Pattern Security
```ruby
# Use anchored patterns to prevent ReDoS
grok {
  patterns_dir => ["/etc/logstash/patterns"]
  match => {
    "message" => "^%{TIMESTAMP_ISO8601:timestamp} %{IP:source_ip} %{GREEDYDATA:remainder}$"
  }
  timeout_millis => 5000
  tag_on_timeout => ["_grok_timeout"]
}
```

## 7. Container Security

### Image Security
```dockerfile
# Base image pinning
FROM docker.elastic.co/elasticsearch/elasticsearch:8.11.1@sha256:specific_hash

# Non-root user
USER elasticsearch:elasticsearch

# Read-only root filesystem
# Specified in docker-compose.yml
```

### Docker Compose Hardening
```yaml
services:
  elasticsearch:
    image: elasticsearch:8.11.1
    user: "1000:1000"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp:size=50M,mode=1777
    volumes:
      - elastic-data:/usr/share/elasticsearch/data:rw
      - ./config:/usr/share/elasticsearch/config:ro
```

### Runtime Security
*   **Seccomp profiles**: Default Docker seccomp
*   **AppArmor/SELinux**: Enforce where available
*   **Resource limits**: Memory and CPU constraints
*   **Health checks**: Mandatory for all services

## 8. Monitoring & Incident Response

### Security Event Monitoring
```yaml
audit_configuration:
  elasticsearch:
    xpack.security.audit:
      enabled: true
      outputs: ["index"]
      events:
        include: ["authentication_failed", "access_denied", "run_as", "anonymous_access"]
      index:
        name: ".security-audit"
        rollover: "daily"

  application_logs:
    - failed_enrichment_attempts
    - mcp_query_patterns
    - configuration_changes
    - honeypot_health_status
```

### Incident Response Procedures

#### Honeypot Compromise
1. **Detect**: Unusual outbound connections, file modifications
2. **Isolate**: Network isolation via firewall rule
3. **Analyze**: Preserve honeypot state for forensics
4. **Rebuild**: Automated rebuild from Terraform/Ansible
5. **Update**: Rotate certificates, update firewall rules

#### SIEM Compromise
1. **Detect**: Unauthorized access, data exfiltration patterns
2. **Contain**: Disable compromised accounts
3. **Investigate**: Audit logs, query history
4. **Remediate**: Patch vulnerabilities, rotate all secrets
5. **Recover**: Restore from secure backups

### Alerting Rules
```yaml
security_alerts:
  honeypot_compromise:
    - outbound_connection_to_non_queue
    - filesystem_modification_outside_allowed
    - memory_dump_attempt
    
  authentication_anomaly:
    - failed_login_threshold: 5/minute
    - new_source_ip_for_service_account
    - certificate_expiration_warning: 30_days
    
  data_exfiltration:
    - large_query_result: >100MB
    - bulk_export_attempt
    - unusual_mcp_query_pattern
```

## 9. Compliance & Audit

### Audit Requirements
*   All configuration changes via Git commits
*   Query audit trail in `.audit-*` indices
*   Certificate lifecycle tracking
*   API key usage monitoring
*   Data retention compliance logging

### Compliance Mappings
*   **GDPR**: PII masking, right to deletion via frozen tier
*   **SOC2**: Access controls, encryption, audit trails
*   **CIS**: Container hardening, network segmentation
*   **NIST**: Continuous monitoring, incident response

## 10. Security Hardening Checklist

### Phase 1.0 Deployment
- [ ] Change all default passwords
- [ ] Enable TLS for all communications
- [ ] Configure firewall rules
- [ ] Set up basic Elasticsearch security
- [ ] Implement log rotation
- [ ] Create service accounts (prepare for Phase 1.5)
- [ ] Enable audit logging
- [ ] Configure secure cookies for Kibana
- [ ] Document all configurations in Git

### Phase 1.5 Migration
- [ ] Deploy message queue with TLS
- [ ] Migrate from root to service accounts
- [ ] Implement certificate-based honeypot auth
- [ ] Set up AWX/Ansible management
- [ ] Configure secret management backend
- [ ] Enable enrichment indices security
- [ ] Implement PII masking rules
- [ ] Update network segmentation
- [ ] Test disaster recovery procedures

### Phase 2.0 Preparation
- [ ] Design K8s network policies
- [ ] Plan multi-tenancy isolation
- [ ] Implement admission controllers
- [ ] Configure pod security policies
- [ ] Set up service mesh (optional)
- [ ] Enable mTLS everywhere
- [ ] Implement zero-trust networking
- [ ] Deploy runtime security monitoring

## 11. Security Maintenance

### Regular Tasks
*   **Daily**: Review security alerts, check honeypot health
*   **Weekly**: Analyze failed authentication attempts
*   **Monthly**: Rotate API keys, review access logs
*   **Quarterly**: Update threat intelligence feeds, security patches
*   **Annually**: Renew certificates, security architecture review

### Version Control Security
```yaml
git_security:
  - .gitignore: All secrets, certificates, sensitive configs
  - Pre-commit hooks: Secret scanning, syntax validation
  - Branch protection: Main branch requires reviews
  - Signed commits: GPG signing required for releases
```

By following these security guidelines, DShield-SIEM maintains defense in depth across all phases of implementation, protecting both the honeypot infrastructure and the valuable threat intelligence data collected.