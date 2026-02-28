# Secure Architecture Design & Threat Modeling Report
## Online Payment Processing Application

---

**Course:** Cyber Security  
**Assignment:** 1 — Secure Architecture Design & Threat Modeling  
**Scenario Chosen:** Option A — Online Payment Processing Application  
**Date:** February 2026  

---

## Table of Contents

1. [System Definition and Architecture](#task-1-system-definition-and-architecture)
2. [Asset Identification and Security Objectives](#task-2-asset-identification-and-security-objectives)
3. [Threat Modeling (STRIDE)](#task-3-threat-modeling)
4. [Secure Architecture Design](#task-4-secure-architecture-design)
5. [Risk Treatment and Residual Risk](#task-5-risk-treatment-and-residual-risk)
6. [Final Architecture and Threat Report Summary](#task-6-final-architecture-and-threat-report)

---

## Task 1: System Definition and Architecture

### 1.1 Scenario Overview

The system under analysis is an **Online Payment Processing Application** — a full-stack financial platform enabling end-users (customers) to make purchases, merchants to accept payments, and administrators to manage operations. The system integrates with a **Core Banking System (CBS)** and a **third-party Payment Gateway** to facilitate the movement of real money between accounts.

This type of system is a high-value target due to the financial assets it handles, the personally identifiable information (PII) it stores, and its internet-facing exposure. A breach could lead to direct financial loss, regulatory penalties (PCI-DSS, GDPR), and severe reputational damage.

---

### 1.2 Application Components

| Component | Description |
|-----------|-------------|
| **Web Frontend** | React-based single-page application (SPA) accessible via browser over HTTPS. Serves the customer-facing payment and account management interface. |
| **Admin Portal** | Separate web interface accessible only from trusted IP ranges. Used by internal staff for operations, refunds, and fraud review. |
| **API Backend (Gateway Layer)** | RESTful API gateway that authenticates requests, enforces rate limiting, and routes calls to internal microservices. |
| **Payment Service** | Microservice responsible for initiating, processing, and recording payment transactions. |
| **User Service** | Manages user registration, authentication, session management, and profile data. |
| **Merchant Service** | Manages merchant onboarding, credentials, and routing rules. |
| **Notification Service** | Sends email/SMS confirmations for transactions. |
| **User Database** | PostgreSQL database storing hashed credentials, profiles, and account metadata. |
| **Merchant Database** | Separate PostgreSQL database storing merchant profiles, API keys, and settlement details. |
| **Transaction Ledger** | Append-only database recording all financial transactions. |
| **Payment Gateway (External)** | Third-party HTTPS API (e.g., Stripe-like interface) for card processing and acquiring. |
| **Core Banking System (CBS)** | Internal system managing bank accounts, balances, and fund transfers via a secure internal API. |
| **Logging & SIEM** | Centralized log aggregation and Security Information and Event Management system. |
| **Secrets Manager** | Vault-like service for storing API keys, DB credentials, certificates, and encryption keys. |

---

### 1.3 Users and Roles

| Actor | Description | Access Level |
|-------|-------------|--------------|
| **Customer** | End-user making payments via the web frontend | Low privilege — own data only |
| **Merchant** | Business entity receiving payments via Merchant API | Medium privilege — own merchant data |
| **Payment Processor** | Automated role used by the Payment Service to call the Payment Gateway | Service account — restricted |
| **System Administrator** | IT staff managing infrastructure and deployments | High privilege — infrastructure only |
| **Application Administrator** | Business operations staff managing merchants, refunds | High privilege — application data |
| **Fraud Analyst** | Reviews flagged transactions (read-only) | Medium privilege — transaction data, read-only |
| **Auditor** | Reviews logs and compliance reports | Low-medium — read-only logs |
| **External Payment Gateway** | Third-party service receiving payment initiation requests | External, authenticated by API keys |
| **Core Banking System** | Internal bank backend receiving fund transfer requests | Internal, mTLS authenticated |

---

### 1.4 Data Types Handled

| Data Category | Examples | Sensitivity |
|---------------|----------|-------------|
| **Authentication Credentials** | Passwords (hashed), session tokens, OTP codes | Critical |
| **Personal Identifiable Information (PII)** | Name, email, phone, address | High |
| **Payment Card Data** | Card numbers (PAN), CVV, expiry (tokenized) | Critical (PCI-DSS scope) |
| **Bank Account Information** | IBAN, account numbers, routing numbers | Critical |
| **Transaction Records** | Amount, timestamp, merchant, status | High |
| **Merchant Credentials** | API keys, webhook secrets | High |
| **Application Secrets** | DB passwords, encryption keys, certificates | Critical |
| **Audit Logs** | Access logs, transaction logs, error logs | Medium-High |
| **Business Logic Data** | Fraud rules, fee schedules, routing tables | High (confidential) |

---

### 1.5 External Dependencies

| Dependency | Type | Purpose | Risk |
|------------|------|---------|------|
| **Payment Gateway API** | External HTTPS | Card processing | Supply chain risk; third-party breach |
| **Core Banking System** | Internal network | Fund settlement | Single point of failure; insider threat |
| **Email/SMS Provider** | External API | Notifications | Account enumeration via delivery failures |
| **DNS Provider** | External | Name resolution | DNS hijacking |
| **CA/TLS Certificates** | External | Encrypted transport | Certificate compromise |
| **Identity Provider (Optional)** | External OIDC/SAML | SSO for admin | Identity federation risks |

---

### 1.6 Trust Boundaries

Trust boundaries define where data crosses from one zone of different trust levels to another. Each boundary crossing must be authenticated, authorized, and encrypted.

```
+----------------------------------------------------------+
|                    INTERNET (Untrusted)                   |
|                                                          |
|   [Customer Browser]          [Merchant API Client]      |
+----------------------------+-----------------------------+
             |                            |
         HTTPS/TLS                    HTTPS/TLS + API Key
             |                            |
+------------v----------------------------v---------------+
|                     DMZ Zone                           |
|   [WAF / DDoS Protection]   [API Rate Limiter]        |
|   [Load Balancer / TLS Termination]                   |
+---+------------------------------------+---------------+
    |  Internal API Call (JWT validated) |
    |                                    |
+---v------------------------------------v---------------+
|              Application Zone (Internal)              |
|                                                       |
|  [API Backend]  [User Svc]  [Payment Svc]            |
|  [Merchant Svc] [Notification Svc]                   |
+---+-----------------------+---------------------------+
    |                       |
    |  Encrypted DB Conn    |  Internal mTLS
    |                       |
+---v-----------+   +------v---------+
|  Data Zone    |   |  Banking Zone  |
|  [User DB]    |   |  [CBS API]     |
|  [Merchant DB]|   +----------------+
|  [Txn Ledger] |
+---------------+
         |
         | (External call, HTTPS + mTLS)
         |
+--------v--------+
|  External Zone  |
|  [Payment GW]   |
+-----------------+
         ^
         |
+--------+--------+
|  Admin Zone     |
|  [Admin Portal] |
|  [SIEM/Logs]    |
|  [Secrets Mgr]  |
+-----------------+
```

**Trust Boundaries Identified:**

| Boundary | From | To | Controls Required |
|---------|------|----|------------------|
| TB-1 | Internet | DMZ | WAF, DDoS protection, TLS |
| TB-2 | DMZ | Application Zone | JWT/OAuth 2.0 validation, internal firewall |
| TB-3 | Application Zone | Data Zone | Encrypted connections, DB auth, principle of least privilege |
| TB-4 | Application Zone | External Payment Gateway | mTLS, API key, IP allowlist |
| TB-5 | Application Zone | Core Banking System | mTLS, service accounts, audit logging |
| TB-6 | Admin Network | Application/Data Zone | VPN/Zero Trust, MFA, privileged access |

---

## Task 2: Asset Identification and Security Objectives

### 2.1 Asset Inventory

| Asset ID | Asset Name | Category | Location | Owner | Criticality |
|----------|-----------|---------|---------|-------|------------|
| A-01 | Customer Authentication Credentials | Data | User Database | Security Team | Critical |
| A-02 | Payment Card Data (tokenized) | Data | Payment Gateway / Vault | Compliance Team | Critical |
| A-03 | Customer PII | Data | User Database | Privacy Officer | High |
| A-04 | Transaction Records | Data | Transaction Ledger | Finance Team | High |
| A-05 | Merchant API Keys | Data | Secrets Manager | Merchant Services | High |
| A-06 | Encryption Keys & Certificates | Data | Secrets Manager / HSM | Security Team | Critical |
| A-07 | Application Source Code | Software | Code Repository | Dev Team | High |
| A-08 | API Backend Service | Software | Application Zone | DevOps | Critical |
| A-09 | Payment Microservice | Software | Application Zone | DevOps | Critical |
| A-10 | Admin Portal | Software | Admin Zone | Operations | High |
| A-11 | Core Banking System Integration | System | Banking Zone | IT Operations | Critical |
| A-12 | SIEM & Audit Logs | Data/System | Logging Zone | SOC | High |
| A-13 | Fraud Detection Rules | Data | Payment Service | Risk Team | High |
| A-14 | Merchant Business Data | Data | Merchant DB | Finance Team | High |
| A-15 | System Infrastructure (servers, network) | Hardware/Infra | Data Center | IT Operations | High |

---

### 2.2 Security Objectives Mapping

| Asset ID | Asset Name | Confidentiality | Integrity | Availability | Accountability |
|----------|-----------|:-:|:-:|:-:|:-:|
| A-01 | Customer Credentials | ★★★ Critical | ★★★ Critical | ★★ High | ★★★ Critical |
| A-02 | Payment Card Data | ★★★ Critical | ★★★ Critical | ★★ High | ★★★ Critical |
| A-03 | Customer PII | ★★★ Critical | ★★ High | ★★ High | ★★ High |
| A-04 | Transaction Records | ★★ High | ★★★ Critical | ★★★ Critical | ★★★ Critical |
| A-05 | Merchant API Keys | ★★★ Critical | ★★★ Critical | ★★ High | ★★ High |
| A-06 | Encryption Keys | ★★★ Critical | ★★★ Critical | ★★ High | ★★★ Critical |
| A-07 | Source Code | ★★ High | ★★★ Critical | ★ Medium | ★★ High |
| A-08 | API Backend | ★★ High | ★★★ Critical | ★★★ Critical | ★★★ Critical |
| A-09 | Payment Microservice | ★★ High | ★★★ Critical | ★★★ Critical | ★★★ Critical |
| A-10 | Admin Portal | ★★★ Critical | ★★★ Critical | ★★ High | ★★★ Critical |
| A-11 | CBS Integration | ★★★ Critical | ★★★ Critical | ★★★ Critical | ★★★ Critical |
| A-12 | Audit Logs | ★★ High | ★★★ Critical | ★★ High | ★★★ Critical |
| A-13 | Fraud Rules | ★★ High | ★★★ Critical | ★★ High | ★★ High |
| A-14 | Merchant Business Data | ★★ High | ★★ High | ★★ High | ★★ High |
| A-15 | Infrastructure | ★★ High | ★★★ Critical | ★★★ Critical | ★★★ Critical |

**Legend:** ★★★ Critical | ★★ High | ★ Medium

---

### 2.3 Definitions of Security Objectives

- **Confidentiality:** Ensuring that sensitive data is accessible only to authorized entities. Critical for PII, card data, and credentials.
- **Integrity:** Ensuring that data is accurate and has not been tampered with. Critical for financial transactions (an attacker modifying transaction amounts could cause massive financial loss).
- **Availability:** Ensuring services are operational when needed. Critical for the payment infrastructure (downtime = direct revenue loss and merchant SLA breaches).
- **Accountability:** Ensuring all actions can be traced to an authenticated identity. Essential for forensic investigation, compliance, and fraud detection.

---

## Task 3: Threat Modeling

### 3.1 Methodology: STRIDE

The **STRIDE** framework categorizes threats into six types:

| Letter | Threat Type | Violated Property |
|--------|------------|------------------|
| **S** | Spoofing | Authentication |
| **T** | Tampering | Integrity |
| **R** | Repudiation | Non-repudiation |
| **I** | Information Disclosure | Confidentiality |
| **D** | Denial of Service | Availability |
| **E** | Elevation of Privilege | Authorization |

---

### 3.2 Threat Model Table

#### Authentication Threats

| Threat ID | STRIDE | Threat Description | Affected Component | Impact | Risk Level |
|-----------|--------|-------------------|--------------------|--------|-----------|
| T-AUTH-01 | **S** | **Credential Stuffing / Brute Force** — Attacker uses leaked credential lists to automatically attempt login to customer accounts, exploiting weak or reused passwords. | Web Frontend → User Service → User DB | Account takeover, unauthorized purchases, financial loss to customers | **HIGH** |
| T-AUTH-02 | **S** | **Session Token Hijacking** — Attacker intercepts or steals session tokens via network sniffing, XSS, or CSRF to impersonate an authenticated user. | Web Frontend, API Backend | Full account takeover, unauthorized transactions | **HIGH** |
| T-AUTH-03 | **S** | **API Key Compromise for Merchants** — Merchant API keys are exposed through unsecured repositories, logs, or misconfigured environments, allowing an attacker to impersonate a legitimate merchant. | Merchant Service, API Backend | Fraudulent transactions under merchant identity, financial loss | **HIGH** |
| T-AUTH-04 | **S** | **Admin Portal Impersonation** — Attacker compromises admin credentials (via phishing, password spray) and gains access to the admin portal to approve fraudulent refunds or alter transaction records. | Admin Portal | Mass financial loss, data manipulation, regulatory breach | **CRITICAL** |
| T-AUTH-05 | **E** | **JWT Token Forgery** — Attacker exploits weak JWT signing (e.g., `alg:none` or weak secret) to forge tokens with elevated privileges. | API Backend | Unauthorized access to any user account or admin functions | **HIGH** |

#### Authorization Threats

| Threat ID | STRIDE | Threat Description | Affected Component | Impact | Risk Level |
|-----------|--------|-------------------|--------------------|--------|-----------|
| T-AUTHZ-01 | **E** | **Insecure Direct Object Reference (IDOR)** — A customer manipulates API parameters (e.g., changing `user_id` in requests) to access another customer's transaction history or account data. | API Backend, User Service | Privacy breach, financial data exposure | **HIGH** |
| T-AUTHZ-02 | **E** | **Privilege Escalation — Internal** — A customer-level user exploits a logic flaw in the API to gain merchant or admin-level permissions. | API Backend, User Service | Full system compromise depending on escalation level | **HIGH** |
| T-AUTHZ-03 | **E** | **Fraud Analyst Accessing Sensitive Controls** — Due to misconfigured RBAC, a read-only fraud analyst role gains write access to transaction or fraud rule systems. | Admin Portal, Payment Service | Corruption of fraud rules, enabling fraudulent transactions | **MEDIUM** |
| T-AUTHZ-04 | **E** | **Rogue Service Account** — An internal microservice's compromised service account is used to access data outside its authorization scope (e.g., Payment Service reading User DB directly). | Application Zone, Data Zone | Lateral movement, data exfiltration | **HIGH** |

#### Data Storage Threats

| Threat ID | STRIDE | Threat Description | Affected Component | Impact | Risk Level |
|-----------|--------|-------------------|--------------------|--------|-----------|
| T-DATA-01 | **I** | **Database SQL Injection / Exfiltration** — Attacker injects SQL via unsanitized API input to read, modify, or delete records in the User or Merchant Database. | API Backend, User DB, Merchant DB | Mass PII and credential exfiltration, PCI-DSS violation | **HIGH** |
| T-DATA-02 | **I** | **Unencrypted Data at Rest** — Sensitive data (PII, card tokens, credentials) stored without encryption. Physical or logical DB access leads to full compromise. | User DB, Merchant DB, Transaction Ledger | Total data breach, regulatory fines | **HIGH** |
| T-DATA-03 | **T** | **Transaction Record Tampering** — An insider or attacker with DB write access alters transaction records to cover up fraud, change amounts, or falsify payment status. | Transaction Ledger | Financial fraud, audit failure, regulatory breach | **CRITICAL** |
| T-DATA-04 | **I** | **Backup Exfiltration** — Database backups stored without encryption or in insecure locations are exfiltrated. | Backup Storage | Equivalent to a full database breach | **HIGH** |
| T-DATA-05 | **I** | **Secrets Leaked in Logs** — Application logs inadvertently capture API keys, passwords, or card data in plaintext. | Logging System, Application Zone | Credential exposure, PCI-DSS violations | **HIGH** |

#### API Communication Threats

| Threat ID | STRIDE | Threat Description | Affected Component | Impact | Risk Level |
|-----------|--------|-------------------|--------------------|--------|-----------|
| T-API-01 | **I** | **Man-in-the-Middle (MitM) Attack** — Attacker intercepts unencrypted or weakly encrypted API communication between components to steal credential or card data in transit. | All API connections | Data theft in transit, credential compromise | **HIGH** |
| T-API-02 | **T** | **API Parameter Tampering** — Attacker modifies API request parameters (e.g., changing transaction amount from 1000 to 1) between the frontend and the payment service. | API Backend, Payment Service | Direct financial loss | **HIGH** |
| T-API-03 | **D** | **API Abuse / Rate Limit Bypass** — Attacker floods the API with requests (DDoS) or systematically abuses endpoints (e.g., OTP brute force, card testing) to cause service degradation or fraudulent card verification. | API Gateway, Payment Service | Service outage, fraudulent card testing, financial loss | **HIGH** |
| T-API-04 | **S** | **Payment Gateway Callback Spoofing** — Attacker sends a forged payment success callback to the API Backend, causing the system to mark a transaction as paid when payment was not completed. | API Backend, Payment Service | Financial fraud (goods/services obtained without payment) | **CRITICAL** |
| T-API-05 | **I** | **Insecure Third-party Integration** — The Payment Gateway or CBS integration uses http instead of https, or does not validate the server certificate, enabling interception. | Payment Service, CBS Integration | Data interception, financial data exposure | **MEDIUM** |

#### Logging and Monitoring Threats

| Threat ID | STRIDE | Threat Description | Affected Component | Impact | Risk Level |
|-----------|--------|-------------------|--------------------|--------|-----------|
| T-LOG-01 | **R** | **Log Tampering / Deletion** — An attacker or malicious insider with access to the logging system deletes or modifies audit logs to cover fraudulent activity. | SIEM, Log Storage | Loss of forensic evidence, compliance failure, audit failure | **HIGH** |
| T-LOG-02 | **R** | **Insufficient Logging** — Critical events (failed logins, privilege changes, large transactions) are not logged, making it impossible to detect or investigate attacks. | Application Zone, Admin Portal | Delayed attack detection, poor incident response | **HIGH** |
| T-LOG-03 | **D** | **Log Flooding** — Attacker generates massive volumes of log events to overwhelm the SIEM, causing genuine alerts to be missed or log storage to fill up. | SIEM, Log Storage | Alert fatigue, missed intrusions | **MEDIUM** |
| T-LOG-04 | **I** | **Log Data Exposure** — SIEM or log access is improperly controlled, allowing unauthorized users to read sensitive log data containing business intelligence or partial credentials. | SIEM | Intelligence gathering for follow-on attacks | **MEDIUM** |

#### Administrative Access Threats

| Threat ID | STRIDE | Threat Description | Affected Component | Impact | Risk Level |
|-----------|--------|-------------------|--------------------|--------|-----------|
| T-ADMIN-01 | **E** | **Admin Privilege Abuse (Insider Threat)** — A malicious or coerced administrator uses their legitimate high-privilege access to approve unauthorized refunds, exfiltrate data, or disable security controls. | Admin Portal, User DB, Transaction Ledger | Significant financial loss, data breach, regulatory exposure | **CRITICAL** |
| T-ADMIN-02 | **S** | **Phishing of Admin Credentials** — Admin users receive a targeted spear-phishing email to steal credentials or deploy malware on their workstation, enabling admin portal access. | Admin Portal | Complete admin-level compromise | **HIGH** |
| T-ADMIN-03 | **E** | **Unprotected Admin Endpoint** — The admin portal is exposed on the public internet without proper access controls (e.g., no IP restriction, no MFA), making it a target for unauthorized access. | Admin Portal | Full compromise of admin functions | **HIGH** |
| T-ADMIN-04 | **T** | **Unauthorized Configuration Change** — A compromised or rogue admin modifies fraud detection thresholds, routing rules, or user permissions to facilitate fraud. | Admin Portal, Payment Service | Systematic fraud enablement | **HIGH** |
| T-ADMIN-05 | **R** | **Admin Action Repudiation** — Administrator denies performing certain privileged actions due to insufficient audit logging on the admin portal. | Admin Portal, SIEM | Accountability failure, legal / compliance risk | **MEDIUM** |

---

### 3.3 Threat Diagram (Annotated Architecture)

```
                         ╔══════════════════════════════╗
                         ║        INTERNET ZONE         ║
                         ║  [T-AUTH-01][T-API-03]       ║
                         ║    Customer   Merchant       ║
                         ╚══════════╤══════════╤════════╝
                                    │ HTTPS    │ HTTPS+APIKey
                    ╔═══════════════v══════════v══════════════╗
                    ║              DMZ ZONE                   ║
                    ║  [WAF]←[T-API-03]  [LoadBalancer]      ║
                    ║  [T-API-01: MitM risk at boundary]      ║
                    ╚═══════════════╤═════════════════════════╝
                                    │ JWT-validated internal call
              ╔═════════════════════v═══════════════════════════════╗
              ║              APPLICATION ZONE                       ║
              ║                                                     ║
              ║  [API Backend]    ←——[T-AUTH-05: JWT Forgery]      ║
              ║       │                                             ║
              ║  ┌────┴──────────────────────────────────┐        ║
              ║  │ User Svc    Payment Svc  Merchant Svc  │        ║
              ║  │ [T-AUTHZ-01]  [T-API-02][T-API-04]   │        ║
              ║  │ [T-AUTHZ-02]  [T-DATA-03]             │        ║
              ║  └────┬──────────────────────────────────┘        ║
              ╚═══════╪════════════════════════════════════════════╝
                      │  Encrypted DB connections
        ╔═════════════v══════════════════╗
        ║          DATA ZONE             ║
        ║  [UserDB]  [MerchantDB]       ║
        ║  [Txn Ledger] [Backups]       ║
        ║  [T-DATA-01][T-DATA-02]       ║
        ║  [T-DATA-03][T-DATA-04]       ║
        ╚══════════════════════╤=========╝
                               │
        ╔══════════════════════v══════════════╗
        ║         EXTERNAL ZONE               ║
        ║  [Payment Gateway] ←[T-API-04]     ║
        ║  [CBS API]         ←[T-AUTH-03]    ║
        ╚═════════════════════════════════════╝

        ╔══════════════════════════════════════╗
        ║           ADMIN ZONE                 ║
        ║  [Admin Portal] ←[T-ADMIN-01,02,03] ║
        ║  [SIEM] ←[T-LOG-01][T-LOG-02]      ║
        ║  [Secrets Manager]                   ║
        ╚══════════════════════════════════════╝
```

---

### 3.4 Risk Summary

| Risk Level | Count | Threat IDs |
|-----------|-------|------------|
| **Critical** | 4 | T-AUTH-04, T-DATA-03, T-API-04, T-ADMIN-01 |
| **High** | 17 | T-AUTH-01, T-AUTH-02, T-AUTH-03, T-AUTH-05, T-AUTHZ-01, T-AUTHZ-02, T-AUTHZ-04, T-DATA-01, T-DATA-02, T-DATA-04, T-DATA-05, T-API-01, T-API-02, T-API-03, T-LOG-01, T-LOG-02, T-ADMIN-02, T-ADMIN-03, T-ADMIN-04 |
| **Medium** | 5 | T-AUTHZ-03, T-API-05, T-LOG-03, T-LOG-04, T-ADMIN-05 |

---

## Task 4: Secure Architecture Design

### 4.1 Architectural Security Controls Overview

The following controls are proposed at an **architectural level** — these are design decisions, not code-level fixes. Each control addresses one or more identified threats.

---

### 4.2 Identity and Access Management (IAM)

#### Control IAM-01: Multi-Factor Authentication (MFA) for All Human Access
- **Applies to:** Customer login, Admin Portal, Fraud Analyst access
- **Addresses:** T-AUTH-01, T-AUTH-04, T-ADMIN-02
- **Justification:** Credential stuffing and phishing attacks are defeated by MFA because stolen passwords alone are insufficient. Time-based OTP (TOTP) or hardware security keys (FIDO2/WebAuthn) should be mandatory for admin roles. Customers should be required to use MFA for high-value transactions.

#### Control IAM-02: OAuth 2.0 / OpenID Connect for API Authentication
- **Applies to:** All API endpoints, Merchant API, Customer sessions
- **Addresses:** T-AUTH-02, T-AUTH-05, T-AUTH-03
- **Justification:** Standardized, audited authentication protocols reduce the risk of implementation errors. Short-lived JWT access tokens (≤15 min expiry) with refresh token rotation ensure that stolen tokens have a narrow window of usability. JWT tokens must be signed with RS256 (asymmetric) or ES256, never with HS256 using a weak secret, and the `alg: none` vulnerability must be explicitly rejected.

#### Control IAM-03: Role-Based Access Control (RBAC) with Least Privilege
- **Applies to:** All services, Admin Portal, Fraud Analyst portal
- **Addresses:** T-AUTHZ-01, T-AUTHZ-02, T-AUTHZ-03, T-AUTHZ-04
- **Justification:** Each role receives only the minimum permissions necessary. Service accounts for microservices are scoped to the specific database tables they need. The Payment Microservice, for example, can write to the Transaction Ledger but cannot read the User Database. RBAC policies must be audited quarterly.

#### Control IAM-04: Privileged Access Management (PAM) for Admin Operations
- **Applies to:** Admin Portal
- **Addresses:** T-ADMIN-01, T-ADMIN-02, T-ADMIN-03
- **Justification:** Admin access must be gated through a PAM solution with just-in-time (JIT) access provisioning — admins request access for specific tasks, and it expires automatically. All admin sessions are recorded. The Admin Portal is not accessible from the public internet; access requires VPN + MFA.

#### Control IAM-05: Merchant API Key Management
- **Applies to:** Merchant Service, API Backend
- **Addresses:** T-AUTH-03, T-DATA-05
- **Justification:** Merchant API keys must be stored only in the Secrets Manager, never in application logs, source code, or environment variables. Keys should support rotation without downtime. The API Gateway validates keys before routing to the merchant service.

---

### 4.3 Network Segmentation

#### Control NET-01: DMZ Zone with WAF and DDoS Protection
- **Applies to:** All internet-facing endpoints
- **Addresses:** T-API-03, T-AUTH-01, T-API-01
- **Justification:** A Web Application Firewall (WAF) at the perimeter filters common attack patterns (SQLi, XSS, OWASP Top 10). A DDoS mitigation layer (using anycast + rate limiting) prevents volumetric attacks from degrading service. TLS termination at the load balancer with modern cipher suites (TLS 1.3, ECDHE) ensures all traffic is encrypted in transit.

#### Control NET-02: Network Micro-segmentation Between Zones
- **Applies to:** All internal network communication
- **Addresses:** T-AUTHZ-04, T-ADMIN-03, T-API-05
- **Justification:** Each application zone (DMZ, Application, Data, Admin, External) is placed in a separate network segment with strict firewall rules. No zone can communicate with another unless explicitly allowed by policy. For example, the User Database is only reachable from the User Service, not from the Payment Service. This limits the blast radius of any single component compromise.

#### Control NET-03: Separate Admin Network Plane
- **Applies to:** Admin Portal
- **Addresses:** T-ADMIN-03, T-ADMIN-01
- **Justification:** Completely separating the admin network from the user-facing internet prevents credential stuffing attackers from even reaching the admin login page. Admin access is only available via a zero-trust VPN that enforces device health checks and MFA.

---

### 4.4 Data Protection

#### Control DATA-01: Encryption at Rest for All Sensitive Data
- **Applies to:** User DB, Merchant DB, Transaction Ledger, Backups
- **Addresses:** T-DATA-01, T-DATA-02, T-DATA-04
- **Justification:** All database storage must use AES-256 encryption at rest. Database passwords are hashed with **bcrypt** (cost factor ≥12) or **Argon2id**. Full disk encryption on database servers protects against physical access attacks. Backup files are encrypted with separate keys before storage and verified periodically.

#### Control DATA-02: Tokenization of Payment Card Data (PCI-DSS Compliance)
- **Applies to:** Payment Service, User DB
- **Addresses:** T-DATA-01, T-DATA-02 (for card data specifically)
- **Justification:** Raw card data (PAN, CVV) is **never** stored in the application databases. When a card is provided, it is immediately sent to the Payment Gateway for tokenization. The application stores only the returned token. This dramatically reduces PCI-DSS scope and eliminates the highest-sensitivity data from internal systems.

#### Control DATA-03: Data in Transit Encryption with Certificate Pinning
- **Applies to:** All API communication, internal microservice calls
- **Addresses:** T-API-01, T-API-05
- **Justification:** All communications use TLS 1.3. Internal service-to-service communications use mutual TLS (mTLS) to authenticate both parties. For critical external integrations (Payment Gateway, CBS), certificate pinning ensures that even a CA compromise does not allow a rogue certificate to be used.

#### Control DATA-04: Append-Only Transaction Ledger
- **Applies to:** Transaction Ledger
- **Addresses:** T-DATA-03
- **Justification:** The Transaction Ledger is designed as an append-only database (using database-level constraints and WAL-based replication). No record can be modified or deleted, only new compensating entries can be added (reversal records). This ensures complete auditability and prevents insider tampering with financial records.

---

### 4.5 Secrets Management

#### Control SEC-01: Centralized Secrets Manager
- **Applies to:** All services, Admin Portal
- **Addresses:** T-DATA-05, T-AUTH-03, T-ADMIN-01
- **Justification:** All secrets (DB passwords, API keys, encryption keys, TLS certificates) are stored in a centralized vault (conceptually equivalent to HashiCorp Vault or AWS Secrets Manager). Secrets are never hardcoded in source code or configuration files. Each microservice retrieves its required secrets at startup via authenticated API calls and caches them in memory only.

#### Control SEC-02: Hardware Security Module (HSM) for Encryption Keys
- **Applies to:** Encryption keys for card tokens and transaction signing
- **Addresses:** T-DATA-02, T-DATA-03
- **Justification:** Critical cryptographic operations (key generation, signing) are performed inside an HSM, ensuring that private keys are never exposed even to the application code. This provides the highest level of key protection.

#### Control SEC-03: Automated Secret Rotation
- **Applies to:** DB credentials, API keys, certificates
- **Addresses:** T-AUTH-03, T-DATA-05
- **Justification:** All secrets have defined maximum lifetimes and are rotated automatically. API key rotation must be possible without service downtime (dual-key window). Certificate rotation is automated via ACME protocol. This limits the value of any stolen secret.

---

### 4.6 Monitoring and Logging

#### Control MON-01: Centralized, Immutable Audit Logging
- **Applies to:** All components, Admin Portal, Payment Service
- **Addresses:** T-LOG-01, T-LOG-02, T-ADMIN-05, T-DATA-03
- **Justification:** All security-relevant events are logged immediately to a centralized SIEM with write-once storage (logs are cryptographically chained to detect tampering). Application logs must **never** contain raw credentials, PAN, or sensitive PII. Log retention must comply with PCI-DSS (12 months) and regulatory requirements.

#### Control MON-02: Real-time Alerting and Anomaly Detection
- **Applies to:** SIEM, Payment Service, Admin Portal
- **Addresses:** T-AUTH-01, T-API-03, T-DATA-03, T-ADMIN-01
- **Justification:** The SIEM is configured with rules to alert on high-severity events: multiple failed logins (>5 in 5 minutes), large or unusual transactions, admin actions outside business hours, access to the CBS integration, changes to fraud detection rules. Alerts are prioritized and routed to the SOC for investigation within defined SLAs.

#### Control MON-03: Payment Webhook Signature Validation
- **Applies to:** Payment Service (callback handler)
- **Addresses:** T-API-04
- **Justification:** All incoming payment status callbacks from the Payment Gateway must be cryptographically verified using HMAC-SHA256 signatures provided in the request header. The callback handler rejects any request without a valid signature, preventing forged payment success notifications that would deliver goods without payment.

---

### 4.7 Secure Deployment Practices

#### Control DEP-01: API Gateway as Single Entry Point
- **Applies to:** All API communication
- **Addresses:** T-AUTH-01, T-API-02, T-API-03, T-AUTH-05
- **Justification:** The API Gateway is the single ingress point for all external requests. It enforces: rate limiting per client, JWT validation, API key validation, request schema validation, input sanitization, and TLS termination. Internal microservices cannot be reached directly from external networks, significantly reducing the attack surface.

#### Control DEP-02: Defense-in-Depth with Layered Security Controls
- **Applies to:** Entire architecture
- **Addresses:** Multiple threats
- **Justification:** No single security control is relied upon exclusively. For example, even if the WAF fails to block an SQL injection attempt, prepared statements at the application layer prevent successful exploitation. Even if a service account is compromised, network segmentation limits what it can access. This redundancy ensures that an attacker must defeat multiple independent layers.

#### Control DEP-03: Separation of User and Admin Planes
- **Applies to:** Admin Portal, API Backend
- **Addresses:** T-ADMIN-01, T-ADMIN-03, T-AUTHZ-02
- **Justification:** The Admin Portal runs as a completely separate application on a separate server, network, and domain from the customer-facing frontend. Admin API endpoints are on a separate path/subdomain with additional authentication requirements. This means that even a full compromise of the customer-facing application does not grant access to administrative functions.

#### Control DEP-04: Input Validation and Output Encoding
- **Applies to:** All API endpoints, Web Frontend
- **Addresses:** T-DATA-01, T-AUTH-02 (XSS-based session theft)
- **Justification:** All API inputs are validated against strict schemas (type, range, format) before processing. All outputs are properly HTML-encoded to prevent XSS. Parameterized queries are used for all database interactions, preventing SQL injection. Content Security Policy (CSP) headers are set on the frontend to restrict script execution.

---

### 4.8 Updated Architecture with Security Controls

```
+==============================+
|       INTERNET (Untrusted)   |
|  [Customer] [Merchant Apps]  |
+==============+===============+
               | HTTPS TLS 1.3 only
+==============v===============+
|   DMZ ZONE                   |
| [DDoS Mitigation Layer]      |
| [WAF - OWASP Rules]          |    ← Controls: NET-01
| [Load Balancer + TLS Term.]  |
+==============+===============+
               | JWT-validated
+==============v===============+
|   APPLICATION ZONE           |
| [API Gateway]                |    ← Controls: DEP-01, IAM-02, IAM-05
|   ├─ Rate Limiting           |
|   ├─ JWT Validation          |
|   ├─ Schema Validation       |
|   ├─ Input Sanitization      |
|                              |
| [User Service]               |    ← Controls: IAM-01, IAM-03, DATA-01
| [Payment Service]            |    ← Controls: MON-03, DATA-02, DATA-04
| [Merchant Service]           |    ← Controls: IAM-05, SEC-01
| [Notification Service]       |
+===+==========================+
    | mTLS encrypted DB connections
+===v==========================+
|   DATA ZONE                  |
| [User DB] - encrypted at rest|    ← Controls: DATA-01, DATA-02
| [Merchant DB] - encrypted    |
| [Transaction Ledger] - R/O   |    ← Control: DATA-04
| [Encrypted Backups]          |    ← Control: DATA-01
+===+==========================+
    | mTLS + Certificate Pinning
+===v==========================+
|   EXTERNAL ZONE              |
| [Payment Gateway] HMAC-verify|    ← Control: MON-03, DATA-03
| [Core Banking System] mTLS   |    ← Control: NET-02, DATA-03
+==============================+

+==============================+
|   ADMIN ZONE (Isolated)      |
| [VPN + MFA required]         |    ← Controls: NET-03, IAM-04
| [Admin Portal] - PAM gated   |    ← Controls: IAM-04, DEP-03
| [SIEM - Immutable Logs]      |    ← Controls: MON-01, MON-02
| [Secrets Manager + HSM]      |    ← Controls: SEC-01, SEC-02, SEC-03
+==============================+
```

---

## Task 5: Risk Treatment and Residual Risk

### 5.1 Risk Treatment Table

| Threat ID | Threat Name | Risk Level | Treatment Decision | Treatment Actions | Residual Risk |
|-----------|------------|-----------|-------------------|------------------|---------------|
| T-AUTH-01 | Credential Stuffing | HIGH | **Mitigate** | MFA (IAM-01), rate limiting (DEP-01), CAPTCHA, breach password detection, account lockout | LOW |
| T-AUTH-02 | Session Token Hijacking | HIGH | **Mitigate** | Short-lived JWTs (IAM-02), HTTPS-only cookies, CSP headers (DEP-04), SameSite cookie attribute | LOW |
| T-AUTH-03 | API Key Compromise | HIGH | **Mitigate** | Secrets Manager (SEC-01), automated rotation (SEC-03), key usage monitoring | LOW-MEDIUM |
| T-AUTH-04 | Admin Portal Impersonation | CRITICAL | **Mitigate** | MFA (IAM-01), PAM (IAM-04), VPN-only access (NET-03), session recording | LOW |
| T-AUTH-05 | JWT Token Forgery | HIGH | **Mitigate** | RS256 signing (IAM-02), reject alg:none, short expiry, JWKS endpoint validation | LOW |
| T-AUTHZ-01 | IDOR | HIGH | **Mitigate** | RBAC enforcement (IAM-03), API-level ownership checks, automated IDOR testing | LOW |
| T-AUTHZ-02 | Privilege Escalation | HIGH | **Mitigate** | Strict RBAC (IAM-03), code review, penetration testing | LOW-MEDIUM |
| T-AUTHZ-03 | Role Misconfiguration | MEDIUM | **Mitigate** | Quarterly RBAC audits (IAM-03), least privilege enforcement, change management | LOW |
| T-AUTHZ-04 | Rogue Service Account | HIGH | **Mitigate** | Network segmentation (NET-02), microservice RBAC (IAM-03), mTLS (DATA-03) | LOW |
| T-DATA-01 | SQL Injection / DB Exfiltration | HIGH | **Mitigate** | Parameterized queries (DEP-04), WAF (NET-01), DB network isolation (NET-02) | LOW |
| T-DATA-02 | Unencrypted Data at Rest | HIGH | **Mitigate** | AES-256 encryption (DATA-01), tokenization (DATA-02) | LOW |
| T-DATA-03 | Transaction Tampering | CRITICAL | **Mitigate** | Append-only ledger (DATA-04), HSM signing (SEC-02), immutable audit log (MON-01) | LOW-MEDIUM |
| T-DATA-04 | Backup Exfiltration | HIGH | **Mitigate** | Encrypted backups (DATA-01), access-controlled backup storage | LOW |
| T-DATA-05 | Secrets in Logs | HIGH | **Mitigate** | Secrets Manager (SEC-01), log scrubbing, DLP on log pipeline | LOW |
| T-API-01 | MitM Attack | HIGH | **Mitigate** | TLS 1.3 everywhere (DATA-03), mTLS for internal, cert pinning (DATA-03) | LOW |
| T-API-02 | API Parameter Tampering | HIGH | **Mitigate** | Input validation (DEP-04), signed transaction objects, server-side price lookup | LOW |
| T-API-03 | API Abuse / DDoS | HIGH | **Mitigate** | Rate limiting (DEP-01), DDoS protection (NET-01), CAPTCHA | LOW-MEDIUM |
| T-API-04 | Callback Spoofing | CRITICAL | **Mitigate** | HMAC webhook validation (MON-03), IP allowlisting Payment Gateway | LOW |
| T-API-05 | Insecure External Integration | MEDIUM | **Mitigate** | TLS enforcement, certificate validation, mTLS (DATA-03) | LOW |
| T-LOG-01 | Log Tampering | HIGH | **Mitigate** | Immutable log storage (MON-01), cryptographic chaining, WORM storage | LOW |
| T-LOG-02 | Insufficient Logging | HIGH | **Mitigate** | Comprehensive logging standards (MON-01), logging coverage audits | LOW |
| T-LOG-03 | Log Flooding | MEDIUM | **Mitigate** | Rate-limited log ingestion, log volume alerting in SIEM (MON-02) | LOW |
| T-LOG-04 | Log Data Exposure | MEDIUM | **Mitigate** | RBAC on SIEM access (IAM-03), log data classification | LOW |
| T-ADMIN-01 | Admin Privilege Abuse | CRITICAL | **Mitigate + Accept partial** | PAM (IAM-04), dual-control for sensitive ops, session recording, real-time alerting (MON-02) | **MEDIUM** (residual) |
| T-ADMIN-02 | Admin Phishing | HIGH | **Mitigate** | Security awareness training, hardware security keys (FIDO2) for admin MFA, email filtering | LOW-MEDIUM |
| T-ADMIN-03 | Unprotected Admin Endpoint | HIGH | **Mitigate** | VPN-only access (NET-03), IP allowlisting, MFA (IAM-01) | LOW |
| T-ADMIN-04 | Unauthorized Config Change | HIGH | **Mitigate** | Change management policies, dual approval for critical changes, audit logging (MON-01) | LOW |
| T-ADMIN-05 | Admin Action Repudiation | MEDIUM | **Mitigate** | Comprehensive privileged operation logging (MON-01), session recording | LOW |

---

### 5.2 Residual Risk Explanation

Despite the controls proposed, certain risks cannot be fully eliminated:

#### Residual Risk 1: Admin Insider Threat (T-ADMIN-01) — **MEDIUM** risk remains
**Why risk remains:** A sufficiently motivated and knowledgeable insider with administrative access may be able to abuse legitimate access in ways that are difficult to detect in real time. Even with dual-control requirements and session recording, a colluding pair of administrators could circumvent some controls. This risk is accepted as a business reality in any financial system.

**Management approach:** Continuous behavioral monitoring, employee background checks and periodic re-vetting, mandatory vacation policies (to allow detection of fraud during absences), segregation of duties, and annual third-party penetration tests focusing on insider scenarios.

#### Residual Risk 2: Third-Party Payment Gateway Dependency — **MEDIUM** risk remains
**Why risk remains:** Security of the external Payment Gateway is outside the organization's direct control. A breach or misuse at the third-party provider could expose tokenized card data or disrupt payment processing despite our mitigations on our side.

**Management approach:** Contractual security requirements (SLAs, right to audit, PCI-DSS certification requirements), use of multiple payment gateway providers (redundancy), and monitoring of gateway security bulletins. Classified as **Transferred** (via contract) with residual **Accepted** risk.

#### Residual Risk 3: Zero-Day Exploits Against Core Infrastructure — **LOW-MEDIUM** risk remains
**Why risk remains:** Novel vulnerabilities in operating systems, TLS libraries, or database software can be exploited before patches are available. Defense-in-depth reduces the impact of any single exploit, but cannot eliminate this risk entirely.

**Management approach:** Rapid patch management processes (SLA of ≤72 hours for critical CVEs), runtime application self-protection (RASP), network-level anomaly detection to detect unusual traffic patterns from a compromised host. Classified as **Accepted** residual risk with compensating controls.

---

## Task 6: Final Architecture and Threat Report

### 6.1 System Overview

This report assesses the security architecture of an **Online Payment Processing Application** — an internet-facing financial platform serving customers, merchants, and administrators. The system processes real payment transactions, handles sensitive PII and financial data, and integrates with external payment infrastructure and a Core Banking System.

The analysis was performed using the **STRIDE** threat modeling framework and produced:
- **29 identified threats** across 6 threat categories
- **4 Critical**, **17 High**, and **5 Medium** risk items
- **28 security architecture controls** grouped across 7 control categories

---

### 6.2 Architecture Summary

The architecture is organized into **5 network zones** separated by trust boundaries:

| Zone | Components | Trust Level |
|------|-----------|-------------|
| Internet Zone | Customer browsers, Merchant API clients | Untrusted |
| DMZ Zone | WAF, DDoS protection, Load balancer | Low-trust |
| Application Zone | API Gateway, Microservices | Internal-trusted |
| Data Zone | Databases, Transaction Ledger | High-trust |
| Admin Zone | Admin Portal, SIEM, Secrets Manager | Privileged |

All inter-zone communication is encrypted (TLS 1.3 / mTLS), authenticated, and authorized before any data is exchanged.

---

### 6.3 Asset Inventory Summary

The system manages **15 identified assets** across Critical, High, and Medium sensitivity levels. The highest-value targets are:
- Customer authentication credentials (A-01)
- Payment card data (A-02) — **protected by tokenization, never stored in application databases**
- Encryption keys and certificates (A-06) — **protected by HSM**
- Transaction records (A-04) — **protected by append-only ledger**
- Admin portal and access (A-10) — **protected by PAM and network isolation**

---

### 6.4 Threat Model Summary

Threats were identified using STRIDE across 6 requirement areas. The highest-risk items were:

| ID | Threat | STRIDE | Risk | Primary Control |
|----|--------|--------|------|----------------|
| T-AUTH-04 | Admin Portal Impersonation | S | Critical | PAM + MFA + VPN isolation |
| T-DATA-03 | Transaction Record Tampering | T | Critical | Append-only ledger + HSM signing |
| T-API-04 | Payment Callback Spoofing | S | Critical | HMAC webhook validation |
| T-ADMIN-01 | Admin Privilege Abuse | E | Critical | PAM + SIEM alerting + session recording |

---

### 6.5 Security Controls Summary

| Category | Controls | Key Controls Implemented |
|---------|---------|------------------------|
| Identity & Access | IAM-01 to IAM-05 | MFA, OAuth 2.0, RBAC, PAM, API key management |
| Network Segmentation | NET-01 to NET-03 | WAF, DDoS, micro-segmentation, admin network isolation |
| Data Protection | DATA-01 to DATA-04 | AES-256 at rest, tokenization, mTLS, append-only ledger |
| Secrets Management | SEC-01 to SEC-03 | Secrets vault, HSM, automated rotation |
| Monitoring & Logging | MON-01 to MON-03 | Immutable logs, SIEM alerting, webhook validation |
| Deployment | DEP-01 to DEP-04 | API gateway, defense-in-depth, admin plane separation, input validation |

---

### 6.6 Residual Risks Summary

| Residual Risk | Level | Treatment | Rationale |
|--------------|-------|-----------|-----------|
| Admin Insider Threat | MEDIUM | Accept + Compensate | Cannot fully prevent colluding/coerced insiders with legitimate access; behavioral monitoring applied |
| Third-party Payment Gateway Dependency | MEDIUM | Transfer + Accept | Contractual SLAs, PCI-DSS requirements; residual supply-chain risk accepted |
| Zero-Day Infrastructure Exploits | LOW-MEDIUM | Accept + Compensate | Rapid patching SLA, RASP, anomaly detection applied; zero-day cannot be predicted |

---

### 6.7 Assumptions and Limitations

| # | Assumption / Limitation |
|---|------------------------|
| 1 | This is a **cloud-agnostic architecture** — all controls are described in terms of functionality, not vendor-specific products. Equivalent technologies exist across all major cloud providers and on-premises environments. |
| 2 | It is assumed that **PCI-DSS compliance** is a hard requirement. Card data is never stored in application databases and is handled exclusively via the tokenization capabilities of the Payment Gateway. |
| 3 | The architecture assumes **internet-facing exposure** for the customer and merchant endpoints. The admin portal and internal systems are deliberately isolated from the internet. |
| 4 | **Insider threats are partially mitigated** but not fully eliminated. The system cannot prevent a sufficiently motivated privileged insider from abusing their access given enough time. |
| 5 | **Physical security** of the data center is assumed to be maintained by an appropriate physical security program. This report does not cover physical access controls. |
| 6 | The threat model covers the **application and infrastructure layers** but does not cover social engineering attacks that fall outside the system boundary (e.g., an attacker impersonating a customer on a phone call to a support agent). |
| 7 | **Threat model is a point-in-time assessment** — as the system evolves, new components and integrations will require threat model updates. Annual re-assessment is recommended. |

---

### 6.8 Recommendations

1. **Conduct a penetration test** of the complete system before production launch, with specific focus on IDOR vulnerabilities, JWT security, and admin portal access controls.
2. **Establish a formal Security Champions Program** within the development team to ensure security considerations are addressed at design time for new features.
3. **Implement a Bug Bounty Program** post-launch to leverage external security researchers to identify vulnerabilities not found in internal testing.
4. **Define and test an Incident Response Plan** specifically for payment breach scenarios, including Card scheme notification procedures (Visa/Mastercard), regulator notification timelines, and customer communication templates.
5. **Schedule annual threat model reviews** aligned with major feature releases and significant architecture changes.

---

*End of Report*

---
*Report prepared as part of Cyber Security Assignment 1 — Secure Architecture Design and Threat Modeling*
