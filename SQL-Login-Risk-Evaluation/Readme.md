# SQL-Login-Risk-Evaluation

A fully automated **SQL Server Access, Permissions & Security Posture Risk Analyzer** that consolidates dozens of security checks into one unified T‑SQL engine. It generates a structured **XML risk report** with weighted scoring for each security category, enabling DBAs and security teams to identify exposure across logins, permissions, server configuration, impersonation paths, credentials, SQL Agent jobs, linked servers, and more.

---

## 🔥 What This Script Does

This risk‑evaluation engine performs deep inspection of SQL Server security posture using metadata extracted from:

* Server principals
* Server & database permissions
* SQL Agent jobs, proxies, and credentials
* Linked server mappings & delegation
* Login policy configuration
* Orphaned and stale logins
* Built‑in sysadmin anomalies
* Default database alignment

It consolidates all insights into a **final weighted risk score** and a **detailed XML report**.

---

## 🧠 Core Architecture

The script uses a modular design:

### **1. Risk Weight Configuration Tables**

Temporary tables such as:

* `#PermissionRiskWeights`
* `#SecurityRiskWeights`
* `#SurfaceRiskWeights`

These allow full customization to align with internal audit standards.

### **2. Data Collection Blocks**

Each producing focused risk components:

* Granted permissions & grant‑option escalation
* SQL Agent job and owner behavior
* Proxy and credential exposures
* Impersonation chains
* Linked server delegation & RPC/RPC OUT
* Orphaned login detection
* Login policy violations (stale, disabled, non‑expiring, SA/Builtin issues)
* Default database misalignments

### **3. Aggregation Layer**

This layer computes:

* Direct permission risk (no extra temp tables needed)
* Additional risk categories (jobs, proxies, credentials, impersonation, etc.)
* Combined `RiskScore_AccessRights`
* Final XML output

---

## 📦 Output: Structured XML Risk Report

The script produces a deeply structured XML like:

```
<SecurityReport>
    <Totals AccessRights="..." AdditionalRisk="..." />
    <AccessRights>
        <Permission Name="..." RiskPoints="..." />
        ...
    </AccessRights>
    <AdditionalRisk>
        <Jobs ... />
        <Proxies ... />
        <Credentials ... />
        <LinkedServers ... />
        <Impersonation ... />
        <LoginProfile ... />
    </AdditionalRisk>
</SecurityReport>
```

Ready for ingestion into:

* Power BI dashboards
* Audit workflows
* Security automation pipelines

---

## 🚀 How to Use

1. Open the script in SSMS.
2. Run it on the SQL instance you want to evaluate.
3. Copy or save the output XML.
4. Feed into downstream tools or store for audit comparison.

No configuration required—but all weights and categories are fully customizable.

---

## ⚙️ Customize Risk Weighting

Risk weight tables at the beginning of the script allow adjusting severity, such as:

* Critical server permissions (CONTROL SERVER, SHUTDOWN)
* Elevated login types
* Policy violations
* Stale logins
* Exposure through jobs, proxies, credentials

You can tune these to match:

* Internal audit scoring
* CIS benchmarks
* GDPR/HIPAA controls

---

## 📈 Why This Script Exists

SQL Server exposes hundreds of potential security gaps including:

* Excessive privileges
* Forgotten accounts
* Dangerous impersonation chains
* Uncontrolled job owners
* Leaking credentials via SQL Agent
* Misconfigured linked servers

Manual inspection is time‑consuming. This script automates everything.

---

## 🛠 Supported Versions

* SQL Server 2014+
* Azure SQL Managed Instance (partial compatibility)
* Azure SQL Database (limited — excludes Agent/Linked Server risk blocks)

---

## 🧭 Roadmap

* JSON output option
* Power BI Risk Dashboard template
* Automated historical baselining
* Export to audit tables
* Plugin architecture for custom risk modules

---

## 📜 License

MIT License (or update as appropriate).

---

## ✉ Support & Contributions

Open an issue or PR with improvements, new risk modules, or edge‑case scenarios.
