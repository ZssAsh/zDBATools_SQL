# 🧠 zDBATools_SQL — Centralized SQL Session Capture (No 3rd Party Tools or Agents)

[![SQL Server](https://img.shields.io/badge/Platform-SQL%20Server-blue?logo=microsoftsqlserver)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()
[![Automation](https://img.shields.io/badge/Automation-SQL%20Agent%20Job-orange)]()
[![LinkedServers](https://img.shields.io/badge/Feature-LinkedServers%20Based-lightgrey)]()

---

## 📘 Overview

**zDBATools_SQL** is a lightweight, SQL-native framework that **centrally captures live session and database activity** from multiple SQL Server instances —  
✅ **Without third-party tools**  
✅ **Without agents or additional licenses**  
✅ **Using only native SQL Server features**

It provides a near real-time view of **who is connecting**, **from where**, and **to which database/application** across all your linked servers.

---

## 🚀 Key Features

- 🔗 **Linked Server-based collection** — Secure, agentless querying across instances  
- 🧩 **Centralized tables** for session, database, and host information  
- 🔄 **SQL Agent Job automation** for scheduled collection  
- ⚙️ **Ignore lists** (applications, logins, hosts, databases) to reduce noise  
- 🧠 **Merge logic** keeps captured data up-to-date automatically  
- 🪶 **Lightweight footprint** — no CLR, triggers, or external services  

---

## 🏗️ Architecture Overview

| Component | Description |
|------------|-------------|
| **Database** | `zDBATools` – shared utility DB |
| **Schemas** | `[SC]` for Session Capture, `[Shared]` for Linked Server configs |
| **Tables** | `CapturedSessions`, `DatabasesSnapshot`, `Ignored*`, `LinkedServers` |
| **Stored Procedures** | `[SC].[usp_CaptureSessions]`, `[SC].[usp_RefreshDatabasesSnapshot]` |
| **View** | `[SC].[uvw_DatabasesSnapshot]` – unified snapshot of DBs + Sessions |
| **SQL Agent Job** | `zDBATools_CaptureSessions` runs every 30 minutes |

---

## ⚙️ Installation

### 1️⃣ Prerequisites

- SQL Server 2016 or later  
- Linked Servers configured between participating instances  
- Permissions to create schemas, tables, and jobs  

---

### 2️⃣ Deployment Steps

1. Create or use a shared DBA utility database (e.g., `zDBATools`)  
2. Run the provided SQL script in order:
   - Schema creation (`[SC]`, `[Shared]`)
   - Table creation scripts  
   - Stored procedures (`usp_CaptureSessions`, `usp_RefreshDatabasesSnapshot`)  
   - SQL Agent Job creation script  
3. Populate `[Shared].[LinkedServers]` with your target linked servers:
   ```sql
   INSERT INTO [Shared].[LinkedServers] (LinkedServerName, Enabled)
   VALUES ('SQLPROD01', 1), ('SQLUAT01', 1), ('SQLDEV01', 0);
