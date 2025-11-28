# SQL Server Access, Permissions & Risk Evaluation Report – v7.9

## Purpose
This query provides a comprehensive security and compliance audit of SQL Server logins and database principals. It helps DBAs and security teams:

- Inventory all logins and database users across the instance.
- Detect high-risk accounts (e.g., sysadmin, dbo, db_owner).
- Identify orphaned users, disabled logins, and accounts with excessive permissions.
- Highlight SA login security posture (renamed/disabled).
- Compute a risk score and recommended actions for each account.

## Benefits
- **Security Hardening**: Quickly spot accounts with elevated privileges or misconfigurations.
- **Compliance Reporting**: Supports audits for SOX, GDPR, HIPAA, and internal security policies.
- **Operational Efficiency**: Provides actionable recommendations (e.g., disable orphaned accounts).
- **Risk Prioritization**: Risk scoring helps focus remediation on the most critical issues.
- **Export-Friendly**: Results can be exported to Excel, Power BI, or CSV for further analysis.

## Query Content Overview
The report consolidates data from:
- sys.server_principals (server-level logins)
- sys.database_principals (database-level users)
- sys.server_permissions and sys.database_permissions (granted permissions)
- Role membership tables for server and database roles

## Column Descriptions & How They Help
| Column | Description | Why It Matters |
|--------|-------------|----------------|
| **ServerName** | Name of the SQL Server instance. | Identifies the source system for multi-server audits. |
| **DatabaseName** | Database where the user exists (NULL for server-only logins). | Helps scope permissions to specific databases. |
| **LoginName** | Server-level login name. | Key identifier for authentication and access control. |
| **LoginType** | Type of login (SQL_LOGIN, WINDOWS_LOGIN, WINDOWS_GROUP). | Indicates authentication method and integration with AD. |
| **LoginDisabled** | 1 if login is disabled. | Disabled accounts should not pose risk but need cleanup. |
| **IsSaLogin** | 1 if this is the SA login (SID = 0x01). | SA login is a critical security focus; must be renamed/disabled. |
| **DbUserName** | Database principal name. | Maps login to database user for permission analysis. |
| **DbPrincipalType** | Type of database principal (SQL_USER, WINDOWS_USER, WINDOWS_GROUP). | Shows how access is granted at DB level. |
| **DefaultSchema** | Default schema for the user. | dbo default schema can indicate elevated privileges. |
| **IsSysAdmin** | 1 if login is a member of sysadmin server role. | Highest privilege level; immediate attention required. |
| **IsDatabaseOwnerLogin** | 1 if user is dbo. | Full control over the database; high risk. |
| **IsDbOwnerMember** | 1 if user is in db_owner role. | Elevated database-level privileges. |
| **HasDDL** | 1 if user has DDL permissions or db_ddladmin role. | Can alter schema; potential risk for unauthorized changes. |
| **HasWrite** | 1 if user can INSERT, UPDATE, or DELETE. | Indicates ability to modify data. |
| **HasRead** | 1 if user can SELECT. | Basic read access; usually low risk unless combined with other perms. |
| **HasExecute** | 1 if user can execute stored procedures. | Important for application accounts; can be abused for privilege escalation. |
| **IsOrphaned** | 1 if database user has no corresponding login. | Orphaned users should be cleaned up to reduce attack surface. |
| **RiskScore** | Numeric score (5–100) based on privileges and risk factors. | Enables prioritization of remediation efforts. |
| **RiskLevel** | High, Medium, or Low based on RiskScore and role membership. | Quick visual indicator for auditors and DBAs. |
| **RiskFactors** | Text summary of why the account is risky (e.g., SysAdmin; db_owner; SA login not disabled). | Transparency for audit and remediation planning. |
| **GrantedServerPermissions** | (Optional) List or count of server-level permissions and roles. | Shows elevated server-level capabilities beyond roles. |
| **GrantedDatabasePermissions** | (Optional) List or count of database-level permissions and roles. | Reveals granular privileges at DB level. |
| **RecommendedAction** | Suggested remediation (e.g., Address Immediately: Highly privileged account). | Provides actionable next steps for security hardening. |

## Usage Scenarios
- **Daily Security Check**: Run the script to detect new high-privilege accounts.
- **Audit Preparation**: Export results to Excel or Power BI for compliance reporting.
- **Incident Response**: Quickly identify accounts with risky permissions during a breach investigation.
- **Role Review**: Validate least-privilege principle across all environments.

## Export Guidance
- For large environments, use count-based outputs instead of full permission lists to avoid Excel performance issues.
- Use CSV or Power BI for normalized data if detailed permissions are required.
- Apply filters on RiskLevel and RiskScore to prioritize remediation.

---
**Author:** Ziad Samhan  
**Version:** v7.9  
**Safe to Run:** Read-only
