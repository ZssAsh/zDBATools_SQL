--==========================================================================================================
-- 1.0 [ACCESS RIGHTS RISKS]
-- Create a temp table to store risk points for built-in server permissions
-- Each permission is assigned a risk value based on potential impact if misused
IF OBJECT_ID('tempdb..#AccessRightsRisks') IS NOT NULL DROP TABLE #AccessRightsRisks;
CREATE TABLE #AccessRightsRisks 
(
	PermissionName NVARCHAR(128) NOT NULL,
	RiskPoints INT NOT NULL
);
-- Insert permissions and their risk points
-- Insert permissions and their risk points
INSERT INTO #AccessRightsRisks(PermissionName, RiskPoints)
SELECT 
	permission_name,
	CASE
		-- Highest risk: server-wide critical permissions
		WHEN permission_name IN ('CONTROL SERVER','SHUTDOWN', 'ALTER ANY LOGIN', 'ALTER SERVER STATE', 'CREATE LOGIN') THEN 10
		-- High risk: altering server/database security
		WHEN permission_name IN ('ALTER ANY DATABASE', 'ALTER ANY ENDPOINT', 'ALTER ANY SERVER ROLE', 'ALTER ANY CREDENTIAL' ) THEN 8
		-- Moderate risk: creating databases, endpoints, server roles, event sessions, impersonation
		WHEN permission_name IN ('CREATE ANY DATABASE', 'CREATE ENDPOINT', 'CREATE SERVER ROLE', 'CREATE ANY EVENT SESSION', 'ALTER ANY EVENT SESSION', 'IMPERSONATE ANY LOGIN' ) THEN 6
		-- Medium risk: bulk operations and select permissions on all user securables
		WHEN permission_name IN ('ADMINISTER BULK OPERATIONS', 'SELECT ALL USER SECURABLES' ) THEN 5
		-- Low risk: viewing server or database state and definitions
		WHEN permission_name IN ('VIEW SERVER SECURITY STATE', 'VIEW ANY DATABASE', 'VIEW SERVER PERFORMANCE STATE', 'VIEW SERVER STATE' ) THEN 3
		WHEN permission_name IN ('VIEW ANY DEFINITION', 'VIEW ANY ERROR LOG', 'VIEW ANY SECURITY DEFINITION', 'VIEW ANY PERFORMANCE DEFINITION' ) THEN 3
		-- Minimal risk: trace, external assembly permissions
		WHEN permission_name IN ('ALTER TRACE', 'CREATE TRACE EVENT NOTIFICATION', 'EXTERNAL ACCESS ASSEMBLY', 'UNSAFE ASSEMBLY', 'CREATE DDL EVENT NOTIFICATION' ) THEN 2
		-- Basic connection/authentication permissions
		WHEN permission_name IN ('CONNECT SQL', 'AUTHENTICATE SERVER', 'CONNECT ANY DATABASE' ) THEN 1
		-- Default risk for any other permission
		ELSE 1
	END AS RiskPoints
FROM sys.fn_builtin_permissions('SERVER');

--==========================================================================================================
-- 2.0 [ATTACK SURFACE RISK WEIGHTS]
-- Table to assign risk weights to server principals based on roles and objects they own
IF OBJECT_ID('tempdb..#AttackSurfaceRiskWeights') IS NOT NULL DROP TABLE #AttackSurfaceRiskWeights;
CREATE TABLE #AttackSurfaceRiskWeights
(
	RiskCategory      VARCHAR(100),      -- Category of risk (SysAdmin, GrantOption, JobOwner, etc.)
	ConditionValue    VARCHAR(200),      -- Value used to match principal/object state
	RiskWeight        DECIMAL(10,2),     -- Weight of risk for scoring
	Notes             VARCHAR(200),      -- Describes why this risk matters
	IsActive          BIT DEFAULT 1,     -- Flag to enable/disable this risk
	RiskCode          NVARCHAR(100)  NULL -- Link to remediation recommendation
);

-- Populate the attack surface weights
INSERT INTO #AttackSurfaceRiskWeights VALUES
	('SysAdmin',			'1',				100,	'Privilege Escalation → Grantable rights',					1,'HighPrivilegeRole'),
	('GrantOption',			'ANY',				0.3,    'Privilege Escalation → Grantable rights',                  1,'GrantOptionRisk'),
	('JobOwner',			'HasJobs',          6,      'Can execute agent jobs',                                   1,'JobRisk'),
	('ProxyOwner',          'HasProxies',       8,      'Run code using external auth',                             1,'ProxyRisk'),
	('CredentialOwner',     'HasCredential',    10,     'Holds stored passwords',                                   1,'CredentialRisk'),
	('Impersonation',       'HasTargets',       10,     'Can EXECUTE AS → Privilege Hop',                           1,'ImpersonationRisk'),
	('LinkedServer',        'HasLinkedServer',	7,      'Lateral movement to remote server',                        1,'LinkedServerRisk'),
	('OrphanLogin',			'IsOrphan',         5,      'Login has no matching user in any DB',                     1,'OrphanedLogin'),
	('DefaultDB',			'InvalidDB',        4,      'Default database is offline, dropped, or inaccessible',	1,'DefaultDBRisk'),
	('DirectPermissions',	'YES',              1,      'Permission granted directly instead of through role',      1,'DirectPermissionRisk');

--==========================================================================================================
-- 3.0 [SECURITY RISK WEIGHTS]
-- Risk points for login-specific security checks (login type, policies, SA account, stale logins, weak passwords)
IF OBJECT_ID('tempdb..#SecurityRiskWeights') IS NOT NULL DROP TABLE #SecurityRiskWeights;
CREATE TABLE #SecurityRiskWeights 
(
	Category        NVARCHAR(50),     -- Security check category
	CheckValue      NVARCHAR(50),     -- Value to check against (login type, policy enforced, etc.)
	RiskPoints      INT,              -- Risk points assigned
	Description     NVARCHAR(200),    -- Description of the risk
	Active          BIT,              -- Enable/disable risk
	RiskCode        NVARCHAR(100)  NULL -- Link to remediation
);

-- Insert sample risk weights
INSERT INTO #SecurityRiskWeights VALUES
	('LoginType',       'SQL_LOGIN',            6,  'SQL logins are password-based and higher exposure',    1,'LoginType_SQL'),
	('LoginType',       'WINDOWS_LOGIN',        2,  'Protected by AD policies and lockout',                 1,'LoginType_Windows'),
	('LoginType',       'CONTAINED_USER',       3,  'Scoped but not AD enforced',                           1,NULL),
	('LoginType',       'EXTERNAL_USER',        1,  'AAD/Federated − lowest exposure',                      1,NULL),
	('PolicyCheck',     '0',                   10, 'Password complexity not enforced',                      1,'PolicyCheck'),
	('PolicyCheck',     '1',                    0,  'Secure default',                                       1,NULL),
	('ExpiryCheck',     '0',                    8,  'No password change enforced',                          1,'ExpiryCheck'),
	('ExpiryCheck',     '1',                    0,  'Secure default',                                       1,NULL),
	('LoginDisabled',   '1',                    0,  'Disabled login = no exposure',                         1,NULL),
	('LoginDisabled',   '0',                    2,  'Active login = some exposure',                         1,'LoginNotDisabled'),
	('BuiltinSA',       '0',                    15, 'SA Not Disabled (active) = CRITICAL RISK',             1,'BuiltinSA'),
	('SaNotRenamed',    'YES',                  10, 'Default SA login name not changed = higher risk',      1,'SaNotRenamed'),
	('SaNotRenamed',    'NO',                   0,  'SA login renamed = safer',                             1,NULL),
	('StaleLogin',      '90',                   7,  'Dormant login may be exploited',                       1,'StaleLogin'),
	('BlankPassword',    '1',                   100, 'Blank Password',                                       1,'BlankPassword'),
	('PasswordSameAsLogin', '1',                50, 'Password same as login',                               1,'PasswordSameAsLogin');

--==========================================================================================================
-- 4.0 [SECURITY RISK REMEDIATION]
-- Links risk codes to recommended fixes and severity
IF OBJECT_ID('tempdb..#SecurityRiskRemediation') IS NOT NULL DROP TABLE #SecurityRiskRemediation;
CREATE TABLE #SecurityRiskRemediation
(
	RiskCode            NVARCHAR(100)  NOT NULL PRIMARY KEY,
	RiskName            NVARCHAR(200)  NOT NULL,
	WhyDangerous        NVARCHAR(MAX)  NOT NULL,
	RecommendedFix      NVARCHAR(MAX)  NOT NULL,
	SeverityLevel       TINYINT        NULL,   -- optional (1=Low, 2=Medium, 3=High, 4=Critical)
	Notes               NVARCHAR(500)  NULL
);

-- Insert remediation info
INSERT INTO #SecurityRiskRemediation(RiskCode, RiskName, WhyDangerous, RecommendedFix, SeverityLevel) VALUES
	('BlankPassword',       'Blank Password Login',             'Login has no password; easy unauthorized access.',     'Set strong password; enable password policy.',     4),
	('PasswordSameAsLogin', 'Password Same as Login Name',      'Weak and easily guessed; common attack target.',       'Change to strong password; enforce policy.',       4),
	('PolicyCheck',         'Password Policy Disabled',         'Allows weak passwords with no complexity rules.',      'Enable CHECK_POLICY; enforce complexity.',         3),
	('ExpiryCheck',         'Password Never Expires',           'Passwords remain unchanged for long periods.',         'Enable CHECK_EXPIRATION; rotate passwords.',       3),
	--('StaleEnabledLogin', 'Unused Active Login',              'Dormant logins can be exploited silently.',            'Disable or remove unused logins.',                 3),
	('BuiltinSA',           'sa Login Enabled',                 'Highly targeted account; full admin compromise risk.', 'Disable or rename sa; enforce strong password.',   4),
	('SaNotRenamed',        'sa Login Not Renamed',             'Default name increases brute-force risk.',             'Rename sa and ensure strong password.',            3),
	('StaleLogin',          'Stale Login',                      'Unused accounts increase attack surface.',             'Disable or validate and clean up.',                2),
	('OrphanedLogin',       'Orphaned Login',                   'Login not mapped to any DB; may be unnecessary.',      'Drop or map to valid DB user.',                    2),
	('HighPrivilegeRole',   'Excess Server Role',               'Too much privilege enables escalation.',               'Remove unneeded high-level roles.',                4),
	('GrantOptionRisk',     'Grant Option Misuse',              'Allows privilege escalation via user grants.',         'Remove GRANT OPTION; restrict permissions.',       3),
	('CredentialRisk',      'Unsafe Credential Usage',          'Credentials may grant elevated access.',               'Remove unused credentials; limit rights.',         3),
	('ProxyRisk',           'SQL Agent Proxy Risk',             'Proxies may run jobs with high privileges.',           'Restrict or remove unused proxies.',               3),
	('ImpersonationRisk',   'Impersonation Privilege Risk',     'IMPERSONATE allows privilege escalation.',             'Remove unnecessary impersonation rights.',         4),
	('LinkedServerRisk',    'Insecure Linked Server',           'Linked servers may expose cross-server access.',       'Use least-privileged accounts; disable RPC OUT.',  3),
	('DefaultDBRisk',       'Master as Default DB',             'May cause unintended access to system DB.',            'Set proper default database.',                     1);

--==========================================================================================================
-- 5.0 [COLLECT OWNED OBJECTS]
-- Collect information about server principals owning jobs, proxies, credentials, linked servers, etc.

-- Owned SQL Agent Jobs
IF OBJECT_ID('tempdb..#OwnedJobs') IS NOT NULL DROP TABLE #OwnedJobs;
SELECT 
	suser_sname(owner_sid) AS LoginName, 
	j1.name AS JobName
INTO #OwnedJobs
FROM msdb.dbo.sysjobs j1

-- Owned Credentials
IF OBJECT_ID('tempdb..#OwnedCredentials') IS NOT NULL DROP TABLE #OwnedCredentials;
SELECT 
	c.name AS CredentialName, 
	suser_sname(c.credential_id) AS LoginName
INTO #OwnedCredentials
FROM sys.credentials c;

-- Owned SQL Agent Proxies
IF OBJECT_ID('tempdb..#OwnedProxies') IS NOT NULL DROP TABLE #OwnedProxies;
SELECT 
	pr.name AS ProxyName, 
	suser_sname(pr.credential_id) AS LoginName
INTO #OwnedProxies
FROM msdb.dbo.sysproxies pr;

-- Linked Servers accessible by logins
IF OBJECT_ID('tempdb..#LinkedServers') IS NOT NULL DROP TABLE #LinkedServers;
SELECT DISTINCT 
	sp.name AS LoginName, 
	ls.name AS LinkedServerName
INTO #LinkedServers
FROM sys.server_principals sp
JOIN sys.linked_logins ll ON sp.principal_id = ll.local_principal_id
JOIN sys.servers ls ON ls.server_id = ll.server_id
WHERE sp.type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP');

-- Impersonation privileges
IF OBJECT_ID('tempdb..#ImpersonationTargets') IS NOT NULL DROP TABLE #ImpersonationTargets;
SELECT DISTINCT 
	p.name AS LoginName, 
	dp.name AS ImpersonatedLogin
INTO #ImpersonationTargets
FROM sys.server_principals p
JOIN sys.server_permissions sp ON sp.grantee_principal_id = p.principal_id
JOIN sys.server_principals dp ON dp.principal_id = sp.grantor_principal_id
WHERE sp.permission_name = 'IMPERSONATE';

-- Server role membership
IF OBJECT_ID('tempdb..#ServerRoles') IS NOT NULL DROP TABLE #ServerRoles;
SELECT 
	sp.name AS LoginName, 
	r2.name AS Role
INTO #ServerRoles
FROM sys.server_principals sp
JOIN sys.server_role_members rm ON rm.member_principal_id = sp.principal_id
JOIN sys.server_principals r2 ON rm.role_principal_id = r2.principal_id
WHERE sp.type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP');

-- Orphaned logins (not mapped to any database)
IF OBJECT_ID('tempdb..#OrphanLogins') IS NOT NULL DROP TABLE #OrphanLogins;
CREATE TABLE #OrphanLogins (LoginName sysname);
INSERT INTO #OrphanLogins(LoginName)
SELECT sp.name
FROM sys.server_principals sp
WHERE 
		sp.type IN ('S','U') AND sp.name NOT LIKE '##%##'
	AND NOT EXISTS 
	(
		SELECT 1 
		FROM sys.databases d
		CROSS APPLY 
		(
			SELECT dp.name 
			FROM sys.database_principals dp 
			WHERE dp.sid = sp.sid
		) x
		WHERE d.database_id > 4
	);

-- Invalid or inaccessible default database
IF OBJECT_ID('tempdb..#InvalidDefaultDB') IS NOT NULL DROP TABLE #InvalidDefaultDB;
CREATE TABLE #InvalidDefaultDB(LoginName sysname);
INSERT INTO #InvalidDefaultDB(LoginName)
SELECT sp.name
FROM sys.server_principals sp
LEFT JOIN sys.databases d ON sp.default_database_name = d.name
WHERE 
		sp.type IN ('S','U') 
	AND (d.name IS NULL OR d.state <> 0);

--==========================================================================================================
-- 6.0 [LOGIN PROFILE]
-- Build detailed login profile including type, permissions, SA/sysadmin status, policy checks
IF OBJECT_ID('tempdb..#LoginProfile') IS NOT NULL DROP TABLE #LoginProfile;
CREATE TABLE #LoginProfile 
(
    LoginName               SYSNAME NOT NULL,       -- Login name
    LoginType               NVARCHAR(60) NOT NULL,	-- SQL_LOGIN, WINDOWS_LOGIN, etc.
    IsSysAdmin              BIT NOT NULL DEFAULT 0, -- Is part of sysadmin role
    IsSA                    BIT NOT NULL DEFAULT 0, -- Is SA login
    LoginDisabled           BIT NOT NULL,           -- Login disabled flag
    LastUpdateDate          DATETIME NULL,          -- Last password change or update
    IsPolicyChecked         BIT NULL,               -- Password complexity policy enforced
    IsExpirationChecked     BIT NULL,               -- Password expiration policy enforced
    SecurableClass          NVARCHAR(50) NOT NULL,	-- Type of securable: SERVER/DB
    PermissionName          NVARCHAR(128) NOT NULL,	-- Permission name
    WithGrantOption         BIT NOT NULL DEFAULT 0, -- Permission granted with GRANT OPTION
    PermissionSource        NVARCHAR(50) NOT NULL	-- Direct or Inherited permission
);

-- Loop through all logins (excluding system accounts) and collect profile & permissions
DECLARE @LoginName SYSNAME;
DECLARE login_cursor CURSOR FOR
SELECT name 
FROM sys.server_principals
WHERE 
		type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP') 
	AND name NOT LIKE '##%##'
	AND name NOT LIKE 'NT SERVICE\%'
	AND name NOT LIKE 'NT AUTHORITY\%';

OPEN login_cursor;
FETCH NEXT FROM login_cursor INTO @LoginName;
WHILE @@FETCH_STATUS = 0
BEGIN
	BEGIN TRY
		-- Fetch login properties
		DECLARE 
			@LoginType NVARCHAR(60),
			@IsDisabled BIT,
			@LastUpdateDate DATETIME,
			@IsPolicyChecked BIT,
			@IsExpirationChecked BIT,
			@IsSysAdmin BIT,
			@IsSA BIT;
		
		SELECT 
			@LoginType = sp.type_desc,
			@IsDisabled = sp.is_disabled,
			@LastUpdateDate = sl.modify_date,
			@IsPolicyChecked = sl.is_policy_checked,
			@IsExpirationChecked = sl.is_expiration_checked,
			@IsSysAdmin = CASE WHEN IS_SRVROLEMEMBER('sysadmin', @LoginName) = 1 THEN 1 ELSE 0 END,
			@IsSA = CASE WHEN sp.sid = 0x01 THEN 1 ELSE 0 END
		FROM sys.server_principals sp
		LEFT JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id
		WHERE sp.name = @LoginName;

		-- Capture direct server permissions granted to login		
		SELECT 
			sp.permission_name,
			CASE WHEN sp.state_desc = 'GRANT_WITH_GRANT_OPTION' THEN 1 ELSE 0 END AS WithGrantOption
			INTO #LoginDirectServerPerms
			FROM sys.server_permissions sp
		WHERE sp.grantee_principal_id = SUSER_ID(@LoginName);

		-- Capture effective server permissions for login
		EXECUTE AS LOGIN = @LoginName;
			USE master;
			SELECT permission_name
			INTO #LoginEffectiveServerPerms
			FROM fn_my_permissions(NULL, 'SERVER');
		REVERT;

		-- Insert login profile with permissions and metadata
		INSERT INTO #LoginProfile
		(
			LoginName, 
			LoginType, 
			IsSysAdmin, 
			IsSA, 
			LoginDisabled, 
			LastUpdateDate,
			IsPolicyChecked, 
			IsExpirationChecked, 
			SecurableClass, 
			PermissionName, 
			WithGrantOption, 
			PermissionSource
		)
		SELECT
			@LoginName,
			@LoginType,
			@IsSysAdmin,
			@IsSA,
			@IsDisabled,
			@LastUpdateDate,
			@IsPolicyChecked,
			@IsExpirationChecked,
            'SERVER',						-- Securable class
            e.permission_name,				-- Effective permission
            ISNULL(d.WithGrantOption,0),	-- GRANT OPTION flag if exists
			CASE 
				WHEN d.permission_name IS NOT NULL 
				THEN 'Direct' 
				ELSE 'Inherited' 
			END
		FROM #LoginEffectiveServerPerms e
		LEFT JOIN #LoginDirectServerPerms d
			ON e.permission_name COLLATE DATABASE_DEFAULT = d.permission_name COLLATE DATABASE_DEFAULT;

		-- Cleanup temporary permission tables for next iteration
		DROP TABLE #LoginDirectServerPerms;
		DROP TABLE #LoginEffectiveServerPerms;

	END TRY
	BEGIN CATCH
		PRINT 'Error processing login: ' + @LoginName + ' - ' + ERROR_MESSAGE();
		REVERT; -- Ensure we revert context if EXECUTE AS failed
	END CATCH;
	FETCH NEXT FROM login_cursor INTO @LoginName;
END

CLOSE login_cursor;
DEALLOCATE login_cursor;
--==========================================================================================================
-- End of cursor: #LoginProfile populated with metadata, permissions, and security attributes
-- Subsequent queries calculate AccessRightsRisk, AttackSurfaceRisk, and SecurityRisk per login
-- Each CTE (AccessRightsRisk, JobRisk, ProxyRisk, etc.) maps login data to corresponding risk weights
-- Final SELECT aggregates all risk scores into Overall_RiskScore
-- Tables dropped at the end to clean up tempdb


-- ==========================================================================================================
-- SQL Server Login Risk Evaluation Query
-- ==========================================================================================================
-- Purpose:
--   This query calculates risk scores for all SQL Server logins across three main dimensions:
--   1. Access Rights Risk       -> Permissions, SysAdmin, SA
--   2. Attack Surface Risk      -> Owned jobs, proxies, credentials, impersonation, linked servers, orphan logins, default DB, direct grants
--   3. Security Risk            -> Login type, policy compliance, expiry, disabled logins, SA account checks, stale logins, password vulnerabilities
--   
--   Each CTE isolates one category of risk, and the final SELECT aggregates them to compute:
--   - AccessRights_RiskScore
--   - Attack_Surface_RiskScore
--   - Security_RiskScore
--   - Overall_RiskScore (sum of all above)
-- ==========================================================================================================

-- 1.0 AccessRightsRisk CTE
-- Calculates risk derived from login permissions.
-- Logic:
--   - If login is SysAdmin or SA -> assign maximum risk (hardcoded 100, can use configurable #AttackSurfaceRiskWeights.SysAdmin)
--   - Else -> sum of permission risk points (from #AccessRightsRisks)
--   - GrantOptionRisk -> risk multiplied by GrantOption weight if permission has WITH GRANT OPTION
WITH AccessRightsRisk AS
(
	SELECT
		LSP.LoginName,
		MAX(CAST(LSP.IsSysAdmin AS INT)) AS IsSysAdmin,
		MAX(CAST(LSP.IsSA AS INT)) AS IsSA,
		CASE 
			WHEN MAX(CAST(LSP.IsSysAdmin AS INT))=1 OR MAX(CAST(LSP.IsSA AS INT))=1 
			THEN 100 -- change to use #AttackSurfaceRiskWeights.SysAdmin
			ELSE SUM(ISNULL(PR.RiskPoints,0))
		END AS RiskScore,
		SUM
		(
			CASE WHEN LSP.WithGrantOption=1 
			THEN ISNULL(PR.RiskPoints,0)*ISNULL(sw.RiskWeight,0) 
			ELSE 0 
			END
		) AS GrantOptionRisk
	FROM #LoginProfile LSP
		LEFT JOIN #AccessRightsRisks PR
			ON LSP.PermissionName COLLATE DATABASE_DEFAULT = PR.PermissionName COLLATE DATABASE_DEFAULT
		LEFT JOIN #AttackSurfaceRiskWeights sw 
			ON sw.RiskCategory='GrantOption'
	GROUP BY LSP.LoginName
),

-- 2.0 Owned Job CTE
-- Calculates risk due to ownership of SQL Server Agent jobs.
JobRisk AS
(
	SELECT 
		oj.LoginName, 
		MAX(s.RiskWeight) AS JobRisk
	FROM #OwnedJobs oj
	CROSS JOIN #AttackSurfaceRiskWeights s
	WHERE 
		s.RiskCategory='JobOwner'
	GROUP BY oj.LoginName
),

-- 3. ProxyRisk CTE
-- Risk due to ownership of SQL Server Agent proxies.
ProxyRisk AS
(
	SELECT 
		op.LoginName, 
		MAX(s.RiskWeight) AS ProxyRisk
	FROM #OwnedProxies op
	CROSS JOIN #AttackSurfaceRiskWeights s
	WHERE 
		s.RiskCategory='ProxyOwner'
	GROUP BY op.LoginName
),

-- 4. CredentialRisk CTE
-- Risk due to ownership of SQL Server credentials.
CredentialRisk AS
(
	SELECT 
		oc.LoginName, 
		MAX(s.RiskWeight) AS CredentialRisk
	FROM #OwnedCredentials oc
	CROSS JOIN #AttackSurfaceRiskWeights s
	WHERE 
		s.RiskCategory='CredentialOwner'
	GROUP BY oc.LoginName
),

-- 5. ImpersonationRisk CTE
-- Risk from impersonation permissions granted to login.
ImpersonationRisk AS
(
	SELECT 
		it.LoginName, 
		MAX(s.RiskWeight) AS ImpersonationRisk
	FROM #ImpersonationTargets it
	CROSS JOIN #AttackSurfaceRiskWeights s
	WHERE 
		s.RiskCategory='Impersonation'
	GROUP BY it.LoginName
),

-- 6. LinkedServerRisk CTE
-- Risk due to access to linked servers.
LinkedServerRisk AS
(
	SELECT 
		ls.LoginName, 
		MAX(s.RiskWeight) AS LinkedServerRisk
	FROM #LinkedServers ls
	CROSS JOIN #AttackSurfaceRiskWeights s
	WHERE 
		s.RiskCategory='LinkedServer'
	GROUP BY ls.LoginName
),

-- 7. OrphanLoginRisk CTE
-- Risk due to orphaned logins (logins without associated user in any database)
OrphanLoginRisk AS
(
	SELECT 
		ol.LoginName, 
		MAX(s.RiskWeight) AS OrphanLoginRisk
	FROM #OrphanLogins ol
	CROSS JOIN #AttackSurfaceRiskWeights s
	WHERE 
		s.RiskCategory='OrphanLogin'
	GROUP BY ol.LoginName
),

-- 8. DefaultDBRisk CTE
-- Risk from invalid default database assignments.
DefaultDBRisk AS
(
	SELECT 
		idd.LoginName, 
		MAX(s.RiskWeight) AS DefaultDBRisk
	FROM #InvalidDefaultDB idd
	CROSS JOIN #AttackSurfaceRiskWeights s
	WHERE 
		s.RiskCategory='DefaultDB'
	GROUP BY idd.LoginName
),
-- 9. DirectPermissions CTE
-- Risk from permissions directly granted to login (not via role).
-- Logic:
--   - Multiply risk points by category 'DirectPermissions' weight
--   - Exclude CONNECT SQL (baseline permission)
DirectPermissions AS
(
	SELECT
		LSP.LoginName,
		SUM
		(
			CASE 
				WHEN LSP.PermissionSource='Direct' 
				THEN ISNULL(PR.RiskPoints,0)*ISNULL(sw.RiskWeight,0) 
				ELSE 0 
			END
		) AS DirectGrantRisk
	FROM #LoginProfile LSP
	LEFT JOIN #AccessRightsRisks PR
		ON LSP.PermissionName COLLATE DATABASE_DEFAULT = PR.PermissionName COLLATE DATABASE_DEFAULT
	LEFT JOIN #AttackSurfaceRiskWeights sw 
		ON sw.RiskCategory='DirectPermissions'
	WHERE 
		LSP.PermissionName <> 'CONNECT SQL'
	GROUP BY LSP.LoginName
),

-- 10. LoginType CTE
-- Risk associated with login type (SQL vs Windows etc.)
LoginType As
(
	SELECT 
		LSP.LoginName,
		MAX(SR.RiskPoints) AS RiskPoints
	FROM #LoginProfile LSP 
	CROSS JOIN #SecurityRiskWeights SR 
	WHERE 
		SR.Category ='LoginType' 
		AND SR.CheckValue = LSP.LoginType
	GROUP BY LSP.LoginName
),

-- 11. PolicyCheck CTE
-- Risk if login does not enforce password policy
PolicyCheck As
(
	SELECT 
		LSP.LoginName,
		MAX(SR.RiskPoints) AS RiskPoints
	FROM #LoginProfile LSP 
	CROSS JOIN #SecurityRiskWeights SR 
	WHERE 
			SR.Category ='PolicyCheck' 
		AND SR.CheckValue = LSP.IsPolicyChecked
	GROUP BY LSP.LoginName
),

-- 12. ExpiryCheck CTE
-- Risk if login does not enforce password expiration
ExpiryCheck As
(
	SELECT 
		LSP.LoginName,
		MAX(SR.RiskPoints) AS RiskPoints
	FROM #LoginProfile LSP 
	CROSS JOIN #SecurityRiskWeights SR 
	WHERE 
			SR.Category ='ExpiryCheck' 
		AND SR.CheckValue = LSP.IsExpirationChecked
	GROUP BY LSP.LoginName
),

-- 13. DisableCheck CTE
-- Risk if login is disabled (or enabled when it shouldn’t be)
DisableCheck As
(
	SELECT 
		LSP.LoginName,
		MAX(SR.RiskPoints) AS RiskPoints
	FROM #LoginProfile LSP 
	CROSS JOIN #SecurityRiskWeights SR 
	WHERE 
			SR.Category ='LoginDisabled' 
		AND SR.CheckValue = LSP.LoginDisabled
	GROUP BY LSP.LoginName
),

-- 14. SaEnabled CTE
-- Risk for Enabled SA account
SaEnabled As
(
	SELECT 
		LSP.LoginName,
		MAX(SR.RiskPoints) AS RiskPoints
	FROM #LoginProfile LSP 
	CROSS JOIN #SecurityRiskWeights SR 
	WHERE 
			LSP.IsSA =1
		AND SR.Category ='BuiltinSA' 
		AND SR.CheckValue = LSP.LoginDisabled
	GROUP BY LSP.LoginName
),

-- 15. SaNotRenamed CTE
-- Risk if SA login has not been renamed
SaNotRenamed As
(
	SELECT 
		LSP.LoginName,
		MAX(SR.RiskPoints) AS RiskPoints
	FROM #LoginProfile LSP 
	CROSS JOIN #SecurityRiskWeights SR 
	WHERE 
			SUSER_SID(LSP.LoginName) = 0x01 
		AND SR.Category ='SaNotRenamed' 
		AND SR.CheckValue = CASE 
			WHEN LOWER(LSP.LoginName) = 'sa' 
			THEN 'YES' 
			ELSE 'NO' 
		END
	GROUP BY LSP.LoginName
),

-- 16. StaleLogin CTE
-- Risk for logins that have not been updated recently
StaleLogin As
(
	SELECT 
		LSP.LoginName,
		MAX(SR.RiskPoints) AS RiskPoints
	FROM #LoginProfile LSP 
	CROSS JOIN #SecurityRiskWeights SR 
	WHERE 
			SR.Category ='StaleLogin' 
		AND DATEDIFF(DAY, LSP.LastUpdateDate, GETDATE()) > CAST(SR.CheckValue AS INT)
	GROUP BY LSP.LoginName
),

-- 17. PasswordCheckRisk CTE
-- Risk if login password is blank or same as login name
PasswordCheckRisk AS 
(
	SELECT 
		LSP.LoginName,
		MAX
		(
			CASE 
				WHEN PWDCOMPARE('', sl.password_hash) = 1 
				THEN SR1.RiskPoints
				WHEN PWDCOMPARE(sl.name, sl.password_hash) = 1 
				THEN SR2.RiskPoints
			END
		) AS RiskPoints
	FROM #LoginProfile LSP 
	LEFT JOIN sys.sql_logins sl 
		ON LSP.LoginName = sl.name
	CROSS JOIN #SecurityRiskWeights SR1  
	CROSS JOIN #SecurityRiskWeights SR2
	WHERE 
			SR1.Category ='BlankPassword'
		AND SR2.Category ='PasswordSameAsLogin' 
	GROUP BY LSP.LoginName
)

-- ======================================
-- 18. Final Aggregation
-- ======================================
-- Combines all CTEs into one result set per login:
--   - AccessRights_RiskScore
--   - Attack_Surface_RiskScore
--   - Security_RiskScore
--   - Overall_RiskScore (sum of all)
SELECT
	LP.LoginName,
	ACC_RSK.IsSA,
	ACC_RSK.IsSysAdmin,
	LP.LoginType,
	LP.LoginDisabled,
	LP.LastUpdateDate,
	SEC_SPS.RiskPoints,
	-- Access Rights Score
	ACC_RSK.RiskScore AS AccessRights_RiskScore,

	-- 2. Attack Surface Score
	(
		ISNULL(ACC_RSK.GrantOptionRisk,0)+
		+ ISNULL(SUR_OJR.JobRisk,0)
		+ ISNULL(SUR_OPR.ProxyRisk,0)
		+ ISNULL(SUR_OCR.CredentialRisk,0)
		+ ISNULL(SUR_IMR.ImpersonationRisk,0)
		+ ISNULL(SUR_LSR.LinkedServerRisk,0)
		+ ISNULL(SUR_OLR.OrphanLoginRisk,0)
		+ ISNULL(SUR_DDR.DefaultDBRisk,0)
		+ ISNULL(SUR_DPR.DirectGrantRisk,0)
	) AS Attack_Surface_RiskScore,

	-- 3. Security Score
	(
		ISNULL(SEC_SLT.RiskPoints,0)
		+ ISNULL(SEC_SPC.RiskPoints,0)
		+ ISNULL(SEC_ECR.RiskPoints,0)
		+ CASE 
			WHEN ACC_RSK.IsSA =1
			THEN ISNULL(SEC_SSE.RiskPoints,0)
			ELSE ISNULL(SEC_SDC.RiskPoints,0)
		END
		+ ISNULL(SEC_SSN.RiskPoints,0)
		+ ISNULL(SEC_SLR.RiskPoints,0)
		+ ISNULL(SEC_SPS.RiskPoints,0) 
	) AS Security_RiskScore,

	-- TOTAL RISK SCORE
	(
		ACC_RSK.RiskScore
		+ ISNULL(ACC_RSK.GrantOptionRisk,0)
		+ ISNULL(SUR_OJR.JobRisk,0)
		+ ISNULL(SUR_OPR.ProxyRisk,0)
		+ ISNULL(SUR_OCR.CredentialRisk,0)
		+ ISNULL(SUR_IMR.ImpersonationRisk,0)
		+ ISNULL(SUR_LSR.LinkedServerRisk,0)
		+ ISNULL(SUR_OLR.OrphanLoginRisk,0)
		+ ISNULL(SUR_DDR.DefaultDBRisk,0)
		+ ISNULL(SUR_DPR.DirectGrantRisk,0)
		+ ISNULL(SEC_SLT.RiskPoints,0)
		+ ISNULL(SEC_SPC.RiskPoints,0)
		+ ISNULL(SEC_ECR.RiskPoints,0)
		+ CASE WHEN ACC_RSK.IsSA =1
			THEN ISNULL(SEC_SSE.RiskPoints,0)
			ELSE ISNULL(SEC_SDC.RiskPoints,0)
		END
		+ ISNULL(SEC_SSN.RiskPoints,0) 
		+ ISNULL(SEC_SPS.RiskPoints,0)
	) AS Overall_RiskScore,

--==============================================================================
--  SECURITY REPORT XML OUTPUT
--  This section assembles the final XML for a single login (LP.LoginName)
--  by combining:
--      • Access Rights Risk (permissions + roles)
--      • Attack Surface Risk (jobs, proxies, credentials, impersonation, etc.)
--      • Security Risk (login configuration + policy compliance)
--      • Security Remediation (why risky + recommended fixes)
--
--  All inner SELECT blocks use FOR XML PATH() to build nested XML structures.
--==============================================================================

(
    SELECT
        ----------------------------------------------------------------------
        -- TOTAL ACCESS RIGHTS RISK (SUM OF PERMISSION-LEVEL SCORES)
        ----------------------------------------------------------------------
        ACC_RSK.RiskScore AS [Totals/@AccessRights],

        ----------------------------------------------------------------------
        -- TOTAL ATTACK SURFACE RISK
        -- Summed across all attack vectors: job ownership, proxies, credentials,
        -- impersonation, linked servers, orphan logins, invalid default DB,
        -- direct grants, grant options.
        ----------------------------------------------------------------------
        (
              ISNULL(ACC_RSK.GrantOptionRisk, 0)
            + ISNULL(SUR_OJR.JobRisk, 0)
            + ISNULL(SUR_OPR.ProxyRisk, 0)
            + ISNULL(SUR_OCR.CredentialRisk, 0)
            + ISNULL(SUR_IMR.ImpersonationRisk, 0)
            + ISNULL(SUR_LSR.LinkedServerRisk, 0)
            + ISNULL(SUR_OLR.OrphanLoginRisk, 0)
            + ISNULL(SUR_DDR.DefaultDBRisk, 0)
            + ISNULL(SUR_DPR.DirectGrantRisk, 0)
        ) AS [Totals/@SurfaceRisk],

        ----------------------------------------------------------------------
        -- TOTAL SECURITY CONFIGURATION RISK
        -- Includes password policy, login type, expiration checks,
        -- disabled logins, stale logins, and whether 'sa' is renamed.
        ----------------------------------------------------------------------
        (
              ISNULL(SEC_SLT.RiskPoints, 0)
            + ISNULL(SEC_SPC.RiskPoints, 0)
            + ISNULL(SEC_ECR.RiskPoints, 0)

            -- Special SA-case override:
            -- If login is 'sa', use BuiltinSA risk weight instead of LoginDisabled.
            + CASE 
                WHEN ACC_RSK.IsSA = 1
                    THEN ISNULL(SEC_SSE.RiskPoints, 0)
                ELSE ISNULL(SEC_SDC.RiskPoints, 0)
              END

            + ISNULL(SEC_SSN.RiskPoints, 0)
            + ISNULL(SEC_SLR.RiskPoints, 0)
        ) AS [Totals/@SecurityRisk],

        ----------------------------------------------------------------------
        -- OVERALL RISK SCORE
        -- Sum of: AccessRights + AttackSurface + SecurityRisk
        ----------------------------------------------------------------------
        (
              ACC_RSK.RiskScore
            + ISNULL(ACC_RSK.GrantOptionRisk, 0)
            + ISNULL(SUR_OJR.JobRisk, 0)
            + ISNULL(SUR_OPR.ProxyRisk, 0)
            + ISNULL(SUR_OCR.CredentialRisk, 0)
            + ISNULL(SUR_IMR.ImpersonationRisk, 0)
            + ISNULL(SUR_LSR.LinkedServerRisk, 0)
            + ISNULL(SUR_OLR.OrphanLoginRisk, 0)
            + ISNULL(SUR_DDR.DefaultDBRisk, 0)
            + ISNULL(SUR_DPR.DirectGrantRisk, 0)
            + ISNULL(SEC_SLT.RiskPoints, 0)
            + ISNULL(SEC_SPC.RiskPoints, 0)
            + ISNULL(SEC_ECR.RiskPoints, 0)
            + CASE 
                WHEN ACC_RSK.IsSA = 1
                    THEN ISNULL(SEC_SSE.RiskPoints, 0)
                ELSE ISNULL(SEC_SDC.RiskPoints, 0)
              END
            + ISNULL(SEC_SSN.RiskPoints, 0)
        ) AS [Totals/@Overall],

        ----------------------------------------------------------------------
        -- ACCESS RIGHTS SECTION
        -- Includes:
        --      • Roles assigned to login
        --      • Individual permissions with risk points
        ----------------------------------------------------------------------
        (
            SELECT
                -- Roles
                (
                    SELECT
                        sr.Role AS [@Name],
                        CASE WHEN sp.is_fixed_role = 1 THEN 1 ELSE 0 END AS [@IsSystemRole]
                    FROM #ServerRoles sr
                    JOIN sys.server_principals sp ON sr.Role = sp.name
                    WHERE sr.LoginName = LP.LoginName
                    FOR XML PATH('Role'), TYPE
                ) AS [Roles],

                -- Permissions
                (
                    SELECT
                        LSP.PermissionName AS [@Name],
                        ISNULL(PR.RiskPoints, 0) AS [@RiskPoints]
                    FROM #LoginProfile LSP
                    LEFT JOIN #AccessRightsRisks PR 
                        ON LSP.PermissionName = PR.PermissionName
                    WHERE LSP.LoginName = LP.LoginName
                    FOR XML PATH('Permission'), TYPE
                ) AS [Permissions]

            FOR XML PATH('AccessRightsRisks'), TYPE
        ),

        ----------------------------------------------------------------------
        -- ATTACK SURFACE RISK SECTION
        -- Includes ALL attack vectors:
        --   Direct / WithGrant permissions, Jobs, Proxies, Credentials,
        --   Impersonation, Linked Servers, Orphan Logins, Invalid Default DB
        ----------------------------------------------------------------------
        (
            SELECT
                --------------------------------------------------------------
                -- DIRECT + WITH GRANT PERMISSIONS
                --------------------------------------------------------------
                (
                    SELECT
                        (
                            -- Direct permissions
                            SELECT
                                LSP.PermissionName AS [@Name],
                                CASE WHEN LSP.PermissionName <> 'CONNECT SQL'
                                        THEN ISNULL(PR.RiskPoints, 0) * ISNULL(sw.RiskWeight, 0)
                                END AS [@RiskPoints]
                            FROM #LoginProfile LSP
                            LEFT JOIN #AccessRightsRisks PR
                                ON LSP.PermissionName = PR.PermissionName
                            LEFT JOIN #AttackSurfaceRiskWeights sw
                                ON sw.RiskCategory = 'DirectPermissions'
                            WHERE LSP.LoginName = LP.LoginName
                              AND LSP.PermissionSource = 'Direct'
                            FOR XML PATH('Permission'), TYPE
                        ) AS Direct,

                        (
                            -- Grant Options
                            SELECT
                                LSP.PermissionName AS [@Name],
                                ISNULL(PR.RiskPoints, 0) * ISNULL(sw.RiskWeight, 0) AS [@RiskPoints]
                            FROM #LoginProfile LSP
                            LEFT JOIN #AccessRightsRisks PR
                                ON LSP.PermissionName = PR.PermissionName
                            LEFT JOIN #AttackSurfaceRiskWeights sw
                                ON sw.RiskCategory = 'GrantOption'
                            WHERE LSP.LoginName = LP.LoginName
                              AND LSP.WithGrantOption = 1
                            FOR XML PATH('Permission'), TYPE
                        ) AS WithGrant

                    WHERE EXISTS (SELECT 1 FROM #LoginProfile LSP WHERE LSP.LoginName = LP.LoginName)
                    FOR XML PATH('Permissions'), TYPE
                ),

                --------------------------------------------------------------
                -- JOB OWNER RISK
                --------------------------------------------------------------
                (
                    SELECT
                        CASE 
                            WHEN EXISTS (SELECT 1 FROM #OwnedJobs WHERE LoginName = LP.LoginName)
                            THEN
                                (
                                    SELECT
                                        -- Parent node risk
                                        (
                                            SELECT SUM(RiskWeight)
                                            FROM #AttackSurfaceRiskWeights
                                            WHERE RiskCategory = 'JobOwner'
                                        ) AS [@RiskPoints],

                                        -- List owned jobs
                                        (
                                            SELECT oj.JobName AS [@Name]
                                            FROM #OwnedJobs oj
                                            JOIN #AttackSurfaceRiskWeights sw
                                                ON sw.RiskCategory = 'JobOwner'
                                            WHERE oj.LoginName = LP.LoginName
                                            FOR XML PATH('Job'), TYPE
                                        )
                                    FOR XML PATH('OwnedJobs'), TYPE
                                )
                        END
                ),

                --------------------------------------------------------------
                -- PROXY OWNER RISK
                --------------------------------------------------------------
                (
                    SELECT 
                        op.ProxyName AS [@Name], 
                        s.RiskWeight AS [@RiskPoints]
                    FROM #OwnedProxies op 
                    CROSS JOIN #AttackSurfaceRiskWeights s
                    WHERE s.RiskCategory = 'ProxyOwner'
                      AND op.LoginName = LP.LoginName
                    FOR XML PATH('Proxy'), TYPE
                ),

                --------------------------------------------------------------
                -- CREDENTIAL OWNER RISK
                --------------------------------------------------------------
                (
                    SELECT 
                        oc.CredentialName AS [@Name], 
                        s.RiskWeight AS [@RiskPoints]
                    FROM #OwnedCredentials oc 
                    CROSS JOIN #AttackSurfaceRiskWeights s
                    WHERE s.RiskCategory = 'CredentialOwner'
                      AND oc.LoginName = LP.LoginName
                    FOR XML PATH('Credential'), TYPE
                ),

                --------------------------------------------------------------
                -- IMPERSONATION RISK
                --------------------------------------------------------------
                (
                    SELECT 
                        it.ImpersonatedLogin AS [@Name], 
                        s.RiskWeight AS [@RiskPoints]
                    FROM #ImpersonationTargets it 
                    CROSS JOIN #AttackSurfaceRiskWeights s
                    WHERE s.RiskCategory = 'Impersonation'
                      AND it.LoginName = LP.LoginName
                    FOR XML PATH('Impersonation'), TYPE
                ),

                --------------------------------------------------------------
                -- LINKED SERVER RISK
                --------------------------------------------------------------
                (
                    SELECT 
                        ls.LinkedServerName AS [@Name], 
                        s.RiskWeight AS [@RiskPoints]
                    FROM #LinkedServers ls 
                    CROSS JOIN #AttackSurfaceRiskWeights s
                    WHERE s.RiskCategory = 'LinkedServer'
                      AND ls.LoginName = LP.LoginName
                    FOR XML PATH('LinkedServer'), TYPE
                ),

                --------------------------------------------------------------
                -- ORPHAN LOGIN RISK
                --------------------------------------------------------------
                (
                    SELECT 
                        ol.LoginName AS [@Name], 
                        s.RiskWeight AS [@RiskPoints]
                    FROM #OrphanLogins ol 
                    CROSS JOIN #AttackSurfaceRiskWeights s
                    WHERE s.RiskCategory = 'OrphanLogin'
                      AND ol.LoginName = LP.LoginName
                    FOR XML PATH('OrphanLogin'), TYPE
                ),

                --------------------------------------------------------------
                -- INVALID DEFAULT DATABASE RISK
                --------------------------------------------------------------
                (
                    SELECT 
                        idd.LoginName AS [@Name], 
                        s.RiskWeight AS [@RiskPoints]
                    FROM #InvalidDefaultDB idd 
                    CROSS JOIN #AttackSurfaceRiskWeights s
                    WHERE s.RiskCategory = 'DefaultDB'
                      AND idd.LoginName = LP.LoginName
                    FOR XML PATH('InvalidDefaultDB'), TYPE
                )

            FOR XML PATH('AttackSurfaceRisk'), TYPE
        ),

        ----------------------------------------------------------------------
        -- SECURITY RISK CHECKS (RAW CHECKS WITHOUT REMEDIATION)
        ----------------------------------------------------------------------
        (
            SELECT
                SR.Category AS [@Category],
                CASE 
                    WHEN SR.Category = 'LoginDisabled' AND LP.IsSA = 1 
                        THEN (SELECT RiskPoints FROM #SecurityRiskWeights WHERE Category = 'BuiltinSA')
                    ELSE SR.RiskPoints
                END AS [@RiskPoints]
            FROM #SecurityRiskWeights SR
            WHERE SR.Category IN ('LoginType','PolicyCheck','ExpiryCheck','LoginDisabled','SaNotRenamed','StaleLogin')
              AND EXISTS
              (
                  SELECT 1
                  FROM #LoginProfile LP2
                  WHERE LP2.LoginName = LP.LoginName
                    AND (
                            (SR.Category='LoginType'     AND SR.CheckValue = LP2.LoginType)
                         OR (SR.Category='PolicyCheck'   AND SR.CheckValue = LP2.IsPolicyChecked)
                         OR (SR.Category='ExpiryCheck'   AND SR.CheckValue = LP2.IsExpirationChecked)
                         OR (SR.Category='LoginDisabled' AND SR.CheckValue = LP2.LoginDisabled)
                         OR (SR.Category='SaNotRenamed'  AND SUSER_SID(LP2.LoginName)=0x01 
                            AND SR.CheckValue = CASE WHEN LOWER(LP2.LoginName)='sa' THEN 'YES' ELSE 'NO' END)
                         OR (SR.Category='StaleLogin'    AND DATEDIFF(DAY, LP2.LastUpdateDate, GETDATE()) > CAST(SR.CheckValue AS INT))
                        )
              )
            FOR XML PATH('Check'), TYPE
        ) AS [SecurityRisk],

        ----------------------------------------------------------------------
        -- SECURITY RISK REMEDIATION DETAILS
        -- Provides: WhyDangerous, RecommendedFix, CheckValue, and RiskPoints
        ----------------------------------------------------------------------
        (
            SELECT
                SR.Category AS [@Category],
                RM.WhyDangerous AS [@Why],
                RM.RecommendedFix AS [@Fix],
                SR.CheckValue AS [@CheckValue],
                CASE 
                    WHEN SR.Category='LoginDisabled' AND LP.IsSA =1 
                        THEN (SELECT RiskPoints FROM #SecurityRiskWeights WHERE Category='BuiltinSA')
                    ELSE SR.RiskPoints
                END AS [@RiskPoints]
            FROM #SecurityRiskWeights SR
            INNER JOIN #SecurityRiskRemediation RM 
                ON SR.Category = RM.RiskCode
            WHERE SR.Category IN ('LoginType','PolicyCheck','ExpiryCheck','LoginDisabled','SaNotRenamed','StaleLogin')
              AND EXISTS
              (
                  SELECT 1
                  FROM #LoginProfile LP2
                  WHERE LP2.LoginName = LP.LoginName
                    AND (
                            (SR.Category='LoginType'     AND SR.CheckValue = LP2.LoginType)
                         OR (SR.Category='PolicyCheck'   AND SR.CheckValue = LP2.IsPolicyChecked)
                         OR (SR.Category='ExpiryCheck'   AND SR.CheckValue = LP2.IsExpirationChecked)
                         OR (SR.Category='LoginDisabled' AND SR.CheckValue = LP2.LoginDisabled)
                         OR (SR.Category='SaNotRenamed'  AND SUSER_SID(LP2.LoginName)=0x01 
                            AND SR.CheckValue = CASE WHEN LOWER(LP2.LoginName)='sa' THEN 'YES' ELSE 'NO' END)
                         OR (SR.Category='StaleLogin'    AND DATEDIFF(DAY, LP2.LastUpdateDate, GETDATE()) > CAST(SR.CheckValue AS INT))
                        )
              )
            FOR XML PATH('Check'), TYPE
        ) AS [SecurityRiskRemediation]

    FOR XML PATH('SecurityReport'), TYPE
) AS SecurityReportXML
--==============================================================================

FROM 
(
	SELECT DISTINCT LoginName,LoginType,LoginDisabled,LastUpdateDate,IsSA FROM #LoginProfile
) LP
LEFT JOIN AccessRightsRisk      ACC_RSK ON LP.LoginName = ACC_RSK.LoginName
LEFT JOIN JobRisk               SUR_OJR ON LP.LoginName = SUR_OJR.LoginName
LEFT JOIN ProxyRisk             SUR_OPR ON LP.LoginName = SUR_OPR.LoginName
LEFT JOIN CredentialRisk        SUR_OCR ON LP.LoginName = SUR_OCR.LoginName
LEFT JOIN ImpersonationRisk     SUR_IMR ON LP.LoginName = SUR_IMR.LoginName
LEFT JOIN LinkedServerRisk      SUR_LSR ON LP.LoginName = SUR_LSR.LoginName
LEFT JOIN OrphanLoginRisk       SUR_OLR ON LP.LoginName = SUR_OLR.LoginName
LEFT JOIN DefaultDBRisk         SUR_DDR ON LP.LoginName = SUR_DDR.LoginName
LEFT JOIN DirectPermissions     SUR_DPR ON LP.LoginName = SUR_DPR.LoginName
LEFT JOIN LoginType             SEC_SLT ON LP.LoginName = SEC_SLT.LoginName
LEFT JOIN PolicyCheck           SEC_SPC ON LP.LoginName = SEC_SPC.LoginName
LEFT JOIN ExpiryCheck           SEC_ECR ON LP.LoginName = SEC_ECR.LoginName
LEFT JOIN DisableCheck          SEC_SDC ON LP.LoginName = SEC_SDC.LoginName
LEFT JOIN SaEnabled             SEC_SSE ON LP.LoginName = SEC_SDC.LoginName AND SUSER_SID(LP.LoginName)=0x01
LEFT JOIN SaNotRenamed          SEC_SSN ON LP.LoginName = SEC_SDC.LoginName AND SUSER_SID(LP.LoginName)=0x01
LEFT JOIN StaleLogin            SEC_SLR ON LP.LoginName = SEC_SLR.LoginName
LEFT JOIN PasswordCheckRisk     SEC_SPS ON LP.LoginName = SEC_SPS.LoginName
ORDER BY OverAll_RiskScore DESC;


-- ======================================
-- 19. Optional cleanup of temporary tables
-- ======================================
DROP TABLE IF EXISTS #AccessRightsRisks;
DROP TABLE IF EXISTS #AttackSurfaceRiskWeights;
DROP TABLE IF EXISTS #SecurityRiskWeights;
DROP TABLE IF EXISTS #SecurityRiskRemediation;
DROP TABLE IF EXISTS #OwnedJobs;
DROP TABLE IF EXISTS #OwnedCredentials;
DROP TABLE IF EXISTS #OwnedProxies;
DROP TABLE IF EXISTS #LinkedServers;
DROP TABLE IF EXISTS #ImpersonationTargets;
DROP TABLE IF EXISTS #ServerRoles;
DROP TABLE IF EXISTS #OrphanLogins;
DROP TABLE IF EXISTS #InvalidDefaultDB;
