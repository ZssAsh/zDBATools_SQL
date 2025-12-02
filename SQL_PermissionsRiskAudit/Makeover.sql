-- 1.0 [ CREATE RISK WEIGHT CONFIG TABLES ]======================================

-- 1.1 Granted Permissions Risks - Weights
IF OBJECT_ID('tempdb..#PermissionRisk') IS NOT NULL DROP TABLE #PermissionRisk;
CREATE TABLE #PermissionRisk (
    PermissionName NVARCHAR(128) NOT NULL,
    RiskPoints INT NOT NULL
);
INSERT INTO #PermissionRisk(PermissionName, RiskPoints)
SELECT 
    permission_name,
    CASE
        WHEN permission_name IN ('CONTROL SERVER','SHUTDOWN','ALTER ANY LOGIN','ALTER SERVER STATE','CREATE LOGIN') THEN 10
        WHEN permission_name IN ('ALTER ANY DATABASE','ALTER ANY ENDPOINT','ALTER ANY SERVER ROLE','ALTER ANY CREDENTIAL') THEN 8
        WHEN permission_name IN ('CREATE ANY DATABASE','CREATE ENDPOINT','CREATE SERVER ROLE','CREATE ANY EVENT SESSION','ALTER ANY EVENT SESSION','IMPERSONATE ANY LOGIN') THEN 6
        WHEN permission_name IN ('ADMINISTER BULK OPERATIONS','SELECT ALL USER SECURABLES') THEN 5
        WHEN permission_name IN ('VIEW SERVER SECURITY STATE','VIEW ANY DATABASE','VIEW SERVER PERFORMANCE STATE','VIEW SERVER STATE') THEN 3
        WHEN permission_name IN ('VIEW ANY DEFINITION','VIEW ANY ERROR LOG','VIEW ANY SECURITY DEFINITION','VIEW ANY PERFORMANCE DEFINITION') THEN 3
        WHEN permission_name IN ('ALTER TRACE','CREATE TRACE EVENT NOTIFICATION','EXTERNAL ACCESS ASSEMBLY','UNSAFE ASSEMBLY','CREATE DDL EVENT NOTIFICATION') THEN 2
        WHEN permission_name IN ('CONNECT SQL','AUTHENTICATE SERVER','CONNECT ANY DATABASE') THEN 1
        ELSE 1
    END AS RiskPoints
FROM sys.fn_builtin_permissions('SERVER');

-- 1.2 Attack Surface Risks - Weights
IF OBJECT_ID('tempdb..#SurfaceRiskWeights') IS NOT NULL DROP TABLE #SurfaceRiskWeights;
CREATE TABLE #SurfaceRiskWeights (
      RiskCategory   VARCHAR(100),
      ConditionValue VARCHAR(200),
      RiskWeight     DECIMAL(10,2),
      Notes          VARCHAR(200),
      IsActive       BIT DEFAULT 1
);
INSERT INTO #SurfaceRiskWeights VALUES
('GrantOption',         'ANY',              0.3,    'Privilege Escalation → Grantable rights',                  1),
('JobOwner',            'HasJobs',          6,      'Can execute agent jobs',                                   1),
('ProxyOwner',          'HasProxies',       8,      'Run code using external auth',                             1),
('CredentialOwner',     'HasCredential',    10,     'Holds stored passwords',                                   1),
('Impersonation',       'HasTargets',       10,     'Can EXECUTE AS → Privilege Hop',                           1),
('LinkedServer',        'HasLinkedServer',  7,      'Lateral movement to remote server',                        1),
('OrphanLogin',         'IsOrphan',         5,      'Login has no matching user in any DB',                     1),
('DefaultDB',           'InvalidDB',        4,      'Default database is offline, dropped, or inaccessible',    1),
('DirectPermissions',   'YES',              2,      'Permission granted directly instead of through role',      1);
-- 1.3 Login Security Risks - Weights

IF OBJECT_ID('tempdb..#LoginSecurityRiskWeights') IS NOT NULL DROP TABLE #LoginSecurityRiskWeights;
CREATE TABLE #LoginSecurityRiskWeights (
    Category        NVARCHAR(50),
    CheckValue      NVARCHAR(50),
    RiskPoints      INT,
    Description     NVARCHAR(200),
    Active          BIT
);
INSERT INTO #LoginSecurityRiskWeights VALUES
('LoginType',       'SQL_LOGIN',            6,  'SQL logins are password-based and higher exposure',    1),
('LoginType',       'WINDOWS_LOGIN',        2,  'Protected by AD policies and lockout',                 1),
('LoginType',       'CONTAINED_USER',       3,  'Scoped but not AD enforced',                           1),
('LoginType',       'EXTERNAL_USER',        1,  'AAD/Federated − lowest exposure',                      1),
('PolicyCheck',     'CHECK_POLICY_OFF',     10, 'Password complexity not enforced',                     1),
('PolicyCheck',     'CHECK_POLICY_ON',      0,  'Secure default',                                       1),
('ExpiryCheck',     'CHECK_EXPIRATION_OFF', 8,  'No password change enforced',                          1),
('ExpiryCheck',     'CHECK_EXPIRATION_ON',  0,  'Secure default',                                       1),
('LoginDisabled',   'YES',                  0,  'Disabled login = no exposure',                         1),
('LoginDisabled',   'NO',                   2,  'Active login = some exposure',                         1),
('BuiltinSA',       'Enabled',              15, 'SA active = CRITICAL RISK',                            1),
('SaNotRenamed',    'YES',                  10, 'Default SA login name not changed = higher risk',      1),
('SaNotRenamed',    'NO',                   0,  'SA login renamed = safer',                             1),
('StaleLogin',      '>90days',              7,  'Dormant login may be exploited',                       1);

-- 2.0 [ OWNERSHIP & ADDITIONAL INFO (temp tables) ]=========================================

-- 2.1 Owned Jobs
IF OBJECT_ID('tempdb..#OwnedJobs') IS NOT NULL DROP TABLE #OwnedJobs;
SELECT suser_sname(owner_sid) AS LoginName,
       STUFF((SELECT '; ' + name FROM msdb.dbo.sysjobs j2 WHERE j2.owner_sid = j1.owner_sid FOR XML PATH(''), TYPE).value('.', 'NVARCHAR(MAX)'),1,2,'') AS OwnedJobs
INTO #OwnedJobs
FROM msdb.dbo.sysjobs j1
GROUP BY owner_sid;

-- 2.2 Owned Credentials
IF OBJECT_ID('tempdb..#OwnedCredentials') IS NOT NULL DROP TABLE #OwnedCredentials;
SELECT c.name AS CredentialName, suser_sname(c.credential_id) AS LoginName
INTO #OwnedCredentials
FROM sys.credentials c;

-- 2.3 Owned Proxies
IF OBJECT_ID('tempdb..#OwnedProxies') IS NOT NULL DROP TABLE #OwnedProxies;
SELECT pr.name AS ProxyName, suser_sname(pr.credential_id) AS LoginName
INTO #OwnedProxies
FROM msdb.dbo.sysproxies pr;

-- 2.4 Impersonation Targets
IF OBJECT_ID('tempdb..#ImpersonationTargets') IS NOT NULL DROP TABLE #ImpersonationTargets;
SELECT DISTINCT p.name AS LoginName, dp.name AS ImpersonatedLogin
INTO #ImpersonationTargets
FROM sys.server_principals p
JOIN sys.server_permissions sp ON sp.grantee_principal_id = p.principal_id
JOIN sys.server_principals dp ON dp.principal_id = sp.grantor_principal_id
WHERE sp.permission_name = 'IMPERSONATE';

-- 2.4 Server Roles
IF OBJECT_ID('tempdb..#ServerRoles') IS NOT NULL DROP TABLE #ServerRoles;
SELECT sp.name AS LoginName, r2.name AS Role
INTO #ServerRoles
FROM sys.server_principals sp
JOIN sys.server_role_members rm ON rm.member_principal_id = sp.principal_id
JOIN sys.server_principals r2 ON rm.role_principal_id = r2.principal_id
WHERE sp.type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP');

-- 2.5 Linked Servers
IF OBJECT_ID('tempdb..#LinkedServers') IS NOT NULL DROP TABLE #LinkedServers;
SELECT ls.name AS LinkedServerName, sp.name AS LoginName
INTO #LinkedServers
FROM sys.linked_logins lsl
JOIN sys.servers ls ON ls.server_id = lsl.server_id
JOIN sys.server_principals sp ON sp.principal_id = lsl.local_principal_id;

-- 2.6 Orphan Logins
IF OBJECT_ID('tempdb..#OrphanLogins') IS NOT NULL DROP TABLE #OrphanLogins;
CREATE TABLE #OrphanLogins (LoginName sysname);
INSERT INTO #OrphanLogins(LoginName)
SELECT sp.name
FROM sys.server_principals sp
WHERE sp.type IN ('S','U') AND sp.name NOT LIKE '##%##'
  AND NOT EXISTS (
        SELECT 1 
        FROM sys.databases d
        CROSS APPLY (
            SELECT dp.name 
            FROM sys.database_principals dp 
            WHERE dp.sid = sp.sid
        ) x
        WHERE d.database_id > 4
  );

-- 2.7 Invalid Default Database
IF OBJECT_ID('tempdb..#InvalidDefaultDB') IS NOT NULL DROP TABLE #InvalidDefaultDB;
CREATE TABLE #InvalidDefaultDB(LoginName sysname);
INSERT INTO #InvalidDefaultDB(LoginName)
SELECT sp.name
FROM sys.server_principals sp
LEFT JOIN sys.databases d ON sp.default_database_name = d.name
WHERE sp.type IN ('S','U') AND (d.name IS NULL OR d.state <> 0);


-- =========================================
-- TEMP TABLE FOR LOGIN SECURITY PROFILE
-- =========================================
IF OBJECT_ID('tempdb..#LoginSecurityProfile') IS NOT NULL DROP TABLE #LoginSecurityProfile;
CREATE TABLE #LoginSecurityProfile (
    LoginName               SYSNAME NOT NULL,
    LoginType               NVARCHAR(60) NOT NULL,
    IsSysAdmin              BIT NOT NULL DEFAULT 0,
    IsSA                    BIT NOT NULL DEFAULT 0, 
    LoginDisabled           BIT NOT NULL,
    LastPasswordUpdate      DATETIME NULL,
    IsPolicyChecked         BIT NULL,
    IsExpirationChecked     BIT NULL,
    SecurableClass          NVARCHAR(50) NOT NULL,
    PermissionName          NVARCHAR(128) NOT NULL,
    WithGrantOption         BIT NOT NULL DEFAULT 0,
    PermissionSource        NVARCHAR(50) NOT NULL
);

-- =========================================
-- CURSOR TO POPULATE LOGIN SECURITY PROFILE
-- =========================================
DECLARE @LoginName SYSNAME;
DECLARE login_cursor CURSOR FOR
SELECT name 
FROM sys.server_principals
WHERE type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP') 
      AND name NOT LIKE '##%##'
      AND name NOT LIKE 'NT SERVICE\%'
      AND name NOT LIKE 'NT AUTHORITY\%';

OPEN login_cursor;
FETCH NEXT FROM login_cursor INTO @LoginName;

WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        DECLARE 
            @LoginType NVARCHAR(60),
            @IsDisabled BIT,
            @LastPasswordUpdate DATETIME,
            @IsPolicyChecked BIT,
            @IsExpirationChecked BIT,
            @IsSysAdmin BIT,
            @IsSA BIT;

        SELECT 
            @LoginType = sp.type_desc,
            @IsDisabled = sp.is_disabled,
            @LastPasswordUpdate = sl.modify_date,
            @IsPolicyChecked = sl.is_policy_checked,
            @IsExpirationChecked = sl.is_expiration_checked,
            @IsSysAdmin = CASE WHEN IS_SRVROLEMEMBER('sysadmin', @LoginName) = 1 THEN 1 ELSE 0 END,
            @IsSA = CASE WHEN sp.sid = 0x01 THEN 1 ELSE 0 END
        FROM sys.server_principals sp
        LEFT JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id
        WHERE sp.name = @LoginName;

        -- Direct server permissions
        SELECT 
            sp.permission_name,
            CASE WHEN sp.state_desc = 'GRANT_WITH_GRANT_OPTION' THEN 1 ELSE 0 END AS WithGrantOption
        INTO #LoginDirectServerPerms
        FROM sys.server_permissions sp
        WHERE sp.grantee_principal_id = SUSER_ID(@LoginName);

        -- Effective server permissions
        EXECUTE AS LOGIN = @LoginName;
        USE master;
        SELECT permission_name
        INTO #LoginEffectiveServerPerms
        FROM fn_my_permissions(NULL, 'SERVER');
        REVERT;

        -- Insert into final table
        INSERT INTO #LoginSecurityProfile(
            LoginName, LoginType, IsSysAdmin, IsSA, LoginDisabled, LastPasswordUpdate,
            IsPolicyChecked, IsExpirationChecked, SecurableClass, PermissionName, 
            WithGrantOption, PermissionSource
        )
        SELECT
            @LoginName,
            @LoginType,
            @IsSysAdmin,
            @IsSA,
            @IsDisabled,
            @LastPasswordUpdate,
            @IsPolicyChecked,
            @IsExpirationChecked,
            'SERVER',
            e.permission_name,
            ISNULL(d.WithGrantOption,0),
            CASE WHEN d.permission_name IS NOT NULL THEN 'Direct' ELSE 'Inherited' END
        FROM #LoginEffectiveServerPerms e
        LEFT JOIN #LoginDirectServerPerms d
            ON e.permission_name COLLATE DATABASE_DEFAULT = d.permission_name COLLATE DATABASE_DEFAULT;

        DROP TABLE #LoginDirectServerPerms;
        DROP TABLE #LoginEffectiveServerPerms;

    END TRY
    BEGIN CATCH
        PRINT 'Error processing login: ' + @LoginName + ' - ' + ERROR_MESSAGE();
        REVERT;
    END CATCH;

    FETCH NEXT FROM login_cursor INTO @LoginName;
END

CLOSE login_cursor;
DEALLOCATE login_cursor;



-- =========================================
-- CALCULATE RISK SCORES WITH OUTER APPLY
-- =========================================
WITH CalculatedRiskScores AS (
    SELECT 
        LSP.LoginName,
        LSP.IsSysAdmin,
        LSP.IsSA,
        CASE 
            WHEN LSP.IsSysAdmin = 1 OR LSP.IsSA = 1 THEN 100 
            ELSE SUM(ISNULL(PR.RiskPoints,0)) 
        END AS RiskScore_AccessRights,
        -- Compute each surface risk separately
        ISNULL(ga.GrantOptionRisk,0)
        + ISNULL(job.JobRisk,0)
        + ISNULL(proxy.ProxyRisk,0)
        + ISNULL(cred.CredentialRisk,0)
        + ISNULL(imp.ImpersonationRisk,0)
        + ISNULL(lsr.LinkedServerRisk,0)
        + ISNULL(ol.OrphanRisk,0)
        + ISNULL(def.DefaultDBRisk,0) AS RiskScore_Surface
    FROM #LoginSecurityProfile LSP
    LEFT JOIN #PermissionRisk PR ON LSP.PermissionName = PR.PermissionName
    LEFT JOIN #SurfaceRiskWeights sw ON sw.RiskCategory='GrantOption' AND sw.IsActive = 1
    OUTER APPLY (
        SELECT SUM(ISNULL(PR.RiskPoints,0) * sw.RiskWeight) AS GrantOptionRisk
        FROM #LoginSecurityProfile LSP2
        LEFT JOIN #PermissionRisk PR ON LSP2.PermissionName = PR.PermissionName
        LEFT JOIN #SurfaceRiskWeights sw ON sw.RiskCategory='GrantOption' AND sw.IsActive=1
        WHERE LSP2.LoginName = LSP.LoginName AND LSP2.WithGrantOption=1
    ) ga
    OUTER APPLY (
        SELECT ISNULL(RiskWeight,0) AS JobRisk
        FROM #SurfaceRiskWeights s
        WHERE s.RiskCategory='JobOwner' AND EXISTS (SELECT 1 FROM #OwnedJobs oj WHERE oj.LoginName = LSP.LoginName)
    ) job
    OUTER APPLY (
        SELECT ISNULL(RiskWeight,0) AS ProxyRisk
        FROM #SurfaceRiskWeights s
        WHERE s.RiskCategory='ProxyOwner' AND EXISTS (SELECT 1 FROM #OwnedProxies op WHERE op.LoginName = LSP.LoginName)
    ) proxy
    OUTER APPLY (
        SELECT ISNULL(RiskWeight,0) AS CredentialRisk
        FROM #SurfaceRiskWeights s
        WHERE s.RiskCategory='CredentialOwner' AND EXISTS (SELECT 1 FROM #OwnedCredentials oc WHERE oc.LoginName = LSP.LoginName)
    ) cred
    OUTER APPLY (
        SELECT ISNULL(RiskWeight,0) AS ImpersonationRisk
        FROM #SurfaceRiskWeights s
        WHERE s.RiskCategory='Impersonation' AND EXISTS (SELECT 1 FROM #ImpersonationTargets it WHERE it.LoginName = LSP.LoginName)
    ) imp
    OUTER APPLY (
        SELECT ISNULL(RiskWeight,0) AS LinkedServerRisk
        FROM #SurfaceRiskWeights s
        WHERE s.RiskCategory='LinkedServer' AND EXISTS (SELECT 1 FROM #LinkedServers ls WHERE ls.LoginName = LSP.LoginName)
    ) lsr
    OUTER APPLY (
        SELECT ISNULL(RiskWeight,0) AS OrphanRisk
        FROM #SurfaceRiskWeights s
        WHERE s.RiskCategory='OrphanLogin' AND EXISTS (SELECT 1 FROM #OrphanLogins ol WHERE ol.LoginName = LSP.LoginName)
    ) ol
    OUTER APPLY (
        SELECT ISNULL(RiskWeight,0) AS DefaultDBRisk
        FROM #SurfaceRiskWeights s
        WHERE s.RiskCategory='DefaultDB' AND EXISTS (SELECT 1 FROM #InvalidDefaultDB idd WHERE idd.LoginName = LSP.LoginName)
    ) def
    GROUP BY LSP.LoginName, LSP.IsSysAdmin, LSP.IsSA, ga.GrantOptionRisk, job.JobRisk, proxy.ProxyRisk, cred.CredentialRisk, imp.ImpersonationRisk, lsr.LinkedServerRisk, ol.OrphanRisk, def.DefaultDBRisk
)


-- Final Output with updated AccessRights structure
SELECT
    LSP.LoginName,
    MAX(LSP.LoginType) AS LoginType,
    MAX(CAST(LSP.IsSysAdmin AS INT)) AS IsSysAdmin,
    MAX(CAST(LSP.IsSA AS INT)) AS IsSA,
    MAX(CAST(LSP.LoginDisabled AS INT)) AS LoginDisabled,
    MAX(LSP.LastPasswordUpdate) AS LastPasswordUpdate,
    MAX(CAST(LSP.IsPolicyChecked AS INT)) AS IsPolicyChecked,
    MAX(CAST(LSP.IsExpirationChecked AS INT)) AS IsExpirationChecked,
    MAX(CRS.RiskScore_AccessRights) AS RiskScore_AccessRights,
    MAX(CRS.RiskScore_Surface) AS RiskScore_Surface,
    MAX(CRS.RiskScore_AccessRights + CRS.RiskScore_Surface) AS RiskScore_Total,

    -- Merged XML
    (
    SELECT
        MAX(CRS.RiskScore_AccessRights) AS [Totals/@AccessRights],
        MAX(CRS.RiskScore_Surface) AS [Totals/@SurfaceRisk],
        MAX(CRS.RiskScore_AccessRights + CRS.RiskScore_Surface) AS [Totals/@Overall],

        -- AccessRights with Roles and Permissions
        (
            SELECT
                -- Roles
                (
    SELECT
        sr.Role AS [@Name],
        CASE WHEN sp.is_fixed_role = 1 THEN 1 ELSE 0 END AS [@IsSystemRole]
    FROM #ServerRoles sr
    JOIN sys.server_principals sp ON sr.Role = sp.name
    WHERE sr.LoginName = LSP.LoginName
    FOR XML PATH('Role'), TYPE
) AS Roles,

                -- Permissions
                (
                    SELECT
                        -- Inherited Permissions
                        (
                            SELECT 
                                LSP2.PermissionName AS [@Name],
                                ISNULL(PR.RiskPoints,0) AS [@RiskPoints]
                            FROM #LoginSecurityProfile LSP2
                            LEFT JOIN #PermissionRisk PR ON LSP2.PermissionName = PR.PermissionName
                            WHERE LSP2.LoginName = LSP.LoginName
                              AND LSP2.PermissionSource = 'Inherited'
                            FOR XML PATH('Permission'), TYPE
                        ) AS Inherited,

                        -- Direct Permissions
                        (
                            SELECT 
                                d.PermissionName AS [@Name],
                                d.WithGrantOption AS [@IsWithGrant],
                                ISNULL(PR.RiskPoints,0) AS [@RiskPoints]
                            FROM #LoginSecurityProfile d
                            LEFT JOIN #PermissionRisk PR ON d.PermissionName = PR.PermissionName
                            WHERE d.LoginName = LSP.LoginName
                              AND d.PermissionSource = 'Direct'
                            FOR XML PATH('Permission'), TYPE
                        ) AS Direct
                    FOR XML PATH('Permissions'), TYPE
                )
            FOR XML PATH('AccessRights'), TYPE
        ) AS AccessRights,

        -- AdditionalRisk (unchanged)
        (
            SELECT
                (
                    SELECT 
                        LSP2.PermissionName AS [@Name],
                        ISNULL(PR.RiskPoints,0)* ISNULL(sw.RiskWeight,0) AS [@RiskPoints]
                    FROM #LoginSecurityProfile LSP2
                    LEFT JOIN #PermissionRisk PR ON LSP2.PermissionName = PR.PermissionName
                    LEFT JOIN #SurfaceRiskWeights sw ON sw.RiskCategory='GrantOption'
                    WHERE LSP2.LoginName = LSP.LoginName AND LSP2.WithGrantOption=1
                    FOR XML PATH('Permission'), TYPE
                ) AS WithGrantPremissions,
                (
                    SELECT oj.OwnedJobs AS [@Name], s.RiskWeight AS [@RiskPoints] 
                    FROM #OwnedJobs oj CROSS JOIN #SurfaceRiskWeights s 
                    WHERE s.RiskCategory='JobOwner' AND oj.LoginName = LSP.LoginName
                    FOR XML PATH('Job'), TYPE
                ) AS Jobs,
                (
                    SELECT op.ProxyName AS [@Name], s.RiskWeight AS [@RiskPoints]
                    FROM #OwnedProxies op CROSS JOIN #SurfaceRiskWeights s
                    WHERE s.RiskCategory='ProxyOwner' AND op.LoginName = LSP.LoginName
                    FOR XML PATH('Proxy'), TYPE
                ) AS Proxies,
                (
                    SELECT oc.CredentialName AS [@Name], s.RiskWeight AS [@RiskPoints]
                    FROM #OwnedCredentials oc CROSS JOIN #SurfaceRiskWeights s
                    WHERE s.RiskCategory='CredentialOwner' AND oc.LoginName = LSP.LoginName
                    FOR XML PATH('Credential'), TYPE
                ) AS Credentials,
                (
                    SELECT it.ImpersonatedLogin AS [@Name], s.RiskWeight AS [@RiskPoints]
                    FROM #ImpersonationTargets it CROSS JOIN #SurfaceRiskWeights s
                    WHERE s.RiskCategory='Impersonation' AND it.LoginName = LSP.LoginName
                    FOR XML PATH('Impersonation'), TYPE
                ) AS ImpersonationTargets,
                (
                    SELECT ls.LinkedServerName AS [@Name], s.RiskWeight AS [@RiskPoints]
                    FROM #LinkedServers ls CROSS JOIN #SurfaceRiskWeights s
                    WHERE s.RiskCategory='LinkedServer' AND ls.LoginName = LSP.LoginName
                    FOR XML PATH('LinkedServer'), TYPE
                ) AS LinkedServers,
                (
                    SELECT ol.LoginName AS [@Name], s.RiskWeight AS [@RiskPoints]
                    FROM #OrphanLogins ol CROSS JOIN #SurfaceRiskWeights s
                    WHERE s.RiskCategory='OrphanLogin' AND ol.LoginName = LSP.LoginName
                    FOR XML PATH('OrphanLogin'), TYPE
                ) AS OrphanLogins,
                (
                    SELECT idd.LoginName AS [@Name], s.RiskWeight AS [@RiskPoints]
                    FROM #InvalidDefaultDB idd CROSS JOIN #SurfaceRiskWeights s
                    WHERE s.RiskCategory='DefaultDB' AND idd.LoginName = LSP.LoginName
                    FOR XML PATH('InvalidDefaultDB'), TYPE
                ) AS InvalidDefaultDB
            FOR XML PATH('AdditionalRisk'), TYPE
        )
    FOR XML PATH('SecurityReport'), TYPE
    ) AS SecurityReportXML
FROM #LoginSecurityProfile LSP
INNER JOIN CalculatedRiskScores CRS ON LSP.LoginName = CRS.LoginName
GROUP BY LSP.LoginName
ORDER BY MAX(CRS.RiskScore_AccessRights + CRS.RiskScore_Surface) DESC;
