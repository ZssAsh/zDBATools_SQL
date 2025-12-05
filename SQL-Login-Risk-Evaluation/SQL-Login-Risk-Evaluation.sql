-- ==========================================================
-- 1.0 [ RISK WEIGHT CONFIG TABLES ]
-- Configurable Risk Weights 
-- * Access Rights Risks ( Roles + Permissions)
-- * Attack Surface Risk (Permissions with Grant, Direct Ganted Permissions, Owned Jobs,Credentials,Proxies,Linked Servers,Impersonation,OrphanLogins,Invalid Default Database)
-- * Login Security Risks ( Login Type and Status, Policy Check, Expiry Check,SA, SysAdmin previlages)
-- ==========================================================

-- 1.1 Granted Permissions Risks - Weights
IF OBJECT_ID('tempdb..#AccessRightsRisks') IS NOT NULL DROP TABLE #AccessRightsRisks;
CREATE TABLE #AccessRightsRisks (
    PermissionName NVARCHAR(128) NOT NULL,
    RiskPoints INT NOT NULL
);
INSERT INTO #AccessRightsRisks(PermissionName, RiskPoints)
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
IF OBJECT_ID('tempdb..#AttackSurfaceRiskWeights') IS NOT NULL DROP TABLE #AttackSurfaceRiskWeights;
CREATE TABLE #AttackSurfaceRiskWeights (
      RiskCategory   VARCHAR(100),
      ConditionValue VARCHAR(200),
      RiskWeight     DECIMAL(10,2),
      Notes          VARCHAR(200),
      IsActive       BIT DEFAULT 1
);
INSERT INTO #AttackSurfaceRiskWeights VALUES
('SysAdmin',            '1',                100,    'Privilege Escalation → Grantable rights',                  1),
('GrantOption',         'ANY',              0.3,    'Privilege Escalation → Grantable rights',                  1),
('JobOwner',            'HasJobs',          6,      'Can execute agent jobs',                                   1),
('ProxyOwner',          'HasProxies',       8,      'Run code using external auth',                             1),
('CredentialOwner',     'HasCredential',    10,     'Holds stored passwords',                                   1),
('Impersonation',       'HasTargets',       10,     'Can EXECUTE AS → Privilege Hop',                           1),
('LinkedServer',        'HasLinkedServer',  7,      'Lateral movement to remote server',                        1),
('OrphanLogin',         'IsOrphan',         5,      'Login has no matching user in any DB',                     1),
('DefaultDB',           'InvalidDB',        4,      'Default database is offline, dropped, or inaccessible',    1),
('DirectPermissions',   'YES',              1,      'Permission granted directly instead of through role',      1);

-- 1.3 Login Security Risks - Weights
IF OBJECT_ID('tempdb..#SecurityRiskWeights') IS NOT NULL DROP TABLE #SecurityRiskWeights;
CREATE TABLE #SecurityRiskWeights (
    Category        NVARCHAR(50),
    CheckValue      NVARCHAR(50),
    RiskPoints      INT,
    Description     NVARCHAR(200),
    Active          BIT
);
INSERT INTO #SecurityRiskWeights VALUES
('LoginType',       'SQL_LOGIN',            6,  'SQL logins are password-based and higher exposure',    1),
('LoginType',       'WINDOWS_LOGIN',        2,  'Protected by AD policies and lockout',                 1),
('LoginType',       'CONTAINED_USER',       3,  'Scoped but not AD enforced',                           1),
('LoginType',       'EXTERNAL_USER',        1,  'AAD/Federated − lowest exposure',                      1),
('PolicyCheck',     '0',                   10, 'Password complexity not enforced',                      1),
('PolicyCheck',     '1',                    0,  'Secure default',                                       1),
('ExpiryCheck',     '0',                    8,  'No password change enforced',                          1),
('ExpiryCheck',     '1',                    0,  'Secure default',                                       1),
('LoginDisabled',   '1',                    0,  'Disabled login = no exposure',                         1),
('LoginDisabled',   '0',                    2,  'Active login = some exposure',                         1),
('BuiltinSA',       '0',                    15, 'SA Not Disabled (active) = CRITICAL RISK',             1),
('SaNotRenamed',    'YES',                  10, 'Default SA login name not changed = higher risk',      1),
('SaNotRenamed',    'NO',                   0,  'SA login renamed = safer',                             1),
('StaleLogin',      '90',                   7,  'Dormant login may be exploited',                       1);


-- ==========================================================
-- 2.0 [ Attack Surface Risk Data]
-- ==========================================================
-- 2.1 Owned Jobs
IF OBJECT_ID('tempdb..#OwnedJobs') IS NOT NULL DROP TABLE #OwnedJobs;
SELECT suser_sname(owner_sid) AS LoginName, j1.name AS JobName
INTO #OwnedJobs
FROM msdb.dbo.sysjobs j1

-- 2.2 Owned Credentials
IF OBJECT_ID('tempdb..#OwnedCredentials') IS NOT NULL DROP TABLE #OwnedCredentials;
SELECT 
    c.name AS CredentialName, 
    suser_sname(c.credential_id) AS LoginName
INTO #OwnedCredentials
FROM sys.credentials c;

-- 2.3 Owned Proxies
IF OBJECT_ID('tempdb..#OwnedProxies') IS NOT NULL DROP TABLE #OwnedProxies;
SELECT 
    pr.name AS ProxyName, 
    suser_sname(pr.credential_id) AS LoginName
INTO #OwnedProxies
FROM msdb.dbo.sysproxies pr;

-- 2.4 Linked Servers
IF OBJECT_ID('tempdb..#LinkedServers') IS NOT NULL DROP TABLE #LinkedServers;
SELECT DISTINCT 
    sp.name AS LoginName, 
    ls.name AS LinkedServerName
INTO #LinkedServers
FROM sys.server_principals sp
JOIN sys.linked_logins ll ON sp.principal_id = ll.local_principal_id
JOIN sys.servers ls ON ls.server_id = ll.server_id
WHERE sp.type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP');

-- 2.5 Impersonation Targets
IF OBJECT_ID('tempdb..#ImpersonationTargets') IS NOT NULL DROP TABLE #ImpersonationTargets;
SELECT DISTINCT 
    p.name AS LoginName, 
    dp.name AS ImpersonatedLogin
INTO #ImpersonationTargets
FROM sys.server_principals p
JOIN sys.server_permissions sp ON sp.grantee_principal_id = p.principal_id
JOIN sys.server_principals dp ON dp.principal_id = sp.grantor_principal_id
WHERE sp.permission_name = 'IMPERSONATE';

-- 2.6 Server Roles
IF OBJECT_ID('tempdb..#ServerRoles') IS NOT NULL DROP TABLE #ServerRoles;
SELECT 
    sp.name AS LoginName, 
    r2.name AS Role
INTO #ServerRoles
FROM sys.server_principals sp
JOIN sys.server_role_members rm ON rm.member_principal_id = sp.principal_id
JOIN sys.server_principals r2 ON rm.role_principal_id = r2.principal_id
WHERE sp.type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP');

-- 2.7 Orphan Logins
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

-- 2.8 Invalid Default Database
IF OBJECT_ID('tempdb..#InvalidDefaultDB') IS NOT NULL DROP TABLE #InvalidDefaultDB;
CREATE TABLE #InvalidDefaultDB(LoginName sysname);
INSERT INTO #InvalidDefaultDB(LoginName)
SELECT sp.name
FROM sys.server_principals sp
LEFT JOIN sys.databases d ON sp.default_database_name = d.name
WHERE sp.type IN ('S','U') AND (d.name IS NULL OR d.state <> 0);

-- ==========================================================
-- 3.0 [ Login Security Data ]
-- ==========================================================


-- ==========================================================
-- 4.0 [ Report Output ]
-- ==========================================================
-- Login Security Profile
IF OBJECT_ID('tempdb..#LoginProfile') IS NOT NULL DROP TABLE #LoginProfile;
CREATE TABLE #LoginProfile (
    LoginName               SYSNAME NOT NULL,
    LoginType               NVARCHAR(60) NOT NULL,
    IsSysAdmin              BIT NOT NULL DEFAULT 0,
    IsSA                    BIT NOT NULL DEFAULT 0, 
    LoginDisabled           BIT NOT NULL,
    LastUpdateDate          DATETIME NULL,
    IsPolicyChecked         BIT NULL,
    IsExpirationChecked     BIT NULL,
    SecurableClass          NVARCHAR(50) NOT NULL,
    PermissionName          NVARCHAR(128) NOT NULL,
    WithGrantOption         BIT NOT NULL DEFAULT 0,
    PermissionSource        NVARCHAR(50) NOT NULL
);

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
        INSERT INTO #LoginProfile(
            LoginName, LoginType, IsSysAdmin, IsSA, LoginDisabled, LastUpdateDate,
            IsPolicyChecked, IsExpirationChecked, SecurableClass, PermissionName, 
            WithGrantOption, PermissionSource
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

-- ==========================================================
-- 4. Set-based Risk Score Computation + XML
-- ==========================================================
WITH AccessRightsRisk AS
(
    SELECT
        LSP.LoginName,
        MAX(CAST(LSP.IsSysAdmin AS INT)) AS IsSysAdmin,
        MAX(CAST(LSP.IsSA AS INT)) AS IsSA,
        CASE 
            WHEN MAX(CAST(LSP.IsSysAdmin AS INT))=1 OR MAX(CAST(LSP.IsSA AS INT))=1 THEN 100 -- change to use #AttackSurfaceRiskWeights.SysAdmin
            ELSE SUM(ISNULL(PR.RiskPoints,0))
        END AS RiskScore,
        SUM(CASE WHEN LSP.WithGrantOption=1 THEN ISNULL(PR.RiskPoints,0)*ISNULL(sw.RiskWeight,0) ELSE 0 END) AS GrantOptionRisk
    FROM #LoginProfile LSP
    LEFT JOIN #AccessRightsRisks PR
        ON LSP.PermissionName COLLATE DATABASE_DEFAULT = PR.PermissionName COLLATE DATABASE_DEFAULT
    LEFT JOIN #AttackSurfaceRiskWeights sw ON sw.RiskCategory='GrantOption'
    GROUP BY LSP.LoginName
),
JobRisk AS
(
    SELECT oj.LoginName, MAX(s.RiskWeight) AS JobRisk
    FROM #OwnedJobs oj
    CROSS JOIN #AttackSurfaceRiskWeights s
    WHERE s.RiskCategory='JobOwner'
    GROUP BY oj.LoginName
),
ProxyRisk AS
(
    SELECT op.LoginName, MAX(s.RiskWeight) AS ProxyRisk
    FROM #OwnedProxies op
    CROSS JOIN #AttackSurfaceRiskWeights s
    WHERE s.RiskCategory='ProxyOwner'
    GROUP BY op.LoginName
),
CredentialRisk AS
(
    SELECT oc.LoginName, MAX(s.RiskWeight) AS CredentialRisk
    FROM #OwnedCredentials oc
    CROSS JOIN #AttackSurfaceRiskWeights s
    WHERE s.RiskCategory='CredentialOwner'
    GROUP BY oc.LoginName
),
ImpersonationRisk AS
(
    SELECT it.LoginName, MAX(s.RiskWeight) AS ImpersonationRisk
    FROM #ImpersonationTargets it
    CROSS JOIN #AttackSurfaceRiskWeights s
    WHERE s.RiskCategory='Impersonation'
    GROUP BY it.LoginName
),
LinkedServerRisk AS
(
    SELECT ls.LoginName, MAX(s.RiskWeight) AS LinkedServerRisk
    FROM #LinkedServers ls
    CROSS JOIN #AttackSurfaceRiskWeights s
    WHERE s.RiskCategory='LinkedServer'
    GROUP BY ls.LoginName
),
OrphanLoginRisk AS
(
    SELECT ol.LoginName, MAX(s.RiskWeight) AS OrphanLoginRisk
    FROM #OrphanLogins ol
    CROSS JOIN #AttackSurfaceRiskWeights s
    WHERE s.RiskCategory='OrphanLogin'
    GROUP BY ol.LoginName
),
DefaultDBRisk AS
(
    SELECT idd.LoginName, MAX(s.RiskWeight) AS DefaultDBRisk
    FROM #InvalidDefaultDB idd
    CROSS JOIN #AttackSurfaceRiskWeights s
    WHERE s.RiskCategory='DefaultDB'
    GROUP BY idd.LoginName
),
DirectPermissions AS
(
    SELECT
        LSP.LoginName,
        SUM(CASE WHEN LSP.PermissionSource='Direct' THEN ISNULL(PR.RiskPoints,0)*ISNULL(sw.RiskWeight,0) ELSE 0 END) AS DirectGrantRisk
    FROM #LoginProfile LSP
    LEFT JOIN #AccessRightsRisks PR
        ON LSP.PermissionName COLLATE DATABASE_DEFAULT = PR.PermissionName COLLATE DATABASE_DEFAULT
    LEFT JOIN #AttackSurfaceRiskWeights sw ON sw.RiskCategory='DirectPermissions'
    WHERE LSP.PermissionName <> 'CONNECT SQL'
    GROUP BY LSP.LoginName
),
LoginType As
(
    SELECT 
        LSP.LoginName,
        MAX(SR.RiskPoints) AS RiskPoints
    FROM #LoginProfile LSP 
    CROSS JOIN #SecurityRiskWeights SR 
    WHERE SR.Category ='LoginType' AND SR.CheckValue = LSP.LoginType
    GROUP BY LSP.LoginName
),
PolicyCheck As
(
    SELECT 
        LSP.LoginName,
        MAX(SR.RiskPoints) AS RiskPoints
    FROM #LoginProfile LSP 
    CROSS JOIN #SecurityRiskWeights SR 
    WHERE SR.Category ='PolicyCheck' AND SR.CheckValue = LSP.IsPolicyChecked
    GROUP BY LSP.LoginName
),
ExpiryCheck As
(
    SELECT 
        LSP.LoginName,
        MAX(SR.RiskPoints) AS RiskPoints
    FROM #LoginProfile LSP 
    CROSS JOIN #SecurityRiskWeights SR 
    WHERE SR.Category ='ExpiryCheck' AND SR.CheckValue = LSP.IsExpirationChecked
    GROUP BY LSP.LoginName
),
DisableCheck As
(
    SELECT 
        LSP.LoginName,
        MAX(SR.RiskPoints) AS RiskPoints
    FROM #LoginProfile LSP 
    CROSS JOIN #SecurityRiskWeights SR 
    WHERE SR.Category ='LoginDisabled' AND SR.CheckValue = LSP.LoginDisabled
    GROUP BY LSP.LoginName
),
SaEnabled As
(
    SELECT 
        LSP.LoginName,
        MAX(SR.RiskPoints) AS RiskPoints
    FROM #LoginProfile LSP 
    CROSS JOIN #SecurityRiskWeights SR 
    WHERE 
            LSP.IsSA =1
        AND SR.Category ='BuiltinSA' AND SR.CheckValue = LSP.LoginDisabled

    GROUP BY LSP.LoginName
),
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
        AND SR.CheckValue = CASE WHEN LOWER(LSP.LoginName) = 'sa' THEN 'YES' ELSE 'NO' END
    GROUP BY LSP.LoginName
),
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
)

SELECT
    LP.LoginName,
    ACC_RSK.IsSA,
    ACC_RSK.IsSysAdmin,
    LP.LoginType,
    LP.LoginDisabled,
    LP.LastUpdateDate,

    ACC_RSK.RiskScore AS AccessRights_RiskScore,
    ISNULL(ACC_RSK.GrantOptionRisk,0)+
    + ISNULL(SUR_OJR.JobRisk,0)
    + ISNULL(SUR_OPR.ProxyRisk,0)
    + ISNULL(SUR_OCR.CredentialRisk,0)
    + ISNULL(SUR_IMR.ImpersonationRisk,0)
    + ISNULL(SUR_LSR.LinkedServerRisk,0)
    + ISNULL(SUR_OLR.OrphanLoginRisk,0)
    + ISNULL(SUR_DDR.DefaultDBRisk,0)
    + ISNULL(SUR_DPR.DirectGrantRisk,0)  AS Attack_Surface_RiskScore,

    ISNULL(SEC_SLT.RiskPoints,0)
    +ISNULL(SEC_SPC.RiskPoints,0)
    +ISNULL(SEC_ECR.RiskPoints,0)
    + CASE WHEN ACC_RSK.IsSA =1
        THEN ISNULL(SEC_SSE.RiskPoints,0)
        ELSE ISNULL(SEC_SDC.RiskPoints,0)
        END
    +ISNULL(SEC_SSN.RiskPoints,0)
    +ISNULL(SEC_SLR.RiskPoints,0) AS Security_RiskScore,

    -------------------
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
    + ISNULL(SEC_SSN.RiskPoints,0) AS Overall_RiskScore,
    -------------------
    -- SecurityReport XML
    (
        SELECT
            ACC_RSK.RiskScore AS [Totals/@AccessRights],
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
            ) AS [Totals/@SurfaceRisk],
            (
                ISNULL(SEC_SLT.RiskPoints,0)
                + ISNULL(SEC_SPC.RiskPoints,0)
                + ISNULL(SEC_ECR.RiskPoints,0)
                + CASE WHEN ACC_RSK.IsSA =1
                    THEN ISNULL(SEC_SSE.RiskPoints,0)
                    ELSE ISNULL(SEC_SDC.RiskPoints,0)
                    END
                + ISNULL(SEC_SSN.RiskPoints,0)
                + ISNULL(SEC_SLR.RiskPoints,0)
            ) AS [Totals/@SecurityRisk],
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
            ) AS [Totals/@Overall],

            -- Access Rights - Details
            -- Access Rights - Roles
-- Access Rights Risks XML
(
    SELECT
        -- ROLES
        (
            SELECT
                sr.Role AS [@Name],
                CASE WHEN sp.is_fixed_role = 1 THEN 1 ELSE 0 END AS [@IsSystemRole]
            FROM #ServerRoles sr
            JOIN sys.server_principals sp ON sr.Role = sp.name
            WHERE sr.LoginName = LP.LoginName
            FOR XML PATH('Role'), TYPE
        ) AS [Roles],

        -- PERMISSIONS
        (
            SELECT
                LSP.PermissionName AS [@Name],
                ISNULL(PR.RiskPoints,0) AS [@RiskPoints]
            FROM #LoginProfile LSP
            LEFT JOIN #AccessRightsRisks PR ON LSP.PermissionName = PR.PermissionName
            WHERE LSP.LoginName = LP.LoginName
            FOR XML PATH('Permission'), TYPE
        ) AS [Permissions]

    FOR XML PATH('AccessRightsRisks'), TYPE
),


            -- Attack Surface Risk - Permissions
            (
                SELECT
                (
                    SELECT
                        -- ============================
                        -- DIRECT PERMISSIONS
                        -- ============================
                        (
                            SELECT
                                LSP.PermissionName AS [@Name],
                                CASE WHEN LSP.PermissionName <>'CONNECT SQL' THEN ISNULL(PR.RiskPoints,0) * ISNULL(sw.RiskWeight,0) END AS [@RiskPoints]
                            FROM #LoginProfile LSP
                            LEFT JOIN #AccessRightsRisks PR
                                ON LSP.PermissionName = PR.PermissionName
                            LEFT JOIN #AttackSurfaceRiskWeights sw
                                ON sw.RiskCategory = 'DirectPermissions'
                            WHERE LSP.LoginName = LP.LoginName
                              AND LSP.PermissionSource = 'Direct'
                              --AND LSP.PermissionName <> 'CONNECT SQL'
                            FOR XML PATH('Permission'), TYPE
                        ) AS Direct,

                        -- ============================
                        -- WITH GRANT OPTION PERMISSIONS
                        -- ============================
                        (
                            SELECT
                                LSP.PermissionName AS [@Name],
                                ISNULL(PR.RiskPoints,0) * ISNULL(sw.RiskWeight,0) AS [@RiskPoints]
                            FROM #LoginProfile LSP
                            LEFT JOIN #AccessRightsRisks PR
                                ON LSP.PermissionName = PR.PermissionName
                            LEFT JOIN #AttackSurfaceRiskWeights sw
                                ON sw.RiskCategory = 'GrantOption'
                            WHERE 
                                LSP.LoginName = LP.LoginName
                                AND LSP.WithGrantOption = 1

                            FOR XML PATH('Permission'), TYPE
                        ) AS WithGrant

                    WHERE EXISTS (
                        SELECT 1
                        FROM #LoginProfile LSP
                        WHERE LSP.LoginName = LP.LoginName
                    )
                    FOR XML PATH('Permissions'), TYPE
                ),
                    -- Attack Surface Risk - Owned Jobs
                    (
                        SELECT
                            CASE 
                                WHEN EXISTS (SELECT 1 FROM #OwnedJobs WHERE LoginName = LP.LoginName)
                                THEN
                                    (
                                        SELECT
                                            -- Parent attribute
                                            (SELECT SUM(RiskWeight)
                                             FROM #AttackSurfaceRiskWeights
                                             WHERE RiskCategory = 'JobOwner') AS [@RiskPoints],

                                            -- Child job elements
                                            (
                                                SELECT 
                                                    oj.JobName AS [@Name]
                                                FROM #OwnedJobs oj
                                                CROSS JOIN #AttackSurfaceRiskWeights sw
                                                WHERE sw.RiskCategory = 'JobOwner'
                                                  AND oj.LoginName = LP.LoginName
                                                FOR XML PATH('Job'), TYPE
                                            )
                                        FOR XML PATH('OwnedJobs'), TYPE
                                    )
                            END
                    ),

                    -- Attack Surface Risk - Proxies
                    (
                        SELECT op.ProxyName AS [@Name], s.RiskWeight AS [@RiskPoints]
                        FROM #OwnedProxies op CROSS JOIN #AttackSurfaceRiskWeights s
                        WHERE s.RiskCategory='ProxyOwner' AND op.LoginName = LP.LoginName
                        FOR XML PATH('Proxy'), TYPE
                    ),
                    -- Attack Surface Risk - Credentials
                    (
                        SELECT oc.CredentialName AS [@Name], s.RiskWeight AS [@RiskPoints]
                        FROM #OwnedCredentials oc CROSS JOIN #AttackSurfaceRiskWeights s
                        WHERE s.RiskCategory='CredentialOwner' AND oc.LoginName = LP.LoginName
                        FOR XML PATH('Credential'), TYPE
                    ),
                    -- Attack Surface Risk - Impersonation
                    (
                        SELECT it.ImpersonatedLogin AS [@Name], s.RiskWeight AS [@RiskPoints]
                        FROM #ImpersonationTargets it CROSS JOIN #AttackSurfaceRiskWeights s
                        WHERE s.RiskCategory='Impersonation' AND it.LoginName = LP.LoginName
                        FOR XML PATH('Impersonation'), TYPE
                    ),
                    -- Attack Surface Risk - LinkedServers
                    (
                        SELECT ls.LinkedServerName AS [@Name], s.RiskWeight AS [@RiskPoints]
                        FROM #LinkedServers ls CROSS JOIN #AttackSurfaceRiskWeights s
                        WHERE s.RiskCategory='LinkedServer' AND ls.LoginName = LP.LoginName
                        FOR XML PATH('LinkedServer'), TYPE
                    ),
                    -- Attack Surface Risk - OrphanLogins
                    (
                        SELECT ol.LoginName AS [@Name], s.RiskWeight AS [@RiskPoints]
                        FROM #OrphanLogins ol CROSS JOIN #AttackSurfaceRiskWeights s
                        WHERE s.RiskCategory='OrphanLogin' AND ol.LoginName = LP.LoginName
                        FOR XML PATH('OrphanLogin'), TYPE
                    ),
                    -- Attack Surface Risk - InvalidDefaultDB
                    (
                        SELECT idd.LoginName AS [@Name], s.RiskWeight AS [@RiskPoints]
                        FROM #InvalidDefaultDB idd CROSS JOIN #AttackSurfaceRiskWeights s
                        WHERE s.RiskCategory='DefaultDB' AND idd.LoginName = LP.LoginName
                        FOR XML PATH('InvalidDefaultDB'), TYPE
                    )
                FOR XML PATH('SurfaceRisk'), TYPE
            ),
            (
            SELECT
                SR.Category AS [@Category],
                --SR.CheckValue AS [@CheckValue],
                CASE 
                    WHEN SR.Category='LoginDisabled' AND LP.IsSA =1 
                        THEN (SELECT RiskPoints FROM #SecurityRiskWeights WHERE Category='BuiltinSA')
                    ELSE SR.RiskPoints
                END AS [@RiskPoints]
            FROM #SecurityRiskWeights SR
            WHERE SR.Category IN ('LoginType','PolicyCheck','ExpiryCheck','LoginDisabled','SaNotRenamed','StaleLogin')
              AND EXISTS (
                  SELECT 1
                  FROM #LoginProfile LP2
                  WHERE LP2.LoginName = LP.LoginName
                    AND (
                        (SR.Category='LoginType' AND SR.CheckValue = LP2.LoginType) OR
                        (SR.Category='PolicyCheck' AND SR.CheckValue = LP2.IsPolicyChecked) OR
                        (SR.Category='ExpiryCheck' AND SR.CheckValue = LP2.IsExpirationChecked) OR
                        (SR.Category='LoginDisabled' AND SR.CheckValue = LP2.LoginDisabled) OR
                        (SR.Category='SaNotRenamed' AND SUSER_SID(LP2.LoginName)=0x01 AND SR.CheckValue = CASE WHEN LOWER(LP2.LoginName)='sa' THEN 'YES' ELSE 'NO' END) OR
                        (SR.Category='StaleLogin' AND DATEDIFF(DAY, LP2.LastUpdateDate, GETDATE()) > CAST(SR.CheckValue AS INT))
                    )
              )
            FOR XML PATH('Check'), TYPE
        ) AS [SecurityRisk]
        FOR XML PATH('SecurityReport'), TYPE
    ) AS SecurityReportXML

FROM (SELECT DISTINCT LoginName,LoginType,LoginDisabled,LastUpdateDate,IsSA FROM #LoginProfile) LP
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
ORDER BY OverAll_RiskScore DESC;
