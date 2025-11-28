/* ================================================================================================
   SQL Server Access, Permissions & Risk Evaluation Report  -- FINAL v7.9
   Ziad Samhan
   ------------------------------------------------------------------------------------------------
   PURPOSE:
       • Inventory server logins and per-database principals, aggregate permissions, and compute risk.
       • Detect high-privilege accounts (sysadmin, dbo, db_owner), orphaned users, disabled/unused logins.
       • Capture logins that exist but have NO database mapping (DatabaseName = NULL)
   ------------------------------------------------------------------------------------------------
   ACTION MODEL:
       1) Address Immediately: SysAdmin / DB Owner / db_owner member
       2) Review: Non-admins with any database/server permissions
       3) Clean-up: Disabled or orphaned logins/users, SA login not secured
	
	------------------------------------------------------------------------------------------------
	v7.9 – resolve collation conflicts, enforce NVARCHAR(MAX) in STRING_AGG, and add optional count-based outputs

	- Fix: apply COLLATE SQL_Latin1_General_CP1_CI_AS to aggregated text to prevent collation conflicts
	- Fix: cast each concatenated element inside STRING_AGG to NVARCHAR(MAX) to avoid 8000-byte truncation
	- Enh: optional compact outputs that replace long aggregated strings with counts:
		  GrantedServerPermissionsCount, GrantedServerRolesCount,
		  GrantedDatabasePermissionsCount, GrantedDatabaseRolesCount
	- Enh: remaned shorten column names 

   ------------------------------------------------------------------------------------------------
   SAFE TO RUN — READ ONLY
   ================================================================================================ */

SET NOCOUNT ON;

IF OBJECT_ID('tempdb..#AccessMatrix') IS NOT NULL DROP TABLE #AccessMatrix;

CREATE TABLE #AccessMatrix
(
    [SrvName]               sysname,
    [DbName]             sysname NULL,
    [Login]                sysname NULL,
    [LoginType]                nvarchar(60) NULL,
    [LoginDisabled]            bit,
    [IsSA]                bit,
    [DbUser]               sysname NULL,
    [PrincipalType]          nvarchar(60),
    [DefaultSchema]            sysname NULL,

    IsSysAdmin               bit,
    [IsDbOwner]     bit,
    [IsDbOwnerMember]          bit,

    [HasDDL]                   bit,
    [HasWrite]                 bit,
    HasRead                  bit,
    HasExecute               bit,

    IsOrphaned               bit,

    RiskScore                int,
    RiskLevel                varchar(10),
    RiskFactors              nvarchar(4000),

    [SrvPerms] nvarchar(50),
    [DbPerms] nvarchar(50),
    RecommendedAction        nvarchar(1000)
);

DECLARE @batch NVARCHAR(MAX) = N'';

-- ===============================================
-- Per-database principal insert (all databases except tempdb)
-- ===============================================
SELECT @batch = @batch + N'
USE ' + QUOTENAME(d.name) + N';

INSERT INTO #AccessMatrix
(
    [SrvName],
    [DbName],
    [Login],
    [LoginType],
    [LoginDisabled],
    [IsSA],
    [DbUser],
    [PrincipalType],
    [DefaultSchema],
    IsSysAdmin,
    [IsDbOwner],
    [IsDbOwnerMember],
    [HasDDL],
    [HasWrite],
    HasRead,
    HasExecute,
    IsOrphaned,
    RiskScore,
    RiskLevel,
    RiskFactors,
    [SrvPerms],
    [DbPerms],
    RecommendedAction
)
SELECT
    @@SERVERNAME AS [SrvName],
    DB_NAME() AS [DbName],
    sp.name AS [Login],
    sp.type_desc AS [LoginType],
    CAST(ISNULL(sp.is_disabled,0) AS bit) AS [LoginDisabled],
    CAST(CASE WHEN sp.sid=0x01 THEN 1 ELSE 0 END AS bit) AS [IsSA],
    dp.name AS [DbUser],
    dp.type_desc AS [PrincipalType],
    dp.default_schema_name AS [DefaultSchema],
    CAST(CASE WHEN ISNULL(IS_SRVROLEMEMBER(''sysadmin'', sp.name),0)=1 THEN 1 ELSE 0 END AS bit) AS IsSysAdmin,
    CAST(CASE WHEN dp.name=''dbo'' THEN 1 ELSE 0 END AS bit) AS [IsDbOwner],
    CAST(CASE WHEN EXISTS(
        SELECT 1 FROM sys.database_role_members drm
        JOIN sys.database_principals r ON r.principal_id=drm.role_principal_id
        WHERE r.name=''db_owner'' AND drm.member_principal_id=dp.principal_id
    ) THEN 1 ELSE 0 END AS bit) AS [IsDbOwnerMember],

    f.[HasDDL],
    f.[HasWrite],
    f.HasRead,
    f.HasExecute,
    f.IsOrphaned,

    CASE
        WHEN ISNULL(IS_SRVROLEMEMBER(''sysadmin'', sp.name),0)=1 THEN 100
        WHEN dp.name=''dbo'' OR EXISTS(
            SELECT 1 FROM sys.database_role_members drm
            JOIN sys.database_principals r ON r.principal_id=drm.role_principal_id
            WHERE r.name=''db_owner'' AND drm.member_principal_id=dp.principal_id
        ) THEN 100
        ELSE CASE WHEN calc.BaseScore<5 THEN 5 WHEN calc.BaseScore>100 THEN 100 ELSE calc.BaseScore END
    END AS RiskScore,

    CASE
    WHEN ISNULL(IS_SRVROLEMEMBER(''sysadmin'', sp.name),0)=1 THEN ''High''
    WHEN dp.name=''dbo'' OR EXISTS(
        SELECT 1 FROM sys.database_role_members drm
        JOIN sys.database_principals r ON r.principal_id=drm.role_principal_id
        WHERE r.name=''db_owner'' AND drm.member_principal_id=dp.principal_id
    ) THEN ''High''
    WHEN sp.sid = 0x01 AND sp.name <> ''sa'' AND ISNULL(sp.is_disabled,0)=1 THEN ''Low''  -- Secured SA
    WHEN calc.BaseScore>=100 THEN ''High''
    WHEN calc.BaseScore>=60 THEN ''Medium''
    ELSE ''Low''
END AS RiskLevel,


    RTRIM(CONCAT(
        CASE WHEN ISNULL(IS_SRVROLEMEMBER(''sysadmin'', sp.name),0)=1 THEN ''SysAdmin; '' ELSE '''' END,
        CASE WHEN sp.sid=0x01 AND sp.name=''sa'' THEN ''SA login not renamed; '' ELSE '''' END,
        CASE WHEN sp.sid=0x01 AND ISNULL(sp.is_disabled,0)=0 THEN ''SA login not disabled; '' ELSE '''' END,
        CASE WHEN dp.name=''dbo'' OR EXISTS(
            SELECT 1 FROM sys.database_role_members drm
            JOIN sys.database_principals r ON r.principal_id=drm.role_principal_id
            WHERE r.name=''db_owner'' AND drm.member_principal_id=dp.principal_id
        ) THEN ''db_owner/dbo; '' ELSE '''' END,
        CASE WHEN f.[HasDDL]=1 THEN ''DDL perms; '' ELSE '''' END,
        CASE WHEN f.[HasWrite]=1 THEN ''Write perms; '' ELSE '''' END,
        CASE WHEN f.HasExecute=1 THEN ''Execute perms; '' ELSE '''' END,
        CASE WHEN f.HasRead=1 THEN ''Read perms; '' ELSE '''' END,
        CASE WHEN dp.default_schema_name=''dbo'' THEN ''Default schema dbo; '' ELSE '''' END,
        CASE WHEN ISNULL(sp.is_disabled,0)=1 THEN ''Login disabled; '' ELSE '''' END,
        CASE WHEN f.IsOrphaned=1 THEN ''Orphaned user; '' ELSE '''' END
    )) AS RiskFactors,

    -- Server permissions + roles
	CONCAT( N''Permissions='',
		CAST((
			SELECT COUNT(*)
			FROM sys.server_permissions p
			WHERE p.grantee_principal_id = sp.principal_id
			  AND p.state_desc IN (N''GRANT'', N''GRANT_WITH_GRANT_OPTION'')
		) AS NVARCHAR(20)),
		N''; Roles='',
		CAST((
			SELECT COUNT(*)
			FROM sys.server_role_members srm
			WHERE srm.member_principal_id = sp.principal_id
		) AS NVARCHAR(20))
	) AS [SrvPerms],

    -- Database permissions + role memberships
    
CONCAT(
    N''DB Perms='',
    CAST((
        SELECT COUNT(*)
        FROM sys.database_permissions p
        WHERE p.grantee_principal_id = dp.principal_id
          AND p.state_desc IN (N''GRANT'', N''GRANT_WITH_GRANT_OPTION'')
    ) AS NVARCHAR(20)),
    N''; DB Roles='',
    CAST((
        SELECT COUNT(*)
        FROM sys.database_role_members drm
        WHERE drm.member_principal_id = dp.principal_id
    ) AS NVARCHAR(20))
) AS [DbPerms],

    CASE
    -- SA not secured (not renamed OR not disabled)
    WHEN sp.sid = 0x01 AND (sp.name = ''sa'' OR ISNULL(sp.is_disabled,0)=0) THEN
        ''Clean-up: Rename and/or disable SA login''
    -- SA secured (renamed AND disabled)
    WHEN sp.sid = 0x01 AND sp.name <> ''sa'' AND ISNULL(sp.is_disabled,0)=1 THEN
        ''No immediate risk: SA login secured (renamed and disabled)''
    -- Other high-privilege accounts
    WHEN ISNULL(IS_SRVROLEMEMBER(''sysadmin'', sp.name),0)=1
      OR dp.name=''dbo''
      OR EXISTS(
          SELECT 1 FROM sys.database_role_members drm
          JOIN sys.database_principals r ON r.principal_id=drm.role_principal_id
          WHERE r.name=''db_owner'' AND drm.member_principal_id=dp.principal_id
      ) THEN ''Address Immediately: Highly privileged account (SysAdmin or DB Owner).''
    -- Disabled or orphaned accounts
    WHEN ISNULL(sp.is_disabled,0)=1 OR f.IsOrphaned=1 THEN
         ''Clean-up: Disabled or orphaned account.''
    ELSE ''Review: Account has database permissions.''
END AS RecommendedAction

FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON dp.sid=sp.sid
CROSS APPLY (
    SELECT
        CAST(CASE WHEN EXISTS(
            SELECT 1 FROM sys.database_permissions p
            WHERE p.grantee_principal_id=dp.principal_id
              AND p.permission_name IN (''ALTER'',''ALTER ANY SCHEMA'',''CONTROL'',''CREATE TABLE'',''CREATE PROCEDURE'',''CREATE FUNCTION'',''CREATE VIEW'')
              AND p.state_desc IN (''GRANT'',''GRANT_WITH_GRANT_OPTION'')
        )
        OR EXISTS(
            SELECT 1 FROM sys.database_role_members drm
            JOIN sys.database_principals r ON r.principal_id=drm.role_principal_id
            WHERE drm.member_principal_id=dp.principal_id AND r.name=''db_ddladmin''
        ) THEN 1 ELSE 0 END AS bit) AS [HasDDL],

        CAST(CASE WHEN EXISTS(
            SELECT 1 FROM sys.database_permissions p
            WHERE p.grantee_principal_id=dp.principal_id
              AND p.permission_name IN (''INSERT'',''UPDATE'',''DELETE'')
              AND p.state_desc IN (''GRANT'',''GRANT_WITH_GRANT_OPTION'')
        )
        OR EXISTS(
            SELECT 1 FROM sys.database_role_members drm
            JOIN sys.database_principals r ON r.principal_id=drm.role_principal_id
            WHERE drm.member_principal_id=dp.principal_id AND r.name=''db_datawriter''
        ) THEN 1 ELSE 0 END AS bit) AS [HasWrite],

        CAST(CASE WHEN EXISTS(
            SELECT 1 FROM sys.database_permissions p
            WHERE p.grantee_principal_id=dp.principal_id
              AND p.permission_name=''SELECT''
              AND p.state_desc IN (''GRANT'',''GRANT_WITH_GRANT_OPTION'')
        )
        OR EXISTS(
            SELECT 1 FROM sys.database_role_members drm
            JOIN sys.database_principals r ON r.principal_id=drm.role_principal_id
            WHERE drm.member_principal_id=dp.principal_id AND r.name=''db_datareader''
        ) THEN 1 ELSE 0 END AS bit) AS HasRead,

        CAST(CASE WHEN EXISTS(
            SELECT 1 FROM sys.database_permissions p
            WHERE p.grantee_principal_id=dp.principal_id
              AND p.permission_name=''EXECUTE''
              AND p.state_desc IN (''GRANT'',''GRANT_WITH_GRANT_OPTION'')
        ) THEN 1 ELSE 0 END AS bit) AS HasExecute,

        CAST(CASE WHEN dp.type_desc IN (''SQL_USER'',''WINDOWS_USER'',''WINDOWS_GROUP'') AND (sp.sid IS NULL OR dp.sid<>sp.sid)
                  OR (dp.type_desc=''SQL_USER'' AND sp.name IS NULL) THEN 1 ELSE 0 END AS bit) AS IsOrphaned
) AS f
CROSS APPLY (
    SELECT
        (CASE WHEN f.[HasDDL]=1 THEN 60 ELSE 0 END) +
        (CASE WHEN f.[HasWrite]=1 THEN 50 ELSE 0 END) +
        (CASE WHEN f.HasExecute=1 THEN 35 ELSE 0 END) +
        (CASE WHEN f.HasRead=1 THEN 20 ELSE 0 END) +
        (CASE WHEN dp.default_schema_name=''dbo'' THEN 10 ELSE 0 END) +
        (CASE WHEN ISNULL(sp.is_disabled,0)=1 THEN -5 ELSE 0 END) +
        (CASE WHEN f.IsOrphaned=1 THEN -5 ELSE 0 END) AS BaseScore
) AS calc
WHERE dp.type_desc IN (''SQL_USER'',''WINDOWS_USER'',''WINDOWS_GROUP'')
  AND dp.name NOT IN (''INFORMATION_SCHEMA'',''guest'',''sys'')
  AND dp.name NOT LIKE ''NT SERVICE\%''
  AND sp.name NOT LIKE ''NT AUTHORITY\%''
  AND (sp.name IS NULL OR sp.name NOT LIKE ''##%##'');
'
FROM sys.databases d
WHERE d.state=0 AND d.name<>'tempdb';

EXEC sp_executesql @batch;

-- ===============================================
-- Capture server-level logins with no database mapping
-- ===============================================
INSERT INTO #AccessMatrix
(
    [SrvName],
    [DbName],
    [Login],
    [LoginType],
    [LoginDisabled],
    [IsSA],
    [DbUser],
    [PrincipalType],
    [DefaultSchema],
    IsSysAdmin,
    [IsDbOwner],
    [IsDbOwnerMember],
    [HasDDL],
    [HasWrite],
    HasRead,
    HasExecute,
    IsOrphaned,
    RiskScore,
    RiskLevel,
    RiskFactors,
    [SrvPerms],
    RecommendedAction
)
SELECT
    @@SERVERNAME AS [SrvName],
    NULL AS [DbName],
    sp.name AS [Login],
    sp.type_desc AS [LoginType],
    CAST(ISNULL(sp.is_disabled,0) AS bit) AS [LoginDisabled],
    CAST(CASE WHEN sp.sid=0x01 THEN 1 ELSE 0 END AS bit) AS [IsSA],
    NULL AS [DbUser],
    N'NO_DB_ACCESS' AS [PrincipalType],
    NULL AS [DefaultSchema],
    CAST(CASE WHEN ISNULL(IS_SRVROLEMEMBER('sysadmin', sp.name),0)=1 THEN 1 ELSE 0 END AS bit) AS IsSysAdmin,
    0 AS [IsDbOwner],
    0 AS [IsDbOwnerMember],
    0 AS [HasDDL],
    0 AS [HasWrite],
    0 AS HasRead,
    0 AS HasExecute,
    0 AS IsOrphaned,
    CASE WHEN ISNULL(IS_SRVROLEMEMBER('sysadmin', sp.name),0)=1 THEN 100
         WHEN ISNULL(sp.is_disabled,0)=1 THEN 10
         ELSE 20 END AS RiskScore,
    CASE WHEN ISNULL(IS_SRVROLEMEMBER('sysadmin', sp.name),0)=1 THEN 'High'
         ELSE 'Low' END AS RiskLevel,
    RTRIM(CONCAT('Login exists with no database mapping; ',
        CASE WHEN ISNULL(sp.is_disabled,0)=1 THEN 'Disabled login; ' ELSE 'Enabled login; ' END
    )) AS RiskFactors,


	CONCAT( N'Permissions=',
		CAST((
			SELECT COUNT(*)
			FROM sys.server_permissions p
			WHERE p.grantee_principal_id = sp.principal_id
			  AND p.state_desc IN (N'GRANT', N'GRANT_WITH_GRANT_OPTION')
		) AS NVARCHAR(20)),
		N'; Roles=',
		CAST((
			SELECT COUNT(*)
			FROM sys.server_role_members srm
			WHERE srm.member_principal_id = sp.principal_id
		) AS NVARCHAR(20))
	) AS [SrvPerms],

    CASE
    -- SA not secured
    WHEN sp.sid = 0x01 AND (sp.name = 'sa' OR ISNULL(sp.is_disabled,0)=0) THEN
        'Clean-up: Rename and/or disable SA login'
    -- SA secured
    WHEN sp.sid = 0x01 AND sp.name <> 'sa' AND ISNULL(sp.is_disabled,0)=1 THEN
        'No immediate risk: SA login secured (renamed and disabled)'
    -- Other high-privilege accounts
    WHEN ISNULL(IS_SRVROLEMEMBER('sysadmin', sp.name),0)=1 THEN
        'Address Immediately: SysAdmin login'
    -- Disabled accounts
    WHEN ISNULL(sp.is_disabled,0)=1 THEN
        'Clean-up: Disabled login'
    ELSE
        'Review: Login with no database access'
END AS RecommendedAction

FROM sys.server_principals sp
WHERE sp.type IN ('S','U','G')
  AND sp.name NOT LIKE '##%##'
  AND sp.name NOT LIKE 'NT SERVICE\%'
  AND sp.name NOT LIKE 'NT AUTHORITY\%'
  AND NOT EXISTS (SELECT 1 FROM #AccessMatrix a WHERE a.[Login]=sp.name);

-- ===============================================
-- Final consolidated report
-- ===============================================
SELECT
    [SrvName],
    [DbName],
    [Login],
    [LoginType],
    [LoginDisabled],
    [IsSA],
    IsSysAdmin,
    [SrvPerms],
    [DbUser],
    [PrincipalType],
    [DefaultSchema],
    [IsDbOwner],
    [IsDbOwnerMember],
    IsOrphaned,
    [DbPerms],
    [HasDDL],
    [HasWrite],
    HasRead,
    HasExecute,
    RiskScore,
    RiskLevel,
    RiskFactors,
    RecommendedAction
FROM #AccessMatrix
ORDER BY RiskScore DESC, RiskLevel DESC, [SrvName], [DbName], [DbUser];
