USE [zDBATools]
GO
/****** Object:  Schema [SC]    Script Date: 11/7/2025 7:04:31 AM ******/
CREATE SCHEMA [SC]
GO
/****** Object:  Schema [Shared]    Script Date: 11/7/2025 7:04:31 AM ******/
CREATE SCHEMA [Shared]
GO
/****** Object:  Table [SC].[CapturedSessions]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [SC].[CapturedSessions](
	[ServerName] [varchar](128) NULL,
	[LoginName] [nvarchar](128) NULL,
	[DatabaseName] [nvarchar](128) NULL,
	[Application] [nvarchar](128) NULL,
	[HostName] [nvarchar](128) NULL,
	[LastSessionDateTime] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [SC].[DatabasesSnapshot]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [SC].[DatabasesSnapshot](
	[ServerName] [varchar](128) NOT NULL,
	[DatabaseName] [nvarchar](128) NOT NULL,
	[state] [varchar](128) NULL,
 CONSTRAINT [PK_DatabasesSnapshot] PRIMARY KEY CLUSTERED 
(
	[ServerName] ASC,
	[DatabaseName] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  View [SC].[uvw_DatabasesSnapshot]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE VIEW [SC].[uvw_DatabasesSnapshot]
AS
	SELECT 
		[SC].[DatabasesSnapshot].[ServerName],
		[SC].[CapturedSessions].LoginName, 
		[SC].[DatabasesSnapshot].[DatabaseName],
		[SC].[DatabasesSnapshot].[state] AS [DatabaseState],
		[SC].[CapturedSessions].[Application], 
		[SC].[CapturedSessions].[HostName], 
		[SC].[CapturedSessions].[LastSessionDateTime],
		DATEDIFF(day,[SC].[CapturedSessions].[LastSessionDateTime],GETDATE()) AS [Days Ago]
	FROM [SC].[DatabasesSnapshot] 
	LEFT OUTER JOIN	[SC].[CapturedSessions] ON 
			[SC].[DatabasesSnapshot].[ServerName] = [SC].[CapturedSessions].[ServerName]
		AND [SC].[DatabasesSnapshot].[DatabaseName] = [SC].[CapturedSessions].[DatabaseName]
GO
/****** Object:  Table [SC].[IgnoredApplications]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [SC].[IgnoredApplications](
	[ServerName] [varchar](128) NOT NULL,
	[Application] [varchar](128) NOT NULL,
 CONSTRAINT [PK_IgnoredApplications] PRIMARY KEY CLUSTERED 
(
	[ServerName] ASC,
	[Application] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [SC].[IgnoredDatabases]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [SC].[IgnoredDatabases](
	[ServerName] [varchar](128) NOT NULL,
	[DatabaseName] [varchar](128) NOT NULL,
 CONSTRAINT [PK_IgnoredDatabases] PRIMARY KEY CLUSTERED 
(
	[ServerName] ASC,
	[DatabaseName] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [SC].[IgnoredHostNames]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [SC].[IgnoredHostNames](
	[ServerName] [varchar](128) NOT NULL,
	[HostName] [varchar](128) NOT NULL,
 CONSTRAINT [PK_IgnoredHostNames] PRIMARY KEY CLUSTERED 
(
	[ServerName] ASC,
	[HostName] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [SC].[IgnoredLogins]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [SC].[IgnoredLogins](
	[ServerName] [varchar](128) NOT NULL,
	[LoginName] [varchar](128) NOT NULL,
 CONSTRAINT [PK_IgnoredLogins] PRIMARY KEY CLUSTERED 
(
	[ServerName] ASC,
	[LoginName] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [Shared].[LinkedServers]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [Shared].[LinkedServers](
	[LinkedServerName] [varchar](128) NOT NULL,
	[Enabled] [bit] NULL,
 CONSTRAINT [PK_LinkedServers] PRIMARY KEY CLUSTERED 
(
	[LinkedServerName] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  StoredProcedure [SC].[usp_CaptureSessions]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [SC].[usp_CaptureSessions]
	-- Add the parameters for the stored procedure here
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	DECLARE @LinkedServer NVARCHAR(128);
	DECLARE @SQL NVARCHAR(MAX);

	-- Table to collect results from all servers
	IF OBJECT_ID('tempdb..#Sessions') IS NOT NULL DROP TABLE #Sessions;

	CREATE TABLE #Sessions (
		ServerName NVARCHAR(128),
		LoginName nvarchar(128),
		DatabaseName nvarchar (128),
		Application nvarchar (128),
		HostName nvarchar (128),
		LastSessionDateTime datetime
	);

	-- Cursor to loop through linked servers
	DECLARE LinkedSrvCursor CURSOR FAST_FORWARD FOR
	SELECT [LinkedServerName] 
	FROM [Shared].[LinkedServers] 
	WHERE [Enabled]= 1 AND [LinkedServerName] NOT LIKE 'loopback%';  -- exclude self

	OPEN LinkedSrvCursor;
	FETCH NEXT FROM LinkedSrvCursor INTO @LinkedServer;

	WHILE @@FETCH_STATUS = 0
	BEGIN
		BEGIN TRY
			SET @SQL = '
			INSERT INTO #Sessions
			SELECT ''' + @LinkedServer + ''' AS ServerName,
				   LoginName, DatabaseName, Application, HostName, LastSessionDateTime
			FROM OPENQUERY([' + @LinkedServer + '],
			''SELECT DISTINCT
				TRIM([login_name])			AS LoginName,
				TRIM(DB_NAME(database_id))	AS DatabaseName,
				TRIM([program_name])		AS [Application],
				TRIM([host_name])			AS [HostName],
				MAX(login_time)				AS [LastSessionDateTime]
			FROM 
				sys.dm_exec_sessions
			WHERE 
					login_name IS NOT NULL
				AND is_user_process = 1
			GROUP BY 
				[login_name],[database_id],[host_name],[program_name]'')';

			EXEC (@SQL);
		END TRY
		BEGIN CATCH
			PRINT 'Could not query linked server: ' + @LinkedServer + ' - ' + ERROR_MESSAGE();
		END CATCH;

		FETCH NEXT FROM LinkedSrvCursor INTO @LinkedServer;
	END

	CLOSE LinkedSrvCursor;
	DEALLOCATE LinkedSrvCursor;

	BEGIN
    MERGE [SC].[CapturedSessions] AS target
    USING 
	(
		SELECT
			[ServerName],
			[LoginName],
			[DatabaseName],
			[Application],
			[HostName],
			[LastSessionDateTime]
		FROM #Sessions
		WHERE 
				[LoginName]		NOT IN (SELECT [LoginName]		FROM [SC].[IgnoredLogins]		WHERE [ServerName] = #Sessions.[ServerName])
			AND [DatabaseName]	NOT IN (SELECT [DatabaseName]	FROM [SC].[IgnoredDatabases]	WHERE [ServerName] = #Sessions.[ServerName])
			AND [Application]	NOT IN (SELECT [Application]	FROM [SC].[IgnoredApplications]	WHERE [ServerName] = #Sessions.[ServerName])
			AND [HostName]		NOT IN (SELECT [HostName]		FROM [SC].[IgnoredHostNames]	WHERE [ServerName] = #Sessions.[ServerName])
	) AS source
	ON 
	(
			target.[ServerName] = source.[ServerName]			
		AND target.[LoginName] = source.[LoginName]
        AND target.[DatabaseName] = source.[DatabaseName]
        AND target.[Application] = source.[Application]
        AND target.[HostName] = source.[HostName]
    )
    WHEN MATCHED THEN 
		UPDATE SET target.LastSessionDateTime = source.LastSessionDateTime
    WHEN NOT MATCHED THEN
        INSERT (ServerName,LoginName, DatabaseName, Application, HostName, LastSessionDateTime)
        VALUES (source.ServerName, source.LoginName, source.DatabaseName, source.Application, source.HostName, source.LastSessionDateTime);
	END
END
GO
/****** Object:  StoredProcedure [SC].[usp_RefreshDatabasesSnapshot]    Script Date: 11/7/2025 7:04:31 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [SC].[usp_RefreshDatabasesSnapshot]
	-- Add the parameters for the stored procedure here
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	DECLARE @LinkedServer NVARCHAR(128);
	DECLARE @SQL NVARCHAR(MAX);


	TRUNCATE TABLE [SC].[DatabasesSnapshot]



	-- Cursor to loop through linked servers
	DECLARE LinkedSrvCursor CURSOR FAST_FORWARD FOR
	SELECT [LinkedServerName] 
	FROM [Shared].[LinkedServers] 
	WHERE [Enabled]= 1 AND [LinkedServerName] NOT LIKE 'loopback%';  -- exclude self

	OPEN LinkedSrvCursor;
	FETCH NEXT FROM LinkedSrvCursor INTO @LinkedServer;

	WHILE @@FETCH_STATUS = 0
	BEGIN
		BEGIN TRY
			SET @SQL = '
			INSERT INTO [SC].[DatabasesSnapshot]
			SELECT ''' + @LinkedServer + ''' AS ServerName,[name] AS DatabaseName,[state_desc] AS state
			FROM OPENQUERY([' + @LinkedServer + '],''SELECT [name],[state_desc] FROM sys.databases WHERE database_id > 4'')';

			EXEC (@SQL);
		END TRY
		BEGIN CATCH
			PRINT 'Could not query linked server: ' + @LinkedServer + ' - ' + ERROR_MESSAGE();
		END CATCH;

		FETCH NEXT FROM LinkedSrvCursor INTO @LinkedServer;
	END

	CLOSE LinkedSrvCursor;
	DEALLOCATE LinkedSrvCursor;
END
GO
