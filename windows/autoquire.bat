@ECHO off
::--------------------------------------------------------
:: Developed by ITSEC Asia @ 2018
:: Contribute to c0denician
::--------------------------------------------------------

::--------------------------------------------------------------------------------------------------------------------------
:: Setting variables
::--------------------------------------------------------------------------------------------------------------------------

set directory=".\Results\%COMPUTERNAME%"
tools\mkdir.exe %directory% > NUL
date /t > %directory%\date_time.txt
time /t >> %directory%\date_time.txt
RRS\tools\robocopy.exe MLRI\ %directory%\redline /MIR

set os=""
set arch=""
:: --------------------
:: Duming Memory
:: --------------------
:acquire_memory
	ECHO Dumping memory
	RRS\tools\mkdir.exe %directory%\pmem
	PMEM\winpmem_3.2.exe -o %directory%\pmem\%computername%.raw --volume_format raw -dd -t
:: --------------------------------------------------------------------------------------------------------------------------
:: Collecting Prefetch so it's not overwritten by the tools we are running.
:: --------------------------------------------------------------------------------------------------------------------------
:collect_prefetch
	ECHO Copying Prefetch Files
	RRS\tools\mkdir.exe %directory%\prefetch
	RRS\tools\robocopy.exe %SystemRoot%\Prefetch %directory%\prefetch /ZB /copy:DTSOU /r:1 /w:1 /ts /FP /np  > NUL
	
:: ---------------------------------------------------------------
:: Determine Operating System and Arch Type for Variable Setting
:: ---------------------------------------------------------------
:setvars
	ver | %WINDIR%\System32\find.exe "5." > NUL
	if %ERRORLEVEL% == 0 set os=legacy
	if "%PROCESSOR_ARCHITECTURE%" == "x86" set arch=32
	if "%PROCESSOR_ARCHITECTURE%" == "AMD64" set arch=64
	if %arch% == 32 (set rawcop=tools\RawCopy.exe) else (set rawcop=tools\RawCopy64.exe)
	if %os% == legacy (set userpath=%systemdrive%\Documents and Settings) else (set userpath=%systemdrive%\Users)
:: --------------------------------
:: Creating output Directories
::---------------------------------
:makedir
	ECHO Making Outpath Directory
	RRS\tools\mkdir.exe %directory%\eventlogs
	RRS\tools\mkdir.exe %directory%\registry
	RRS\tools\mkdir.exe %directory%\networking
	RRS\tools\mkdir.exe %directory%\process
	RRS\tools\mkdir.exe %directory%\autoruns
	RRS\tools\mkdir.exe %directory%\userinfo
	RRS\tools\mkdir.exe %directory%\timeline
	RRS\tools\mkdir.exe %directory%\md5hashes
	RRS\tools\mkdir.exe %directory%\domains
	
:: --------------------------------------------------------------------------------------------------------------------------
:: Collecting Volatile Data Now
:: --------------------------------------------------------------------------------------------------------------------------
:acquire_volatile
:: --------------------------------------------------------------------------------------------------------------------------
:: Collecting Network Information
:: --------------------------------------------------------------------------------------------------------------------------
	ECHO Getting Network Information
	RRS\tools\tcpvcon.exe -a -c -n /accepteula >> %directory%\networking\%COMPUTERNAME%-TCPVcon_Port-to-Process-mapping.csv
	%SystemRoot%\System32\ipconfig.exe /displaydns >> %directory%\networking\%COMPUTERNAME%-IPconfig_DisplayDNS.txt
	%SystemRoot%\System32\net.exe file >> %directory%\networking\%COMPUTERNAME%-Net_File-transfer-over-netbios.txt
	%SystemRoot%\System32\netstat.exe -ano >> %directory%\networking\%COMPUTERNAME%-Netstat.txt
:: --------------------------------------------------------------------------------------------------------------------------
:: Collecting System Information
:: --------------------------------------------------------------------------------------------------------------------------	
	ECHO Getting System Information
	RRS\tools\pslist.exe -t /accepteula >> %directory%\process\%COMPUTERNAME%-PSList_Treeview.txt
	%SystemRoot%\system32\wbem\wmic job list full >> %directory%\process\%COMPUTERNAME%-Jobs.txt
	RRS\tools\handle.exe -a /accepteula >> %directory%\process\%COMPUTERNAME%-Handle_Objects.txt
	RRS\tools\listdlls.exe /accepteula >> %directory%\process\%COMPUTERNAME%-List_DLLs.txt
:: --------------------------------------------------------------------------------------------------------------------------
:: Collecting Active Logon Sessions
:: --------------------------------------------------------------------------------------------------------------------------
:user_information	
	ECHO Copying Active Logon Sessions
	RRS\tools\logonsessions.exe /accepteula >> %directory%\userinfo\%COMPUTERNAME%-Logonsessions_Active-logon-sessions.txt
	
:: --------------------------------------------------------------------------------------------------------------------------
:: Collecting Domain Information
:: --------------------------------------------------------------------------------------------------------------------------
:domain_information
	ECHO Obtaining Domain Information
	net group "Domain Admins" /domain >> %directory%\domains\domain_admins.txt
	net group "Enterprise Admins" /domain >> %directory%\domains\enterprise_admins.txt
	
:: --------------------------------------------------------------------------------------------------------------------------
:: Starting to acquire nonvolatile data
:: --------------------------------------------------------------------------------------------------------------------------
:acquire_nonvolatile
:: --------------------------------------------------------------------------------------------------------------------------
:: Colelcting Autoruns information
:: --------------------------------------------------------------------------------------------------------------------------
	ECHO Copying Autoruns
	RRS\tools\autorunsc.exe -f /accepteula * >> %directory%\autoruns\%COMPUTERNAME%-Autostart_All.txt
:: --------------------------------------------------------------------------------------------------------------------------
:: Collecting Registry, Event Logs, Timeline, and Hashes
:: --------------------------------------------------------------------------------------------------------------------------
	if %os% == legacy (
		for /f "delims=" %%U in ('dir "%userpath%" /b' ) do (
			:: ----------------------------
			echo Collecting NTUSER.DAT Files
			:: ----------------------------
			RRS\tools\fget.exe -extract "%userpath%\%%~nxU\NTUSER.DAT" %directory%\registry\NTUSER.DAT_%%~nxU
		)
		:: ---------------------------------
		echo Collecting Windows Event Logs
		:: ---------------------------------
		RRS\tools\fget.exe -extract %SystemRoot%\System32\Config\SecEvent.Evt %directory%\eventlogs\SecEvent.Evt
		RRS\tools\fget.exe -extract %SystemRoot%\System32\Config\SysEvent.Evt %directory%\eventlogs\SysEvent.Evt
		RRS\tools\fget.exe -extract %SystemRoot%\System32\Config\AppEvent.Evt %directory%\eventlogs\AppEvent.Evt
		GOTO misc_artifacts
	)
	:: --------------------------------------
	:: If Windows Vista+ this will process
	:: --------------------------------------
	) else (
		for /f "delims=" %%U in ('dir "%userpath%" /b' ) do (
			:: ----------------------------
			echo Collecting NTUSER.DAT Files
			:: ----------------------------
			RRS\tools\fget.exe -extract "%userpath%\%%~nxU\NTUSER.DAT" %directory%\registry\NTUSER.DAT_%%~nxU
			RRS\tools\fget.exe -extract "%userpath%\%%~nxU\appdata\local\microsoft\windows\usrclass.dat" %directory%\registry\UsrClass.DAT_%%~nxU
		)
		:: ---------------------------------
		echo Collecting Windows Event Logs
		:: ---------------------------------
		RRS\tools\fget.exe -extract %SystemRoot%\System32\winevt\Logs\Security.evtx %directory%\eventlogs\Security.evtx
		RRS\tools\fget.exe -extract %SystemRoot%\System32\winevt\Logs\System.evtx %directory%\eventlogs\System.evtx
		RRS\tools\fget.exe -extract %SystemRoot%\System32\winevt\Logs\Application.evtx %directory%\eventlogs\Application.evtx
		RRS\tools\fget.exe -extract "%SystemRoot%\System32\winevt\Logs\Windows Powershell.evtx" %directory%\eventlogs\WindowsPowershell.evtx
		GOTO misc_artifacts
	)
:misc_artifacts
	:: --------------------------------------------------------------------------------------------------------------------------
	:: Collecting Timeline Information
	:: --------------------------------------------------------------------------------------------------------------------------
	ECHO Copying $MFT
	RRS\tools\fget.exe -extract %systemdrive%\$MFT %directory%\timeline\MFT_%COMPUTERNAME%
	ECHO Copying $LogFile
	RRS\tools\fget.exe -extract %systemdrive%\$LogFile %directory%\timeline\LogFile_%COMPUTERNAME%
	:: --------------------------------------------------------------------------------------------------------------------------
	:: Collecting Registry Information
	:: --------------------------------------------------------------------------------------------------------------------------
	ECHO Copying Registry Files	
	RRS\tools\fget.exe -extract %SystemRoot%\system32\config\software %directory%\registry\SOFTWARE
	RRS\tools\fget.exe -extract %SystemRoot%\system32\config\system %directory%\registry\SYSTEM
	RRS\tools\fget.exe -extract %SystemRoot%\system32\config\security %directory%\registry\SECURITY
	RRS\tools\fget.exe -extract %SystemRoot%\system32\config\sam %directory%\registry\SAM
	:: --------------------------------------
	:: Hashing Files
	:: --------------------------------------
	ECHO Hashing Files			
	RRS\tools\md5deep.exe -z -r -l -o e -s "%SystemDrive%\*" >> %directory%\md5hashes\Hashes.txt
		
:loki
	ECHO Begin Loki and Yara scan
	LOKI\loki.exe
		
:redline_artifacts
    ECHO Begin Redline collection
	cd %directory%\redline
	Call RunRedlineAudit.bat

@ECHO off	
ECHO.
ECHO.
ECHO.
ECHO Your collection is now complete. Check your artifacts before leaving.
ECHO.
ECHO.
ECHO.
:: ------------------------------------------------------------------------