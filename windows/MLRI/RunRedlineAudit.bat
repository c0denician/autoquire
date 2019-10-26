@ECHO off

SETLOCAL enableextensions enabledelayedexpansion
SET elevate=.\elevate.cmd
SET helper=.\Helper.bat
SET args=%1

IF NOT EXIST "%elevate%" goto :failed
IF NOT EXIST "%helper%" goto :failed

For /f "tokens=2 delims=[]" %%G in ('ver') Do (set _version=%%G) 
For /f "tokens=2,3,4 delims=. " %%G in ('echo %_version%') Do (set _major=%%G& set _minor=%%H& set _build=%%I) 
Echo Major version: %_major%  Minor Version: %_minor%.%_build%

if "%_major%"=="5" goto sub5
if "%_major%"=="6" goto sub6
if "%_major%"=="10" goto sub6

Echo unsupported OS version
goto:eof

:sub5
call %helper% %args%
GOTO :end

:sub6
ECHO Requesting elevation
call %elevate% %helper% %args%
GOTO :end

:failed
ECHO.
ECHO.
ECHO Failure Encountered:
ECHO Privilege Escalation Script and/or Helper Script not found.
GOTO :end

:end
ENDLOCAL
@ECHO on