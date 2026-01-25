@echo off
REM =====================================================
REM Corp Domain Logon Script
REM Last Updated: 2025-12-01
REM Contact: IT Support x4567
REM =====================================================

echo Initializing user environment...

REM Set network time
net time \\DC01 /set /yes > nul 2>&1

REM Map network drives
echo Mapping network drives...
net use H: \\filesvr\users\%username% /persistent:no > nul 2>&1
if errorlevel 1 echo Warning: Could not map H: drive

net use S: \\filesvr\shared /persistent:no > nul 2>&1
if errorlevel 1 echo Warning: Could not map S: drive

net use P: \\filesvr\projects /persistent:no > nul 2>&1
if errorlevel 1 echo Warning: Could not map P: drive

REM Set environment variables
set CORP_ENV=PRODUCTION
set LOG_PATH=\\logsvr\logs\%COMPUTERNAME%

REM Run group-specific scripts
if exist "\\dc01\netlogon\dept\%DEPT%.bat" (
    call "\\dc01\netlogon\dept\%DEPT%.bat"
)

REM Printers
rundll32 printui.dll,PrintUIEntry /in /n "\\printsvr\MainPrinter" > nul 2>&1

echo Logon script complete.
exit /b 0
