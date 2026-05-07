@echo off
setlocal enabledelayedexpansion
title Network Attack Lab

:MAIN_MENU
cls
echo ============================================================
echo   NETWORK ATTACK LAB  -  Select and Run
echo   Monitor: http://localhost:5001
echo ============================================================
echo.
echo   [0]  System Check      (verify honeypots are running)
echo.
echo   [1]  SSH Brute Force    ^=^> detects: SSH-Patator
echo   [2]  FTP Brute Force    ^=^> detects: FTP-Patator
echo   [3]  RDP Brute Force    ^=^> detects: Brute Force
echo   [4]  Telnet Brute Force ^=^> detects: Brute Force
echo   [5]  VNC Brute Force    ^=^> detects: Brute Force
echo.
echo   [6]  SSH DDoS Flood     ^=^> detects: DDoS
echo   [7]  RDP DDoS Flood     ^=^> detects: DDoS
echo.
echo   [8]  Port Scan          ^=^> detects: PortScan
echo.
echo   [9]  Exit
echo.
echo ============================================================
set /p CHOICE="  Select [0-9]: "

if "%CHOICE%"=="0" goto SYSTEM_CHECK
if "%CHOICE%"=="1" goto ATTACK_SSH
if "%CHOICE%"=="2" goto ATTACK_FTP
if "%CHOICE%"=="3" goto ATTACK_RDP
if "%CHOICE%"=="4" goto ATTACK_TELNET
if "%CHOICE%"=="5" goto ATTACK_VNC
if "%CHOICE%"=="6" goto DDOS_SSH
if "%CHOICE%"=="7" goto DDOS_RDP
if "%CHOICE%"=="8" goto SCAN
if "%CHOICE%"=="9" goto EXIT

echo   Invalid choice.
pause >nul
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:SYSTEM_CHECK
cls
echo ============================================================
echo   SYSTEM CHECK
echo ============================================================
echo.
python -c "
import socket
PORTS = [(2222,'SSH'),(2121,'FTP'),(2323,'Telnet'),(13389,'RDP'),(5901,'VNC'),(7001,'ScanTrap'),(7005,'ScanTrap'),(7010,'ScanTrap')]
ok = fail = 0
for port, name in PORTS:
    s = socket.socket()
    s.settimeout(1)
    r = s.connect_ex(('127.0.0.1', port))
    s.close()
    if r == 0:
        print(f'  [OK]   {port}  ({name})')
        ok += 1
    else:
        print(f'  [FAIL] {port}  ({name})')
        fail += 1
print()
print('All OK - ready to test.' if fail == 0 else f'WARNING: {fail} port(s) not reachable. Is app.py running?')
"
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:ATTACK_SSH
cls
echo   Running: SSH Brute Force (25 attempts, 0.2s delay) -> port 2222
echo   Watch: http://localhost:5001
echo.
python -c "
import socket, time
for i in range(25):
    s = socket.socket()
    s.settimeout(2)
    try: s.connect(('127.0.0.1', 2222))
    except: pass
    finally: s.close()
    time.sleep(0.2)
    if (i+1) % 5 == 0: print(f'  {i+1}/25 attempts')
print('Done. Check dashboard for SSH-Patator.')
"
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:ATTACK_FTP
cls
echo   Running: FTP Brute Force (25 attempts, 0.2s delay) -> port 2121
echo   Watch: http://localhost:5001
echo.
python -c "
import socket, time
for i in range(25):
    s = socket.socket()
    s.settimeout(2)
    try: s.connect(('127.0.0.1', 2121))
    except: pass
    finally: s.close()
    time.sleep(0.2)
    if (i+1) % 5 == 0: print(f'  {i+1}/25 attempts')
print('Done. Check dashboard for FTP-Patator.')
"
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:ATTACK_RDP
cls
echo   Running: RDP Brute Force (25 attempts, 0.2s delay) -> port 13389
echo   Watch: http://localhost:5001
echo.
python -c "
import socket, time
for i in range(25):
    s = socket.socket()
    s.settimeout(2)
    try: s.connect(('127.0.0.1', 13389))
    except: pass
    finally: s.close()
    time.sleep(0.2)
    if (i+1) % 5 == 0: print(f'  {i+1}/25 attempts')
print('Done. Check dashboard for Brute Force.')
"
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:ATTACK_TELNET
cls
echo   Running: Telnet Brute Force (25 attempts, 0.2s delay) -> port 2323
echo   Watch: http://localhost:5001
echo.
python -c "
import socket, time
for i in range(25):
    s = socket.socket()
    s.settimeout(2)
    try: s.connect(('127.0.0.1', 2323))
    except: pass
    finally: s.close()
    time.sleep(0.2)
    if (i+1) % 5 == 0: print(f'  {i+1}/25 attempts')
print('Done. Check dashboard for Brute Force.')
"
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:ATTACK_VNC
cls
echo   Running: VNC Brute Force (25 attempts, 0.2s delay) -> port 5901
echo   Watch: http://localhost:5001
echo.
python -c "
import socket, time
for i in range(25):
    s = socket.socket()
    s.settimeout(2)
    try: s.connect(('127.0.0.1', 5901))
    except: pass
    finally: s.close()
    time.sleep(0.2)
    if (i+1) % 5 == 0: print(f'  {i+1}/25 attempts')
print('Done. Check dashboard for Brute Force.')
"
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:DDOS_SSH
cls
echo   Running: SSH DDoS Flood (200 connections, no delay) -> port 2222
echo   Watch: http://localhost:5001
echo.
python -c "
import socket, time
t0 = time.time()
for i in range(200):
    s = socket.socket()
    s.settimeout(0.05)
    try: s.connect(('127.0.0.1', 2222))
    except: pass
    finally: s.close()
    if (i+1) % 50 == 0:
        print(f'  {i+1}/200  ({(i+1)/(time.time()-t0):.0f} conn/s)')
print(f'Done in {time.time()-t0:.1f}s. Check dashboard for DDoS.')
"
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:DDOS_RDP
cls
echo   Running: RDP DDoS Flood (200 connections, no delay) -> port 13389
echo   Watch: http://localhost:5001
echo.
python -c "
import socket, time
t0 = time.time()
for i in range(200):
    s = socket.socket()
    s.settimeout(0.05)
    try: s.connect(('127.0.0.1', 13389))
    except: pass
    finally: s.close()
    if (i+1) % 50 == 0:
        print(f'  {i+1}/200  ({(i+1)/(time.time()-t0):.0f} conn/s)')
print(f'Done in {time.time()-t0:.1f}s. Check dashboard for DDoS.')
"
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:SCAN
cls
echo   Running: Port Scan (common ports + trap ports 7001-7010)
echo   Watch: http://localhost:5001
echo.
python -c "
import socket, time
ports = [21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5900,8080,
         7001,7002,7003,7004,7005,7006,7007,7008,7009,7010]
open_ports = []
for p in ports:
    s = socket.socket()
    s.settimeout(0.3)
    r = s.connect_ex(('127.0.0.1', p))
    s.close()
    if r == 0:
        open_ports.append(p)
        print(f'  OPEN  {p}')
    time.sleep(0.01)
print(f'Scan done. Open: {open_ports}. Check dashboard for PortScan.')
"
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────
:EXIT
endlocal
exit /b 0
