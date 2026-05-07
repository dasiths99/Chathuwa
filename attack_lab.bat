@echo off
setlocal enabledelayedexpansion
title Network Attack Lab - Manual Testing Tool

:MAIN_MENU
cls
echo ============================================================
echo   NETWORK ATTACK LAB  ^|  Manual Testing Only
echo   For testing the Network Flow Monitor detection system
echo ============================================================
echo.
echo   --- Brute Force ---
echo   [1]  SSH Brute Force       (port 22)
echo   [2]  FTP Brute Force       (port 21)
echo   [3]  RDP Brute Force       (port 3389)
echo   [4]  Telnet Brute Force    (port 23)
echo   [5]  VNC Brute Force       (port 5900)
echo   [6]  Custom Brute Force    (you choose host, port, count)
echo.
echo   --- DDoS / Flood ---
echo   [7]  TCP Flood DDoS        (flood connections to a port)
echo   [8]  UDP Flood DDoS        (flood UDP packets)
echo.
echo   --- Port Scan ---
echo   [9]  Port Scan             (sweep common ports)
echo   [10] Custom Port Scan      (you choose host, port range)
echo.
echo   [0]  Exit
echo.
echo ============================================================
set /p CHOICE="  Select attack type [0-10]: "

if "%CHOICE%"=="1"  goto ATTACK_SSH
if "%CHOICE%"=="2"  goto ATTACK_FTP
if "%CHOICE%"=="3"  goto ATTACK_RDP
if "%CHOICE%"=="4"  goto ATTACK_TELNET
if "%CHOICE%"=="5"  goto ATTACK_VNC
if "%CHOICE%"=="6"  goto ATTACK_CUSTOM
if "%CHOICE%"=="7"  goto DDOS_TCP
if "%CHOICE%"=="8"  goto DDOS_UDP
if "%CHOICE%"=="9"  goto SCAN_DEFAULT
if "%CHOICE%"=="10" goto SCAN_CUSTOM
if "%CHOICE%"=="0"  goto EXIT

echo   [!] Invalid choice. Press any key to try again.
pause >nul
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────────────
:ATTACK_SSH
cls
echo ============================================================
echo   SSH Brute Force Attack (port 22)
echo ============================================================
echo   Default target: 127.0.0.1  (honeypot on port 2222)
echo.
set /p BF_HOST="  Target host [default: 127.0.0.1]: "
if "%BF_HOST%"=="" set BF_HOST=127.0.0.1
set /p BF_COUNT="  Number of attempts [default: 40]: "
if "%BF_COUNT%"=="" set BF_COUNT=40
set /p BF_DELAY="  Delay between attempts in seconds [default: 0.05]: "
if "%BF_DELAY%"=="" set BF_DELAY=0.05
goto RUN_BRUTE_FORCE_22

:ATTACK_FTP
cls
echo ============================================================
echo   FTP Brute Force Attack (port 21)
echo ============================================================
echo   Default target: 127.0.0.1  (honeypot on port 2121)
echo.
set /p BF_HOST="  Target host [default: 127.0.0.1]: "
if "%BF_HOST%"=="" set BF_HOST=127.0.0.1
set /p BF_COUNT="  Number of attempts [default: 40]: "
if "%BF_COUNT%"=="" set BF_COUNT=40
set /p BF_DELAY="  Delay between attempts in seconds [default: 0.05]: "
if "%BF_DELAY%"=="" set BF_DELAY=0.05
goto RUN_BRUTE_FORCE_21

:ATTACK_RDP
cls
echo ============================================================
echo   RDP Brute Force Attack (port 3389)
echo ============================================================
echo   Default target: 127.0.0.1  (honeypot on port 13389)
echo.
set /p BF_HOST="  Target host [default: 127.0.0.1]: "
if "%BF_HOST%"=="" set BF_HOST=127.0.0.1
set /p BF_COUNT="  Number of attempts [default: 40]: "
if "%BF_COUNT%"=="" set BF_COUNT=40
set /p BF_DELAY="  Delay between attempts in seconds [default: 0.05]: "
if "%BF_DELAY%"=="" set BF_DELAY=0.05
goto RUN_BRUTE_FORCE_3389

:ATTACK_TELNET
cls
echo ============================================================
echo   Telnet Brute Force Attack (port 23)
echo ============================================================
echo   Default target: 127.0.0.1  (honeypot on port 2323)
echo.
set /p BF_HOST="  Target host [default: 127.0.0.1]: "
if "%BF_HOST%"=="" set BF_HOST=127.0.0.1
set /p BF_COUNT="  Number of attempts [default: 40]: "
if "%BF_COUNT%"=="" set BF_COUNT=40
set /p BF_DELAY="  Delay between attempts in seconds [default: 0.05]: "
if "%BF_DELAY%"=="" set BF_DELAY=0.05
goto RUN_BRUTE_FORCE_23

:ATTACK_VNC
cls
echo ============================================================
echo   VNC Brute Force Attack (port 5900)
echo ============================================================
echo   Default target: 127.0.0.1  (honeypot on port 5901)
echo.
set /p BF_HOST="  Target host [default: 127.0.0.1]: "
if "%BF_HOST%"=="" set BF_HOST=127.0.0.1
set /p BF_COUNT="  Number of attempts [default: 40]: "
if "%BF_COUNT%"=="" set BF_COUNT=40
set /p BF_DELAY="  Delay between attempts in seconds [default: 0.05]: "
if "%BF_DELAY%"=="" set BF_DELAY=0.05
goto RUN_BRUTE_FORCE_5900

:ATTACK_CUSTOM
cls
echo ============================================================
echo   Custom Brute Force Attack
echo ============================================================
echo.
set /p BF_HOST="  Target host [default: 127.0.0.1]: "
if "%BF_HOST%"=="" set BF_HOST=127.0.0.1
set /p BF_PORT="  Target port (22, 21, 3389, 23, 5900): "
if "%BF_PORT%"=="" set BF_PORT=22
set /p BF_COUNT="  Number of attempts [default: 40]: "
if "%BF_COUNT%"=="" set BF_COUNT=40
set /p BF_DELAY="  Delay between attempts in seconds [default: 0.05]: "
if "%BF_DELAY%"=="" set BF_DELAY=0.05
goto RUN_BRUTE_FORCE_CUSTOM

:: ─────────────────────────────────────────────────────────────────────────────
:RUN_BRUTE_FORCE_22
set BF_PORT=22
goto RUN_BRUTE_FORCE_CUSTOM

:RUN_BRUTE_FORCE_21
set BF_PORT=21
goto RUN_BRUTE_FORCE_CUSTOM

:RUN_BRUTE_FORCE_3389
set BF_PORT=3389
goto RUN_BRUTE_FORCE_CUSTOM

:RUN_BRUTE_FORCE_23
set BF_PORT=23
goto RUN_BRUTE_FORCE_CUSTOM

:RUN_BRUTE_FORCE_5900
set BF_PORT=5900
goto RUN_BRUTE_FORCE_CUSTOM

:RUN_BRUTE_FORCE_CUSTOM
cls
echo ============================================================
echo   Running: Brute Force on %BF_HOST%:%BF_PORT%
echo   Attempts: %BF_COUNT%  Delay: %BF_DELAY%s
echo ============================================================
echo   Watch: http://localhost:5001  (Network Flow Monitor)
echo   Expected label: SSH-Patator / FTP-Patator / Brute Force
echo ============================================================
echo.
python -c "
import socket, time, sys

host    = '%BF_HOST%'
port    = %BF_PORT%
count   = %BF_COUNT%
delay   = %BF_DELAY%

# Honeypot port map (network.py passive monitor listens on these)
HONEYPOT = {22: 2222, 21: 2121, 23: 2323, 3389: 13389, 5900: 5901}
LOCALHOST = {'127.0.0.1', 'localhost', '::1'}

target_port = HONEYPOT.get(port, port) if host in LOCALHOST else port
if host in LOCALHOST and port in HONEYPOT:
    print(f'[INFO] Localhost -- remapping :{port} -> :{target_port} (honeypot)')

print(f'Target : {host}:{target_port}  Attempts: {count}  Delay: {delay}s')
print()

for i in range(count):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect((host, target_port))
    except OSError:
        pass
    finally:
        try: s.close()
        except OSError: pass
    if delay > 0:
        time.sleep(delay)
    if (i + 1) % 10 == 0 or i == 0:
        print(f'  ... {i+1}/{count} attempts')

print()
print('Done. Check Network Flow Monitor -> ML Predictions feed for Brute Force.')
"
echo.
echo ============================================================
echo   Attack finished. Check the ML Predictions feed.
echo ============================================================
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────────────
:DDOS_TCP
cls
echo ============================================================
echo   TCP Flood DDoS Attack
echo ============================================================
echo   Sends a rapid burst of TCP connections to overwhelm a port.
echo   Default target: 127.0.0.1:2222  (honeypot, simulates :22)
echo.
set /p DD_HOST="  Target host [default: 127.0.0.1]: "
if "%DD_HOST%"=="" set DD_HOST=127.0.0.1
set /p DD_PORT="  Target port [default: 2222]: "
if "%DD_PORT%"=="" set DD_PORT=2222
set /p DD_COUNT="  Number of flood packets [default: 600]: "
if "%DD_COUNT%"=="" set DD_COUNT=600
cls
echo ============================================================
echo   Running: TCP Flood DDoS on %DD_HOST%:%DD_PORT%
echo   Packets: %DD_COUNT%  (no delay - maximum speed)
echo ============================================================
echo   Watch: http://localhost:5001  (Network Flow Monitor)
echo   Expected label: DDoS
echo ============================================================
echo.
python -c "
import socket, time
host  = '%DD_HOST%'
port  = %DD_PORT%
count = %DD_COUNT%
print(f'TCP flood -> {host}:{port}  ({count} connections, no delay)')
t0 = time.time()
for i in range(count):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.05)
    try: s.connect((host, port))
    except OSError: pass
    finally:
        try: s.close()
        except OSError: pass
    if (i + 1) % 100 == 0:
        print(f'  ... {i+1}/{count}  ({(i+1)/(time.time()-t0):.0f} conn/s)')
elapsed = time.time() - t0
print(f'Done. {count} packets in {elapsed:.1f}s ({count/elapsed:.0f} conn/s)')
print('Check Network Flow Monitor -> DDoS should be flagged.')
"
echo.
echo ============================================================
echo   Attack finished. Check the ML Predictions feed.
echo ============================================================
echo.
pause
goto MAIN_MENU

:DDOS_UDP
cls
echo ============================================================
echo   UDP Flood DDoS Attack
echo ============================================================
echo   Sends a rapid burst of large UDP packets.
echo.
set /p DU_HOST="  Target host [default: 127.0.0.1]: "
if "%DU_HOST%"=="" set DU_HOST=127.0.0.1
set /p DU_PORT="  Target port [default: 9999]: "
if "%DU_PORT%"=="" set DU_PORT=9999
set /p DU_COUNT="  Number of packets [default: 600]: "
if "%DU_COUNT%"=="" set DU_COUNT=600
cls
echo ============================================================
echo   Running: UDP Flood DDoS on %DU_HOST%:%DU_PORT%
echo   Packets: %DU_COUNT%  (large payloads, no delay)
echo ============================================================
echo   Watch: http://localhost:5001  (Network Flow Monitor)
echo   Expected label: DDoS
echo ============================================================
echo.
python -c "
import socket, time
host  = '%DU_HOST%'
port  = %DU_PORT%
count = %DU_COUNT%
payload = b'X' * 1300
print(f'UDP flood -> {host}:{port}  ({count} x 1300-byte packets)')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
t0 = time.time()
for i in range(count):
    try: s.sendto(payload, (host, port))
    except OSError: pass
    if (i + 1) % 100 == 0:
        print(f'  ... {i+1}/{count}  ({(i+1)/(time.time()-t0):.0f} pkt/s)')
s.close()
elapsed = time.time() - t0
print(f'Done. {count} packets in {elapsed:.1f}s ({count/elapsed:.0f} pkt/s)')
print('Check Network Flow Monitor -> DDoS should be flagged.')
"
echo.
echo ============================================================
echo   Attack finished. Check the ML Predictions feed.
echo ============================================================
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────────────
:SCAN_DEFAULT
cls
echo ============================================================
echo   Port Scan (sweep common ports)
echo ============================================================
echo   Default target: 127.0.0.1
echo.
set /p SCAN_HOST="  Target host [default: 127.0.0.1]: "
if "%SCAN_HOST%"=="" set SCAN_HOST=127.0.0.1
set /p SCAN_TIMEOUT="  Timeout per port in seconds [default: 0.3]: "
if "%SCAN_TIMEOUT%"=="" set SCAN_TIMEOUT=0.3
goto RUN_SCAN_DEFAULT

:SCAN_CUSTOM
cls
echo ============================================================
echo   Custom Port Scan
echo ============================================================
echo.
set /p SCAN_HOST="  Target host [default: 127.0.0.1]: "
if "%SCAN_HOST%"=="" set SCAN_HOST=127.0.0.1
set /p SCAN_START="  Start port [default: 1]: "
if "%SCAN_START%"=="" set SCAN_START=1
set /p SCAN_END="  End port [default: 1024]: "
if "%SCAN_END%"=="" set SCAN_END=1024
set /p SCAN_TIMEOUT="  Timeout per port in seconds [default: 0.3]: "
if "%SCAN_TIMEOUT%"=="" set SCAN_TIMEOUT=0.3
goto RUN_SCAN_CUSTOM

:RUN_SCAN_DEFAULT
cls
echo ============================================================
echo   Running: Port Scan on %SCAN_HOST%
echo ============================================================
echo   Watch: http://localhost:5001  (Network Flow Monitor)
echo   Expected label: PortScan
echo ============================================================
echo.
python -c "
import socket, time
host = '%SCAN_HOST%'
timeout = %SCAN_TIMEOUT%
# Includes honeypot trap ports (7001-7010) that trigger PortScan detection
# plus common ports for realism
ports = [21,22,23,25,53,80,110,135,143,443,445,3306,3389,5900,8080,
         7001,7002,7003,7004,7005,7006,7007,7008,7009,7010]
print(f'Scanning {host} ({len(ports)} ports) ...')
open_ports = []
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((host, port))
    s.close()
    status = 'OPEN' if result == 0 else 'closed'
    if result == 0:
        open_ports.append(port)
    print(f'  Port {port:5d}: {status}')
    time.sleep(0.02)
print()
print(f'Scan complete. Open ports: {open_ports if open_ports else \"none\"}')
print('Check Network Flow Monitor -> PortScan should be flagged.')
"
echo.
echo ============================================================
echo   Scan finished. Check the Network Flow Monitor.
echo ============================================================
echo.
pause
goto MAIN_MENU

:RUN_SCAN_CUSTOM
cls
echo ============================================================
echo   Running: Custom Port Scan on %SCAN_HOST%
echo   (ports %SCAN_START%-%SCAN_END% + honeypot traps 7001-7010)
echo ============================================================
echo   Watch: http://localhost:5001  (Network Flow Monitor)
echo   Expected label: PortScan
echo ============================================================
echo.
python -c "
import socket, time
host = '%SCAN_HOST%'
timeout = %SCAN_TIMEOUT%
start_port = %SCAN_START%
end_port = %SCAN_END%
# Always include honeypot trap ports so PortScan detection fires
trap_ports = list(range(7001, 7011))
scan_ports = list(range(start_port, end_port + 1)) + trap_ports
total = len(scan_ports)
print(f'Scanning {host} ({total} ports incl. trap ports 7001-7010) ...')
open_ports = []
for port in scan_ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((host, port))
    s.close()
    if result == 0:
        open_ports.append(port)
        print(f'  Port {port}: OPEN')
    time.sleep(0.01)
print()
print(f'Scan complete. Open ports: {open_ports if open_ports else \"none\"}')
print('Check Network Flow Monitor -> PortScan should be flagged.')
"
echo.
echo ============================================================
echo   Scan finished. Check the Network Flow Monitor.
echo ============================================================
echo.
pause
goto MAIN_MENU

:: ─────────────────────────────────────────────────────────────────────────────
:EXIT
cls
echo   Exiting Attack Lab. Stay legal!
timeout /t 2 >nul
endlocal
exit /b 0
