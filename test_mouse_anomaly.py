"""
Mouse Anomaly Test
------------------
Double-click this file (or run: python test_mouse_anomaly.py)
Keep the CyberWatch dashboard open — watch the purple line spike.

The script gives you a 5-second countdown, then sweeps the mouse
at high speed for 6 seconds, then stops.
"""

import time
import ctypes
import ctypes.wintypes

def move_mouse(x, y):
    ctypes.windll.user32.SetCursorPos(x, y)

def get_screen_size():
    w = ctypes.windll.user32.GetSystemMetrics(0)
    h = ctypes.windll.user32.GetSystemMetrics(1)
    return w, h

print("=" * 50)
print("  CyberWatch — Mouse Anomaly Test")
print("=" * 50)
print()
print("Keep the dashboard open and watch the graph.")
print()

for i in range(5, 0, -1):
    print(f"  Starting in {i}...", end="\r")
    time.sleep(1)

print("\n  RUNNING — moving mouse at high speed...\n")

W, H = get_screen_size()
start = time.time()
x = 0
direction = 1

# Phase 1: rapid left-right sweeps (3 seconds)
while time.time() - start < 3:
    move_mouse(x, H // 2)
    x += direction * 80
    if x >= W - 80:
        direction = -1
    elif x <= 0:
        direction = 1
    time.sleep(0.01)   # ~80 moves/sec = very high speed

print("  Phase 1 done — diagonal sweeps now...\n")

# Phase 2: diagonal zigzag sweeps (3 more seconds)
start2 = time.time()
points = [
    (50,  50),  (W-50, H-50),
    (W-50, 50), (50,   H-50),
    (W//2, 50), (W//2, H-50),
    (50, H//2), (W-50, H//2),
]
idx = 0
while time.time() - start2 < 3:
    tx, ty = points[idx % len(points)]
    # Move in small steps toward target at high speed
    cx_arr = ctypes.wintypes.POINT()
    ctypes.windll.user32.GetCursorPos(ctypes.byref(cx_arr))
    cx, cy = cx_arr.x, cx_arr.y
    dx, dy = tx - cx, ty - cy
    dist = (dx**2 + dy**2) ** 0.5
    if dist < 30:
        idx += 1
    else:
        step = min(120, dist)
        nx = int(cx + dx / dist * step)
        ny = int(cy + dy / dist * step)
        move_mouse(nx, ny)
    time.sleep(0.008)

print("  Done! Check the dashboard — anomaly spike should be visible.")
print()
input("  Press Enter to close this window.")
