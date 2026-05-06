"""
Deep check: print the raw source of every code cell, looking for
any cell whose source contains JSON-like metadata text.
Also print the exact byte positions so we can see context.
"""
import json, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

path = r'C:\Users\Dassa\Documents\Research\network\Training codes\gan-1.ipynb'

# Raw text check first
with open(path, 'r', encoding='utf-8') as f:
    raw = f.read()

# Scan for any occurrence of '_uuid' or '"trusted": true' OUTSIDE the metadata sections
# (i.e., inside a "source" field value)
import re

# Find all "source": "..." or "source": [...] spans and check their content
# Simple heuristic: look for _uuid appearing inside a source value
for m in re.finditer(r'"source"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(\[.*?\]))', raw, re.DOTALL):
    content = m.group(1) or m.group(2) or ''
    if '_uuid' in content or '"trusted"' in content or '_cell_guid' in content:
        print(f"CORRUPTED SOURCE at char {m.start()}:")
        print(content[:300])
        print()

# Now load and check each cell
with open(path, 'r', encoding='utf-8') as f:
    nb = json.load(f)

print(f"\nTotal cells: {len(nb['cells'])}")
for i, cell in enumerate(nb['cells']):
    src = cell.get('source', '')
    if isinstance(src, list):
        src_str = ''.join(src)
    else:
        src_str = src
    if '_uuid' in src_str or '_cell_guid' in src_str or '"trusted"' in src_str:
        print(f"\n!!! Cell {i} has JSON metadata in source !!!")
        print(src_str[:500])
    else:
        lines = src_str.count('\n') + 1 if src_str else 0
        print(f"Cell {i:2d}: OK ({lines} lines) | {src_str[:50].replace(chr(10), '|')}")

print("\nDone.")
