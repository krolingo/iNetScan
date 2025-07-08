#!/usr/bin/env python3
import os, re

def slugify(name):
    # 1) Strip leading digits
    name = re.sub(r'^\d+', '', name)
    # 2) Replace any non‐alphanumeric with underscore
    name = re.sub(r'[^\w]+', '_', name)
    # 3) Collapse multiple underscores
    name = re.sub(r'__+', '_', name)
    # 4) Trim leading/trailing underscores and lowercase
    return name.strip('_').lower()

if __name__ == '__main__':
    svg_dir = os.path.join(os.path.dirname(__file__), 'icons', 'svg')
    for fname in os.listdir(svg_dir):
        if not fname.lower().endswith('.svg'):
            continue
        base = fname[:-4]
        new_base = slugify(base)
        new_fname = new_base + '.svg'
        if base != new_base:
            src = os.path.join(svg_dir, fname)
            dst = os.path.join(svg_dir, new_fname)
            if os.path.exists(dst):
                print(f"⚠️  Skipping {fname} → {new_fname} (target exists)")
            else:
                print(f"Renaming {fname} → {new_fname}")
                os.rename(src, dst)