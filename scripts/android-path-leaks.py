#!/usr/bin/env python3
import re
import sys


HOST_PATH = re.compile(r"/(Users|home|root|builds)/|^/(private|tmp|var/folders)/")


def leaked_paths(lines, roots):
    roots = tuple(root.rstrip("/") for root in roots if root.rstrip("/"))
    return sorted({
        line.rstrip("\n") for line in lines
        if HOST_PATH.search(line) or any(root + "/" in line or line.strip() == root for root in roots)
    })


if __name__ == "__main__":
    for line in leaked_paths(sys.stdin, sys.argv[1:]):
        print(line)
