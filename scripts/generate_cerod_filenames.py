#!/usr/bin/env python3
"""Generate candidate CEROD filenames from observed constants for testing."""
from itertools import permutations, product

ACT_KEY = '7bb07b8d471d642e'
KNOWN = [':cerod:', 'KeyKey.db', ACT_KEY]
SEPS = ['', '/', '-', '_', ':', '::', ':/', '/:']
PREFIXES = ['', '/var/', '/tmp/', '/Library/Application Support/', '/Users/Shared/']


def generate(limit=20000):
    seen = set()
    candidates = []
    # permutations of the known tokens with separators
    for r in range(2, 4):
        for perm in permutations(KNOWN, r):
            for sep in SEPS:
                s = sep.join(perm)
                if len(s) < 4 or len(s) > 512:
                    continue
                if s in seen:
                    continue
                seen.add(s)
                candidates.append(s)
                if len(candidates) >= limit:
                    return candidates
    # prefix + token combos
    for p in PREFIXES:
        for t in KNOWN:
            s = p + t
            if s not in seen:
                candidates.append(s)
                seen.add(s)
                if len(candidates) >= limit:
                    return candidates
    return candidates


if __name__ == '__main__':
    for s in generate(2000):
        print(s)
