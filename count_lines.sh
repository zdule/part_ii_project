#!/bin/bash
cloc . --exclude-dir=measurements,kamprobes --not-match-f='dummy.c|compile_commands'
# Add 45 lines of diffs to kamprobes repository
# measured with:
# cloc --git --diff 9b0a3d5138f31ad6aacba0fb9cb0208f4701805e HEAD
# inside the kamprobes subrepo
