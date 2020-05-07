#!/bin/bash
cloc . --exclude-dir=measurements,kamprobes --not-match-f='dummy.c|compile_commands'
