#!/bin/bash
set ux

echo time_plaintext_stack
cmake-build-release/bin/time_plaintext_stack 1 24 >time_plaintext_stack.csv 2>&1
