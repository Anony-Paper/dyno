#!/bin/bash
set ux

echo time_static_path_ostack
cmake-build-release/bin/time_static_path_ostack 1 24 >time_static_path_ostack.csv 2>&1
