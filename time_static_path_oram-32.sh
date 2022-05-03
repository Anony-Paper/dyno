#!/bin/bash
set ux

echo time_static_path_oram-32
cmake-build-release/bin/time_static_path_oram-32 1 24 >time_static_path_oram-32.csv 2>&1
