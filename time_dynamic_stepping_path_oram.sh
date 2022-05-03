#!/bin/bash
set ux

echo time_dynamic_stepping_path_oram
cmake-build-release/bin/time_all_but_alloc_dynamic_stepping_path_oram 1 24 >time_dynamic_stepping_path_oram.csv 2>&1
