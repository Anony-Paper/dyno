#!/bin/bash
set ux

echo time_dynamic_stepping_path_omap
cmake-build-release/bin/time_all_but_alloc_dynamic_stepping_path_omap 1 24 >time_dynamic_stepping_path_omap.csv 2>&1
