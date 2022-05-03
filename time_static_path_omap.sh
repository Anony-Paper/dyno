#!/bin/bash
set ux

echo time_static_path_omap
cmake-build-release/bin/time_static_path_omap 1 24 >time_static_path_omap.csv 2>&1
