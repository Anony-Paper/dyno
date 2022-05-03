#!/bin/bash
set ux

echo time_static_path_oheap
cmake-build-release/bin/time_static_path_oheap 1 24 >time_static_path_oheap.csv 2>&1
