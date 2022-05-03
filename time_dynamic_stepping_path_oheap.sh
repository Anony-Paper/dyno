#!/bin/bash
set ux

echo time_dynamic_stepping_path_oheap
cmake-build-release/bin/time_all_but_alloc_dynamic_stepping_path_oheap 1 24 >time_dynamic_stepping_path_oheap.csv 2>&1
