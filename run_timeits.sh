#!/bin/bash
set ux

./time_static_path_oram-4.sh &
./time_dynamic_stepping_path_oram.sh &

./time_static_path_omap.sh &
./time_dynamic_stepping_path_omap.sh &

./time_static_path_oheap.sh &
./time_dynamic_stepping_path_oheap.sh &

./time_plaintext_stack.sh &
./time_static_path_ostack.sh &
