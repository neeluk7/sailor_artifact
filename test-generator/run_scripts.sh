#!/bin/bash

# List of programs
programs=(./fflags_write_app ./fflags_read_app ./frm_write_app ./frm_read_app ./fcsr_write_app ./fcsr_read_app ./vxsat_write_app ./vxsat_read_app ./vxrm_write_app ./vxrm_read_app ./vcsr_write_app ./vcsr_read_app)

# Number of programs to run in parallel
batch_size=2

for ((i=0; i<${#programs[@]}; i+=batch_size)); do
    for ((j=0; j<batch_size && i+j<${#programs[@]}; j++)); do
        prog="${programs[i+j]}"
        log="output_${i+j+1}.log"
        echo "Running $prog -> $log"
        "$prog" > "$log" 2>&1 &
    done
    wait  # Wait for current batch to finish before continuing
done

