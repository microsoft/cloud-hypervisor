#!/bin/sh
sudo ./cloud-hypervisor \
        -vvvv \
        --craton \
        --seccomp false \
        --kernel /var/lib/are/kernel \
        --disk path=/var/lib/are/data,readonly=on path=/dev/disk/by-label/are-writable \
        --net tap=tap0 \
        --cmdline "console=hvc0 root=/dev/vda rootrw=/dev/vdb" \
        --cpus boot=1 
        #--console off \
        #--serial tty

