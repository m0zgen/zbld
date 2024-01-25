#!/bin/bash
# Author: Yevgeniy Goncharov aka xck, http://lab.sys-adm.in
# Update zDNS users config.xml files

# Sys env / paths / etc
# -------------------------------------------------------------------------------------------\
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd); cd $SCRIPT_PATH

# Variables
TARGET_DIR="users"

# Change values in found config.xml file
# -------------------------------------------------------------------------------------------\
replace_values() {
    file="$1"
    sed -i 's/cache_ttl_seconds.*/cache_ttl_seconds: 129600/g' "$file"
    sed -i 's/console_message_enable.*/console_message_enable: false/g' "$file"
}

# Scan files and call replace_values function
# -------------------------------------------------------------------------------------------\
scan_files() {
    dir="$1"
    # If TARGET_DIR is not a directory, exit
    if [ ! -d "$dir" ]; then
        echo "Directory $dir not found!"
        exit 1
    fi
    for file in "$dir"/*; do
#        echo "Scanning $file"
        if [ -d "$file" ]; then
            # If this is a directory, call this function recursively
            scan_files "$file"
        elif [ "$(basename "$file")" == "config.yml" ]; then
            # If this is a config.xml file, call replace_values function
            replace_values "$file"
            echo "File $file updated!"
        fi
    done
}

# Target dir
# -------------------------------------------------------------------------------------------\
scan_files "${TARGET_DIR}"

echo "Config files updated!"
