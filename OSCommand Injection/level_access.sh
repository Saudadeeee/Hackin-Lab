#!/bin/bash

LEVEL=$1
CURRENT_LEVEL_FILE="/var/www/html/current_level.txt"

# Function to create decoy files
create_decoys() {
    local level=$1

    for i in {1..10}; do
        if [ $i -ne $level ]; then
            mkdir -p /tmp/fake_flags/level$i
            echo "FAKE_FLAG{you_need_to_complete_level_${i}_properly}" > /tmp/fake_flags/level$i/flag.txt
        fi
    done
    
    ln -sf /tmp/fake_flags/* /var/flags/ 2>/dev/null
}

# Function to unlock current level flag
unlock_flag() {
    local level=$1
    local flag_content=""
    
    case $level in
        1) flag_content="FLAG{basic_injection_discovered}";;
        2) flag_content="FLAG{semicolon_filter_bypassed}";;
        3) flag_content="FLAG{space_filter_$(id -u)_bypassed}";;
        4) flag_content="FLAG{keyword_$(uname)_bypass_complete}";;
        5) flag_content="FLAG{blind_execution_confirmed}";;
        6) flag_content="FLAG{timing_attack_successful}";;
        7) flag_content="FLAG{advanced_encoding_bypass_successful}";;
        8) flag_content="FLAG{waf_bypass_master_level}";;
        9) flag_content="FLAG{out_of_band_data_exfiltration}";;
        10) flag_content="FLAG{race_condition_automation_bypass}";;
        *) flag_content="INVALID_LEVEL";;
    esac
    
    # Create accessible flag for current level only
    mkdir -p /tmp/level${level}_access
    echo "$flag_content" > /tmp/level${level}_access/flag.txt
    chmod 644 /tmp/level${level}_access/flag.txt
    
    # Create symbolic link in web directory for easy access
    ln -sf /tmp/level${level}_access/flag.txt /var/www/html/level${level}_flag.txt
    
    echo "$flag_content"
}

# Set current level context
echo "$LEVEL" > $CURRENT_LEVEL_FILE

# Create decoys for all other levels
create_decoys $LEVEL

# Unlock only the current level's flag
unlock_flag $LEVEL
