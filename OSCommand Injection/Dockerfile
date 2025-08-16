FROM php:8.1-apache

# Install required tools during build time (faster)
RUN apt-get update && \
    apt-get install -y \
        curl \
        wget \
        net-tools \
        iputils-ping \
        dnsutils \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod rewrite

# Create dynamic flag generation script
RUN echo '#!/bin/bash' > /usr/local/bin/generate_flag.sh && \
    echo 'LEVEL=$1' >> /usr/local/bin/generate_flag.sh && \
    echo 'case $LEVEL in' >> /usr/local/bin/generate_flag.sh && \
    echo '  1) echo "FLAG{basic_$(whoami)_$(hostname)_injection}";;' >> /usr/local/bin/generate_flag.sh && \
    echo '  2) echo "FLAG{filter_bypass_$(date +%Y)_success}";;' >> /usr/local/bin/generate_flag.sh && \
    echo '  3) echo "FLAG{space_filter_$(id -u)_bypassed}";;' >> /usr/local/bin/generate_flag.sh && \
    echo '  4) echo "FLAG{keyword_$(uname -s)_bypass_complete}";;' >> /usr/local/bin/generate_flag.sh && \
    echo '  5) echo "FLAG{blind_injection_$(date +%m%d)_success}";;' >> /usr/local/bin/generate_flag.sh && \
    echo '  6) echo "FLAG{time_based_$(uptime | cut -d, -f1 | tr -d " " | cut -d: -f1)_detected}";;' >> /usr/local/bin/generate_flag.sh && \
    echo '  *) echo "INVALID_LEVEL";;' >> /usr/local/bin/generate_flag.sh && \
    echo 'esac' >> /usr/local/bin/generate_flag.sh && \
    chmod +x /usr/local/bin/generate_flag.sh

# Create level-specific flag files that require specific commands
RUN mkdir -p /var/flags && \
    echo 'FLAG{basic_injection_discovered}' > /var/flags/level1_hint.txt && \
    echo 'FLAG{semicolon_filter_bypassed}' > /var/flags/level2_hint.txt && \
    echo 'Use: /usr/local/bin/generate_flag.sh 3' > /var/flags/level3_cmd.txt && \
    echo 'Use: /usr/local/bin/generate_flag.sh 4' > /var/flags/level4_cmd.txt && \
    echo 'FLAG{blind_execution_confirmed}' > /var/flags/level5_proof.txt && \
    echo 'FLAG{timing_attack_successful}' > /var/flags/level6_timing.txt && \
    echo 'FLAG{advanced_encoding_bypass_successful}' > /var/flags/level7_encoding.txt && \
    echo 'FLAG{waf_bypass_master_level}' > /var/flags/level8_waf.txt && \
    echo 'FLAG{out_of_band_data_exfiltration}' > /var/flags/level9_oob.txt && \
    echo 'FLAG{race_condition_automation_bypass}' > /var/flags/level10_race.txt

# Set working directory
WORKDIR /var/www/html

# Expose port
EXPOSE 80
