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

# Copy flag system and level access control
COPY flag_system.php /var/www/html/flag_system.php
COPY level_access.sh /usr/local/bin/level_access.sh
RUN chmod +x /usr/local/bin/level_access.sh

# Create decoy flag structure to prevent cheating
RUN mkdir -p /var/flags && \
    echo 'DECOY_FLAG{these_are_fake_flags_complete_levels_properly}' > /var/flags/README.txt && \
    echo 'DECOY_FLAG{level_1_fake_flag}' > /var/flags/level1_decoy.txt && \
    echo 'DECOY_FLAG{level_2_fake_flag}' > /var/flags/level2_decoy.txt && \
    echo 'DECOY_FLAG{level_3_fake_flag}' > /var/flags/level3_decoy.txt && \
    echo 'DECOY_FLAG{level_4_fake_flag}' > /var/flags/level4_decoy.txt && \
    echo 'DECOY_FLAG{level_5_fake_flag}' > /var/flags/level5_decoy.txt && \
    echo 'DECOY_FLAG{level_6_fake_flag}' > /var/flags/level6_decoy.txt && \
    echo 'DECOY_FLAG{level_7_fake_flag}' > /var/flags/level7_decoy.txt && \
    echo 'DECOY_FLAG{level_8_fake_flag}' > /var/flags/level8_decoy.txt && \
    echo 'DECOY_FLAG{level_9_fake_flag}' > /var/flags/level9_decoy.txt && \
    echo 'DECOY_FLAG{level_10_fake_flag}' > /var/flags/level10_decoy.txt && \
    chmod 644 /var/flags/*

# Set working directory
WORKDIR /var/www/html

# Expose port
EXPOSE 80
