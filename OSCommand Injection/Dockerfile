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

# Copy flag system and anti-cheat components
COPY flag_system.php /var/www/html/flag_system.php
COPY init_anticheat.sh /usr/local/bin/init_anticheat.sh
RUN chmod +x /usr/local/bin/init_anticheat.sh

# Initialize anti-cheat system
RUN /usr/local/bin/init_anticheat.sh

# Ensure anti-cheat runs on container startup
RUN echo '#!/bin/bash' > /usr/local/bin/startup.sh && \
    echo '/usr/local/bin/init_anticheat.sh' >> /usr/local/bin/startup.sh && \
    echo 'apache2-foreground' >> /usr/local/bin/startup.sh && \
    chmod +x /usr/local/bin/startup.sh

# Override default command to run anti-cheat first
CMD ["/usr/local/bin/startup.sh"]

# Set working directory
WORKDIR /var/www/html

# Expose port
EXPOSE 80
