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
