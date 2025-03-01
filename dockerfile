# Use Ubuntu LTS base with Python 3.10
FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3.10 \
    python3-pip \
    steghide \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app
COPY src/ /app/

# Install Python dependencies
RUN pip3 install -r /app/requirements.txt

# Set entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
