# Use Ubuntu LTS base with Python 3.10
FROM ubuntu:22.04

# Install system dependencies including liboqs C library
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3.10 \
    python3-pip \
    steghide \
    build-essential \
    cmake \
    ninja-build \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs C library (commented out for now - focus on AES first)
# RUN git clone https://github.com/open-quantum-safe/liboqs.git && \
#     cd liboqs && \
#     mkdir build && cd build && \
#     cmake -GNinja .. && \
#     ninja && \
#     ninja install && \
#     ldconfig && \
#     cd ../.. && \
#     rm -rf liboqs

# Set working directory
WORKDIR /app
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY run_tests.py /app/

# Install Python dependencies
RUN pip3 install -r /app/src/requirements.txt

# Set Python path
ENV PYTHONPATH=/app:/app/src

# Set entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
