# Security-hardened Dockerfile with pinned versions for quantum secret vault
# Pin base image to specific digest for immutability
FROM ubuntu:22.04@sha256:0bced47fffa3361afa981854fcabcd4577cd43cebbb808cea2b1f33a3dd7f508 AS builder

# Install system dependencies
# Note: apt packages are NOT version-pinned because:
# 1. Base image is pinned by SHA256 digest - provides reproducibility
# 2. apt packages receive security updates - pinning breaks when updates occur
# 3. Critical crypto deps (liboqs, Python packages) ARE pinned below
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3.10 \
    python3-pip \
    build-essential \
    cmake \
    ninja-build \
    git \
    astyle \
    gcc \
    libssl-dev \
    python3-pytest \
    python3-pytest-xdist \
    unzip \
    xsltproc \
    doxygen \
    graphviz \
    python3-yaml \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs C library with pinned version and verification
RUN git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    # Verify git commit hash for additional security
    git rev-parse HEAD | grep -q "^f4b96220e4bd208895172acc4fedb5a191d9f5b1$" && \
    mkdir build && cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON .. && \
    ninja && \
    ninja install && \
    ldconfig && \
    cd ../.. && \
    rm -rf liboqs

# Install liboqs-python with pinned versions and verification
RUN pip3 install --no-cache-dir \
    setuptools==69.5.1 \
    wheel==0.42.0 && \
    git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
    # Verify git commit hash
    git rev-parse HEAD | grep -q "^7906e7879a099fa34217035957d977314f99757d$" && \
    cat pyproject.toml && \
    echo '#!/usr/bin/env python3' > setup.py && \
    echo 'from setuptools import setup, find_packages' >> setup.py && \
    echo 'setup(' >> setup.py && \
    echo '    name="liboqs-python",' >> setup.py && \
    echo '    version="0.12.0",' >> setup.py && \
    echo '    packages=find_packages(),' >> setup.py && \
    echo '    python_requires=">=3.7"' >> setup.py && \
    echo ')' >> setup.py && \
    python3 setup.py install && \
    cd .. && \
    rm -rf liboqs-python

# Copy source code
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY run_tests.py /app/

# Install Python dependencies with pinned versions
WORKDIR /app
RUN pip3 install --no-cache-dir -r /app/src/requirements.txt
RUN pip3 install --no-cache-dir -r /app/tests/requirements.txt

# Runtime stage - minimal attack surface
FROM ubuntu:22.04@sha256:0bced47fffa3361afa981854fcabcd4577cd43cebbb808cea2b1f33a3dd7f508 AS runtime

# Install only essential runtime dependencies (minimal attack surface)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3.10 \
    python3-pip \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy only necessary artifacts from builder
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/lib/python3.10/dist-packages/ /usr/local/lib/python3.10/dist-packages/
COPY --from=builder /app/ /app/

# Set working directory and Python path
WORKDIR /app
ENV PYTHONPATH=/app:/app/src
RUN ldconfig

# Install Python dependencies in runtime for testing
RUN pip3 install --no-cache-dir -r /app/src/requirements.txt
RUN pip3 install --no-cache-dir -r /app/tests/requirements.txt

# Create non-root user for additional security
RUN useradd -r -s /bin/false -M -d /nonexistent quantumvault && \
    mkdir -p /app/.pytest_cache /output /vault && \
    chown -R quantumvault:quantumvault /app/.pytest_cache /output /vault
USER quantumvault

# No default entrypoint - scripts will run commands directly
