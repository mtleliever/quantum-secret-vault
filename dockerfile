# Security-hardened Dockerfile with pinned versions for quantum secret vault
# Pin base image to specific digest for immutability
FROM ubuntu:22.04@sha256:0bced47fffa3361afa981854fcabcd4577cd43cebbb808cea2b1f33a3dd7f508 AS builder

# Pin all system dependencies to specific versions
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3.10=3.10.12-1~22.04.11 \
    python3-pip=22.0.2+dfsg-1ubuntu0.6 \
    build-essential=12.9ubuntu3 \
    cmake=3.22.1-1ubuntu1.22.04.2 \
    ninja-build=1.10.1-1 \
    git=1:2.34.1-1ubuntu1.15 \
    astyle=3.1-2build1 \
    gcc=4:11.2.0-1ubuntu1 \
    libssl-dev=3.0.2-0ubuntu1.19 \
    python3-pytest=6.2.5-1ubuntu2 \
    python3-pytest-xdist=2.5.0-1 \
    unzip=6.0-26ubuntu3.2 \
    xsltproc=1.1.34-4ubuntu0.22.04.4 \
    doxygen=1.9.1-2ubuntu2 \
    graphviz=2.42.2-6 \
    python3-yaml=5.4.1-1ubuntu1 \
    valgrind=1:3.18.1-1ubuntu2 \
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

# Install only essential runtime dependencies with pinned versions
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3.10=3.10.12-1~22.04.11 \
    python3-pip=22.0.2+dfsg-1ubuntu0.6 \
    libssl3=3.0.2-0ubuntu1.19 \
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
