# Use Ubuntu LTS base with Python 3.10
FROM ubuntu:22.04

# Install system dependencies including liboqs C library dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3.10 \
    python3-pip \
    steghide \
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

# Install liboqs C library (using specific tag for stability)
RUN git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON .. && \
    ninja && \
    ninja install && \
    ldconfig && \
    cd ../.. && \
    rm -rf liboqs

# Install liboqs-python from source (since PyPI package is unavailable)
RUN pip3 install setuptools==69.5.1 wheel && \
    git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs-python.git && \
    cd liboqs-python && \
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

# Set working directory
WORKDIR /app
COPY src/ /app/src/
COPY tests/ /app/tests/
COPY run_tests.py /app/

# Install Python dependencies
RUN pip3 install -r /app/src/requirements.txt

# Install test dependencies
RUN pip3 install -r /app/tests/requirements.txt

# Set Python path
ENV PYTHONPATH=/app:/app/src

# No default entrypoint - scripts will run commands directly
