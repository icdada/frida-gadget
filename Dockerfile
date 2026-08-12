FROM eclipse-temurin:17-jdk-jammy
LABEL maintainer="ksg97031 <ksg97031@gmail.com>"

ARG APKTOOL_VERSION=2.11.1
ENV APKTOOL_VERSION=${APKTOOL_VERSION}

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        python-is-python3 \
        python3 \
        python3-pip \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install apktool. The launcher script and the jar are fetched over HTTPS with
# --proto '=https' so a redirect cannot downgrade the transfer to plain HTTP.
WORKDIR /usr/local/bin
RUN curl -fsSL --proto '=https' --tlsv1.2 \
        -o apktool \
        https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool && \
    curl -fsSL --proto '=https' --tlsv1.2 \
        -o apktool.jar \
        "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar" && \
    chmod +x apktool apktool.jar

# Create a non-root user
RUN useradd -m -s /bin/bash frida-user

# Install python dependencies. '--only-binary :all:' installs wheels only, so no
# package can run setup code while the image is being built. frida is imported
# by scripts/__init__.py to read the version the gadget is matched against.
WORKDIR /workspace
COPY requirements.txt /workspace/requirements.txt
RUN pip3 install --no-cache-dir --only-binary :all: --upgrade pip && \
    pip3 install --no-cache-dir --only-binary :all: frida && \
    pip3 install --no-cache-dir --only-binary :all: -r requirements.txt

COPY scripts /workspace/scripts

# Set ownership of workspace directory
RUN chown -R frida-user:frida-user /workspace

# Switch to non-root user
USER frida-user

ENTRYPOINT ["python3", "-m", "scripts.cli"]
