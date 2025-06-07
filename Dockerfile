FROM eclipse-temurin:17-jdk-jammy
LABEL MAINTAINER ksg97031 (ksg97031@gmail.com)

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        python3 \
        python3-pip \
        python-is-python3 \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Frida
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir frida

# Install apktool
ENV APKTOOL_VERSION=2.11.1 
WORKDIR /usr/local/bin
RUN curl -sLO https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool && \
    chmod +x apktool
RUN curl -sL -o apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar && \
    chmod +x apktool.jar

# Create a non-root user
RUN useradd -m -s /bin/bash frida-user

# Install dependencies
WORKDIR /workspace
COPY scripts /workspace/scripts
COPY requirements.txt /workspace/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Set ownership of workspace directory
RUN chown -R frida-user:frida-user /workspace

# Switch to non-root user
USER frida-user

ENTRYPOINT ["python3", "-m", "scripts.cli"]
