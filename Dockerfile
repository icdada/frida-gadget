FROM eclipse-temurin:17-jdk-jammy
LABEL maintainer="ksg97031 <ksg97031@gmail.com>"

ARG APKTOOL_VERSION=2.11.1
# sha256 of apktool_${APKTOOL_VERSION}.jar. Bitbucket and the GitHub release
# serve byte-identical files; override both together to move to a new version.
ARG APKTOOL_SHA256=56d59c524fc764263ba8d345754d8daf55b1887818b15cd3b594f555d249e2db
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

# Install apktool. ADD fetches over HTTPS and refuses a redirect to plain HTTP,
# and the jar carries a checksum so a substituted artifact fails the build.
ADD --chmod=755 \
    https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
    /usr/local/bin/apktool
ADD --chmod=755 --checksum=sha256:${APKTOOL_SHA256} \
    https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar \
    /usr/local/bin/apktool.jar

# Create a non-root user
RUN useradd -m -s /bin/bash frida-user

# Install python dependencies. '--only-binary :all:' installs wheels only, so no
# package can run setup code while the image is being built. frida is listed in
# requirements.txt, so it no longer needs a line of its own.
WORKDIR /workspace
COPY requirements.txt /workspace/requirements.txt
RUN pip3 install --no-cache-dir --only-binary :all: --upgrade pip && \
    pip3 install --no-cache-dir --only-binary :all: -r requirements.txt

COPY scripts /workspace/scripts

# Set ownership of workspace directory
RUN chown -R frida-user:frida-user /workspace

# Switch to non-root user
USER frida-user

ENTRYPOINT ["python3", "-m", "scripts.cli"]
