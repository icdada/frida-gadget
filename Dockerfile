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

# Install python dependencies from the lock file, so a rebuild resolves to the
# same versions rather than whatever is newest. '--only-binary :all:' installs
# wheels only, so no package can run setup code while the image is being built.
# setup.py keeps ranges instead; pinning a library's dependencies would force
# them on everyone who installs frida-gadget.
WORKDIR /workspace
COPY requirements.lock /workspace/requirements.lock
RUN pip3 install --no-cache-dir --only-binary :all: pip==26.2.1 && \
    pip3 install --no-cache-dir --only-binary :all: -r requirements.lock

COPY scripts /workspace/scripts

# Set ownership of workspace directory
RUN chown -R frida-user:frida-user /workspace

# Switch to non-root user
USER frida-user

ENTRYPOINT ["python3", "-m", "scripts.cli"]
