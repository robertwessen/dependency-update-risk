FROM python:3.12-slim

# Install dep-risk from PyPI (VERSION build arg lets you pin a release)
ARG VERSION=latest
RUN pip install --no-cache-dir "dep-risk${VERSION:+==}${VERSION#latest}" 2>/dev/null \
    || pip install --no-cache-dir dep-risk

# Mount a directory to /scan for use with --input
VOLUME ["/scan"]
WORKDIR /scan

ENTRYPOINT ["dep-risk"]
