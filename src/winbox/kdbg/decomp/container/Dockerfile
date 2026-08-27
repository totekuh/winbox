FROM eclipse-temurin:21-jdk-jammy@sha256:ce5767b7222312d42395f5bab033cd91f09e44032a2f21bdfd7b5b912dbe1e77

ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_RELEASE_DATE=20260817
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54
ARG PYGHIDRA_VERSION=3.1.0
ARG PYGHIDRA_SHA256=62d76e4c42352fc38cb3a9526ba7e25681d21388c16e59a2d17e99aeaf47ac94
ARG JPYPE_SHA256=cdca93cc74f8db1f604d2ea6adb764dec4dec68528f1ee68308fa3d524095739
ARG PACKAGING_SHA256=5fc45236b9446107ff2415ce77c807cee2862cb6fac22b8a73826d0693b0980e

LABEL io.winbox.component="pyghidra" \
      io.winbox.worker-api="6" \
      io.winbox.ghidra-version="${GHIDRA_VERSION}" \
      io.winbox.pyghidra-version="${PYGHIDRA_VERSION}"

ENV DEBIAN_FRONTEND=noninteractive \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp/home

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl python3 python3-venv unzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl --fail --location --retry 4 --output /tmp/ghidra.zip \
       "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE_DATE}.zip" \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum --check --strict \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && python3 -m venv /opt/venv \
    && curl --fail --location --retry 4 --output /tmp/jpype1-1.5.2-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl \
       "https://files.pythonhosted.org/packages/97/0a/cbe03759331c640aa5862f974028122a862b08935a0b11b8fa6f6e46c26b/jpype1-1.5.2-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl" \
    && echo "${JPYPE_SHA256}  /tmp/jpype1-1.5.2-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl" | sha256sum --check --strict \
    && curl --fail --location --retry 4 --output /tmp/packaging-26.2-py3-none-any.whl \
       "https://files.pythonhosted.org/packages/df/b2/87e62e8c3e2f4b32e5fe99e0b86d576da1312593b39f47d8ceef365e95ed/packaging-26.2-py3-none-any.whl" \
    && echo "${PACKAGING_SHA256}  /tmp/packaging-26.2-py3-none-any.whl" | sha256sum --check --strict \
    && /opt/venv/bin/pip install --no-cache-dir /tmp/jpype1-1.5.2-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl /tmp/packaging-26.2-py3-none-any.whl \
    && rm /tmp/jpype1-1.5.2-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl /tmp/packaging-26.2-py3-none-any.whl \
    && curl --fail --location --retry 4 --output "/tmp/pyghidra-${PYGHIDRA_VERSION}-py3-none-any.whl" \
       "https://files.pythonhosted.org/packages/0d/e9/1d8f9a790be5c6d3f95a8c1428016269c0c049ae70463bc3edbc76f2bb04/pyghidra-${PYGHIDRA_VERSION}-py3-none-any.whl" \
    && echo "${PYGHIDRA_SHA256}  /tmp/pyghidra-${PYGHIDRA_VERSION}-py3-none-any.whl" | sha256sum --check --strict \
    && /opt/venv/bin/pip install --no-cache-dir --no-deps "/tmp/pyghidra-${PYGHIDRA_VERSION}-py3-none-any.whl" \
    && rm "/tmp/pyghidra-${PYGHIDRA_VERSION}-py3-none-any.whl" \
    && find /opt/ghidra -type d -name __pycache__ -prune -exec rm -rf '{}' + \
    && find /opt/ghidra -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

COPY worker.py /opt/winbox/worker.py

WORKDIR /opt/winbox

ENTRYPOINT ["/opt/venv/bin/python", "/opt/winbox/worker.py"]
