# Linux end-to-end for sealref against a real Secret Service (gnome-keyring on
# a private D-Bus session). Build from the repo root:
#   docker build -f tests/linux/Dockerfile -t sealref-linux .
#   docker run --rm sealref-linux
# Dummy values only; everything lives inside the container.
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      dbus dbus-x11 gnome-keyring libsecret-1-0 \
 && rm -rf /var/lib/apt/lists/*

# Two environments: keyring only, and keyring + keyrings.alt (the plaintext /
# encrypted-file backends sealref must refuse).
COPY . /src
RUN python -m venv /opt/venv-sec && python -m venv /opt/venv-alt \
 && /opt/venv-sec/bin/pip install --no-cache-dir 'keyring==25.7.0' /src \
 && /opt/venv-alt/bin/pip install --no-cache-dir 'keyring==25.7.0' 'keyrings.alt==5.0.2' /src

WORKDIR /src
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["sh", "tests/linux/run.sh"]
