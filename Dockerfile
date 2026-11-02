# syntax=docker/dockerfile:1
# Compiles the app to a native binary with Nuitka, then ships only that binary
# (plus the shared libs it links) on scratch: no Python interpreter, no shell.
# The previous "interpreter on scratch" variant lives in Dockerfile.python.

# Stage 1: compile.
FROM python:3.12-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential patchelf \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src

COPY requirements.txt .
RUN pip install --no-cache-dir $(grep -v '^pytest' requirements.txt) blake3 nuitka

COPY app.py algorithms.py ./
COPY static ./static

# passlib/Crypto/argon2 are resolved with getattr/lazy imports, so include them whole.
RUN python -m nuitka --standalone --assume-yes-for-downloads \
      --output-dir=/out --output-filename=ranstring --jobs="$(nproc)" \
      --include-package=passlib --include-package=Crypto --include-package=argon2 \
      --include-data-dir=static=static \
      --nofollow-import-to=pytest \
      app.py

# Nuitka bundles most libs but not glibc/loader. `ldd f1 f2 ...` prints
# "path:" header lines (hence `!~ /:$/`); libs already under /out are kept as is.
RUN mkdir -p /rootfs/tmp && chmod 1777 /rootfs/tmp \
 && { ldd /out/app.dist/ranstring; find /out/app.dist -name '*.so*' -exec ldd {} +; } 2>/dev/null \
    | awk '$3 ~ /^\// {print $3} $1 ~ /^\// && $1 !~ /:$/ {print $1}' \
    | grep -v '^/out/' | sort -u \
    | xargs -r -I{} cp -L --parents {} /rootfs

# Stage 2: nothing but the compiled app and the libs above.
FROM scratch
COPY --from=build /rootfs/ /
COPY --from=build /out/app.dist/ /app/
ENV HOST=0.0.0.0 PORT=5000
WORKDIR /app
USER 10001:10001
EXPOSE 5000
ENTRYPOINT ["/app/ranstring"]
