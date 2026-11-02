# syntax=docker/dockerfile:1
# Stage 1: install deps and collect a minimal Python runtime into /rootfs.
FROM python:3.12-slim AS build
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --target /deps \
      $(grep -v '^pytest' requirements.txt) gunicorn blake3

COPY app.py algorithms.py ./
COPY static ./static
RUN python -m compileall -q /deps /app

# Python + stdlib + every shared library (incl. the ELF loader) that the
# interpreter and the C extensions link against. Works for x86_64 and arm64.
# `ldd f1 f2 ...` prints "path:" header lines (hence the `!~ /:$/`), and libs
# vendored under /deps are already copied by the `COPY /deps` below.
RUN mkdir -p /rootfs/tmp && chmod 1777 /rootfs/tmp \
 && cp -a --parents /usr/local/bin/python3.12 /usr/local/lib/python3.12 /usr/local/lib/libpython3.12.so* /rootfs \
 && rm -rf /rootfs/usr/local/lib/python3.12/site-packages/* \
           /rootfs/usr/local/lib/python3.12/test \
           /rootfs/usr/local/lib/python3.12/idlelib \
           /rootfs/usr/local/lib/python3.12/tkinter \
           /rootfs/usr/local/lib/python3.12/turtledemo \
           /rootfs/usr/local/lib/python3.12/ensurepip \
 && { ldd /usr/local/bin/python3.12; find /usr/local/lib/python3.12/lib-dynload /deps -name '*.so*' -exec ldd {} +; } 2>/dev/null \
    | awk '$3 ~ /^\// {print $3} $1 ~ /^\// && $1 !~ /:$/ {print $1}' \
    | grep -v '^/deps/' | sort -u \
    | xargs -r -I{} cp -L --parents {} /rootfs

# Stage 2: nothing but the files above. No shell, no package manager.
FROM scratch
COPY --from=build /rootfs/ /
COPY --from=build /deps /deps
COPY --from=build /app /app
ENV PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LD_LIBRARY_PATH=/usr/local/lib
WORKDIR /app
USER 10001:10001
EXPOSE 5000
# /dev/shm for gunicorn's heartbeat files so the root FS can stay read-only.
ENTRYPOINT ["/usr/local/bin/python3.12", "-m", "gunicorn", \
            "--bind", "0.0.0.0:5000", "--workers", "2", \
            "--worker-tmp-dir", "/dev/shm", "app:app"]
