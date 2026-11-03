FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates=20260816ubuntu0.24.04.1 \
    && apt-get -S 20261001T000000Z update \
    && DEBIAN_FRONTEND=noninteractive apt-get -S 20261001T000000Z install -y --no-install-recommends \
    clang cmake g++ libclang-rt-18-dev make python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cmake --preset debug && cmake --build --preset debug && ctest --preset debug \
    && python3 -m unittest discover -s tests -v
