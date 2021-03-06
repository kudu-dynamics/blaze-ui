ARG BLAZE_IMAGE=${CI_REGISTRY}/${CI_PROJECT_NAMESPACE}/blaze/blaze:latest

FROM ${BLAZE_IMAGE} as main
RUN apt install -yq \
    zlib1g-dev

COPY ./ /blaze/blaze-ui
WORKDIR /blaze/blaze-ui/server

RUN stack build --test --no-run-tests --ghc-options -fdiagnostics-color=always

ENV BLAZE_UI_HOST=localhost
ENV BLAZE_UI_WS_PORT=5765
ENV BLAZE_UI_HTTP_PORT=5766

CMD ["stack", "exec", "blaze-server"]

FROM main as minimal
RUN cd /blaze/blaze-ui/server && stack install
RUN rm -rf \
    /usr/local/bin/stack \
    /blaze \
    /root/.stack \
    /usr/share/binaryninja-api

# This is hacky. Maybe we should FROM a more minimal base image?
RUN apt remove -y \
    autoconf \
    automake \
    build-essential \
    nano \
    haskell-stack \
    git \
    vim \
    cmake \
    ninja-build \
    python3-distutils \

    && apt autoremove -y

CMD ["/root/.local/bin/blaze-server"]
