ARG BLAZE_IMAGE=${CI_REGISTRY}/${CI_PROJECT_NAMESPACE}/blaze/blaze:latest

FROM ${BLAZE_IMAGE} as main
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,id=blaze-apt,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=blaze-apt-lists,target=/var/apt/lists,sharing=locked \
    apt install -yq \
        zlib1g-dev

COPY ./ /blaze/blaze-ui
WORKDIR /blaze/blaze-ui/server

RUN stack build --test --no-run-tests --ghc-options -fdiagnostics-color=always

ENV BLAZE_UI_HOST=localhost
ENV BLAZE_UI_WS_PORT=5765
ENV BLAZE_UI_HTTP_PORT=5766

CMD ["stack", "exec", "blaze-server"]

FROM main as minimal
RUN cd /blaze/blaze-ui/server && stack install --copy-bins --local-bin-path /blaze/bin
SHELL ["/bin/bash", "-c"]
WORKDIR /blaze
RUN shopt -s nullglob && \
    rm -rf \
        /var/cache/apt \
        /var/apt/lists \
        /root/.local/bin/stack \
        /usr/local/bin/stack \
        /blaze/{binary-analysis,binaryninja-haskell,blaze,blaze-ui} \
        /root/.stack \
        /usr/share/binaryninja-api

# This is hacky. Maybe we should FROM a more minimal base image?
RUN --mount=type=cache,id=blaze-apt,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=blaze-apt-lists,target=/var/apt/lists,sharing=locked \
    apt remove -y \
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
        hlint \

    && apt autoremove -y

ENV PATH="/blaze/bin:${PATH}"
CMD ["blaze-server"]
