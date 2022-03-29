ARG BLAZE_IMAGE=${CI_REGISTRY}/blaze/blaze/blaze:latest

FROM ${BLAZE_IMAGE} as main
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,id=blaze-apt,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=blaze-apt-lists,target=/var/apt/lists,sharing=locked \
    apt update -yq &&                 \
    apt install -yq --no-install-recommends \
        zlib1g-dev

# Copy project definition for building dependencies
COPY \
    server/stack.yaml \
    server/package.yaml \
    /blaze/build/blaze-ui/server/

WORKDIR /blaze/build/blaze-ui

# Build dependencies only
RUN --mount=type=cache,id=blaze-stackroot,target=/root/.stack \
    --mount=type=cache,id=blazeui-ba-stackwork,target=/blaze/build/binary-analysis/.stack-work \
    --mount=type=cache,id=blazeui-bnhs-stackwork,target=/blaze/build/binaryninja-haskell/.stack-work \
    --mount=type=cache,id=blazeui-blaze-stackwork,target=/blaze/build/blaze/.stack-work \
    --mount=type=cache,id=blazeui-blazeui-stackwork,target=/blaze/build/blaze-ui/server/.stack-work \
    cd server && \
    stack build --only-dependencies --ghc-options -fdiagnostics-color=always

# Copy and build
COPY server/ /blaze/build/blaze-ui/server
RUN --mount=type=cache,id=blaze-stackroot,target=/root/.stack \
    --mount=type=cache,id=blazeui-ba-stackwork,target=/blaze/build/binary-analysis/.stack-work \
    --mount=type=cache,id=blazeui-bnhs-stackwork,target=/blaze/build/binaryninja-haskell/.stack-work \
    --mount=type=cache,id=blazeui-blaze-stackwork,target=/blaze/build/blaze/.stack-work \
    --mount=type=cache,id=blazeui-blazeui-stackwork,target=/blaze/build/blaze-ui/server/.stack-work \
    cd server && \
    stack build --test --no-run-tests \
        --copy-bins --local-bin-path /blaze/bin \
        --ghc-options -fdiagnostics-color=always && \
    cp $(stack path --dist-dir)/build/blaze-server-test/blaze-server-test ~/.local/bin

ENV BLAZE_UI_HOST=localhost
ENV BLAZE_UI_WS_PORT=5765
ENV BLAZE_UI_HTTP_PORT=5766

COPY ./ /blaze/build/blaze-ui/
COPY ./ /blaze/src/blaze-ui/

CMD ["/blaze/bin/blaze-server"]

FROM main as docs
RUN --mount=type=cache,id=blaze-stackroot,target=/root/.stack \
    --mount=type=cache,id=blazeui-ba-stackwork,target=/blaze/build/binary-analysis/.stack-work \
    --mount=type=cache,id=blazeui-bnhs-stackwork,target=/blaze/build/binaryninja-haskell/.stack-work \
    --mount=type=cache,id=blazeui-blaze-stackwork,target=/blaze/build/blaze/.stack-work \
    --mount=type=cache,id=blazeui-blazeui-stackwork,target=/blaze/build/blaze-ui/server/.stack-work \
    make docs

FROM main as minimal
SHELL ["/bin/bash", "-c"]
WORKDIR /blaze
RUN shopt -s nullglob && \
    rm -rf \
        /var/cache/apt \
        /var/apt/lists \
        /root/.local/bin/* \
        /usr/local/bin/stack \
        /blaze/build \
        /root/.stack \
        /root/.cabal \
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


FROM python:3.8 as wheel-builder
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,id=blaze-apt,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=blaze-apt-lists,target=/var/apt/lists,sharing=locked \
    apt update -yq && apt install -yq --no-install-recommends jq
RUN --mount=type=cache,id=blaze-pip,target=/root/.cache/pip \
    pip install toml-cli build pkginfo
COPY binja_plugin/ /binja_plugin/
WORKDIR /binja_plugin
ARG CI_PIPELINE_ID=
RUN CI_PIPELINE_ID=${CI_PIPELINE_ID} ./package_plugin.sh


FROM abhin4v/hastatic:latest as hastatic


FROM ubuntu:latest as wheel-server
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,id=blaze-apt,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=blaze-apt-lists,target=/var/apt/lists,sharing=locked \
    apt update -yq && apt install -yq --no-install-recommends jq moreutils
COPY --from=hastatic /usr/bin/hastatic /usr/bin/hastatic
COPY --from=wheel-builder /binja_plugin/dist/*.whl /binja_plugin/dist/plugins.json /www/
COPY .docker/wheel-server-entrypoint /usr/bin/wheel-server-entrypoint
WORKDIR /www
CMD ["/usr/bin/wheel-server-entrypoint"]
