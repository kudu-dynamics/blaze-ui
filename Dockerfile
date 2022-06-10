# syntax=docker/dockerfile:1.4

ARG BLAZE_IMAGE=${CI_REGISTRY}/blaze/blaze/blaze:latest
ARG BLAZE_MINIMAL_BASE_IMAGE=ubuntu:21.10

FROM ${BLAZE_IMAGE} as main
ARG BUILD_TYPE=dev
ARG STACK_BUILD_OPTIONS=

RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,id=blaze-apt,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=blaze-apt-lists,target=/var/apt/lists,sharing=locked \
    apt update -yq &&                 \
    apt install -yq --no-install-recommends \
        zlib1g-dev

# Copy project definition for building dependencies
COPY \
    server/stack*.yaml \
    server/package.yaml \
    server/Makefile \
    /blaze/build/blaze-ui/server/

WORKDIR /blaze/build/blaze-ui

# Build dependencies only
RUN --mount=type=cache,id=blaze-stackroot,target=/root/.stack \
    --mount=type=cache,id=blazeui-ba-stackwork,target=/blaze/build/binary-analysis/.stack-work \
    --mount=type=cache,id=blazeui-bnhs-stackwork,target=/blaze/build/binaryninja-haskell/.stack-work \
    --mount=type=cache,id=blazeui-blaze-stackwork,target=/blaze/build/blaze/.stack-work \
    --mount=type=cache,id=blazeui-blazeui-stackwork,target=/blaze/build/blaze-ui/server/.stack-work \
    cd server && \
    make \
        STACK_BUILD_OPTIONS="${STACK_BUILD_OPTIONS} --only-dependencies" \
        BUILD_TYPE="${BUILD_TYPE}" \
        build

# Copy and build
COPY server/ /blaze/build/blaze-ui/server
RUN --mount=type=cache,id=blaze-stackroot,target=/root/.stack \
    --mount=type=cache,id=blazeui-ba-stackwork,target=/blaze/build/binary-analysis/.stack-work \
    --mount=type=cache,id=blazeui-bnhs-stackwork,target=/blaze/build/binaryninja-haskell/.stack-work \
    --mount=type=cache,id=blazeui-blaze-stackwork,target=/blaze/build/blaze/.stack-work \
    --mount=type=cache,id=blazeui-blazeui-stackwork,target=/blaze/build/blaze-ui/server/.stack-work \
    cd server && \
    make \
        STACK_BUILD_OPTIONS="${STACK_BUILD_OPTIONS} --copy-bins --local-bin-path /blaze/bin" \
        BUILD_TYPE="${BUILD_TYPE}" \
        TEST_BIN_DEST_DIR="${HOME}/.local/bin" \
        copy-tests

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

FROM ${BLAZE_MINIMAL_BASE_IMAGE} as minimal
SHELL ["/bin/bash", "-c"]

RUN rm -f /etc/apt/apt.conf.d/docker-clean
RUN cat <<-EOF >/etc/apt/apt.conf.d/keep-cache
	Binary::apt::APT::Keep-Downloaded-Packages "true";
EOF

RUN --mount=type=cache,id=blaze-apt,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=blaze-apt-lists,target=/var/apt/lists,sharing=locked \
<<EOF
    apt update -yq
    packages=(
        netbase
        locales

        # binja things
        dbus

        # ghc things
        libffi7
        libgmp10
        libncurses5
        libtinfo5
    )
    apt install -yq --no-install-recommends "${packages[@]}"
EOF

RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

COPY --from=main /usr/share/binaryninja /usr/share/binaryninja
COPY --from=main /root/.binaryninja /root/.binaryninja
COPY --from=main /usr/local/bin/z3 /usr/local/bin/z3
COPY --from=main /blaze/src/ /blaze/src/
COPY --from=main /blaze/bin/blaze-server /blaze/bin/blaze-server

ENV LD_LIBRARY_PATH="/usr/share/binaryninja"
ENV BLAZE_BINJA_API="/usr/share/binaryninja-api"
ENV BINJA_CORE="/usr/share/binaryninja"
ENV BINJA_PLUGINS="/usr/share/binaryninja/plugins"

WORKDIR /blaze

CMD ["/blaze/bin/blaze-server"]


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
    apt update -yq && apt install -yq --no-install-recommends jq moreutils strace
COPY --from=hastatic /usr/bin/hastatic /usr/bin/hastatic
COPY --from=wheel-builder /binja_plugin/dist/*.whl /binja_plugin/dist/plugins.json /www/
COPY .docker/wheel-server-entrypoint /usr/bin/wheel-server-entrypoint
WORKDIR /www
CMD ["/usr/bin/wheel-server-entrypoint"]
