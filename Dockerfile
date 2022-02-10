ARG BLAZE_IMAGE=${CI_REGISTRY}/blaze/blaze/blaze:latest

FROM ${BLAZE_IMAGE} as main
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,id=blaze-apt,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=blaze-apt-lists,target=/var/apt/lists,sharing=locked \
    apt install -yq \
        zlib1g-dev

COPY server/ /blaze/build/blaze-ui/server/
WORKDIR /blaze/build/blaze-ui/server
RUN stack build --test --no-run-tests --ghc-options -fdiagnostics-color=always

ENV BLAZE_UI_HOST=localhost
ENV BLAZE_UI_WS_PORT=5765
ENV BLAZE_UI_HTTP_PORT=5766

COPY .ci/ /blaze/build/blaze-ui/.ci/
COPY ./ /blaze/src/blaze-ui/

CMD ["stack", "exec", "blaze-server"]


FROM main as minimal
RUN cd /blaze/build/blaze-ui/server && stack install --copy-bins --local-bin-path /blaze/bin
SHELL ["/bin/bash", "-c"]
WORKDIR /blaze
RUN shopt -s nullglob && \
    rm -rf \
        /var/cache/apt \
        /var/apt/lists \
        /root/.local/bin/stack \
        /usr/local/bin/stack \
        /blaze/build \
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


FROM python:3.8 as wheel-builder
RUN apt update && apt install -y --no-install-recommends jq
RUN pip install toml-cli build pkginfo
COPY binja_plugin/ /binja_plugin/
WORKDIR /binja_plugin
ARG CI_PIPELINE_ID=
RUN CI_PIPELINE_ID=${CI_PIPELINE_ID} ./package_plugin.sh


FROM abhin4v/hastatic:latest as hastatic


FROM ubuntu:latest as wheel-server
RUN apt update && apt install -y --no-install-recommends jq moreutils
COPY --from=hastatic /usr/bin/hastatic /usr/bin/hastatic
COPY --from=wheel-builder /binja_plugin/dist/*.whl /binja_plugin/dist/plugins.json /www/
COPY .docker/wheel-server-entrypoint /usr/bin/wheel-server-entrypoint
WORKDIR /www
CMD ["/usr/bin/wheel-server-entrypoint"]
