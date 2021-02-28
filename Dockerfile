ARG BLAZE_IMAGE=${CI_REGISTRY}/${CI_PROJECT_NAMESPACE}/blaze/blaze:latest

FROM ${BLAZE_IMAGE}
RUN apt install -yq \
    zlib1g-dev

COPY ./ /blaze/blaze-ui
WORKDIR /blaze/blaze-ui/server

RUN stack build --test --no-run-tests --ghc-options -fdiagnostics-color=always

# Note: blaze-ui can also accept these arguments as set environment variables.
# ARG BLAZE_UI_HOST=localhost
# ARG BLAZE_UI_WEBSOCKETS_PORT=5765
# ARG BLAZE_UI_HTTP_PORT=5766

# RUN stack run -- ${BLAZE_UI_HOST} ${BLAZE_UI_WEBSOCKETS_PORT} ${BLAZE_UI_HTTP_PORT}
