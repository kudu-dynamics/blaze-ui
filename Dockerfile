ARG BLAZE_IMAGE=${CI_REGISTRY}/${CI_PROJECT_NAMESPACE}/blaze/blaze:latest

FROM ${BLAZE_IMAGE}
RUN apt install -yq \
    zlib1g-dev

COPY ./ /blaze/blaze-ui
WORKDIR /blaze/blaze-ui/server

RUN stack build --test --no-run-tests --ghc-options -fdiagnostics-color=always

ENV BLAZE_UI_HOST=localhost
ENV BLAZE_UI_WS_PORT=5765
ENV BLAZE_UI_HTTP_PORT=5766

CMD ["stack", "exec", "blaze-ui-server"]
