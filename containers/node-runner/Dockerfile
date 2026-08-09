# syntax=docker.io/docker/dockerfile@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
ARG INCIDENTSEAL_NODE_IMAGE=gcr.io/distroless/nodejs24-debian13@sha256:fbbdda866ea71aef98c4abece17e3d61fbf820cc2ef3961522caa2478716171a
FROM ${INCIDENTSEAL_NODE_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/drwbkr1/incidentseal"
COPY --chown=65532:65532 node_runner.mjs /opt/incidentseal/node_runner.mjs
USER 65532:65532
WORKDIR /opt/incidentseal
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["/opt/incidentseal/node_runner.mjs"]
