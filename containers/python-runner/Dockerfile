# syntax=docker.io/docker/dockerfile@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
ARG INCIDENTSEAL_PYTHON_IMAGE=cgr.dev/chainguard/python@sha256:69437de912cc3b5d36a2480b8fb0c3f658f151d8bc1978d19a6412be3a4983d5
FROM ${INCIDENTSEAL_PYTHON_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/drwbkr1/incidentseal"
COPY --chown=65532:65532 python_runner.py /opt/incidentseal/python_runner.py
USER 65532:65532
WORKDIR /opt/incidentseal
ENTRYPOINT ["/usr/bin/python"]
CMD ["/opt/incidentseal/python_runner.py"]
