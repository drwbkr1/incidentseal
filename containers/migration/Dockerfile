# syntax=docker.io/docker/dockerfile@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
ARG INCIDENTSEAL_POSTGRES_IMAGE=cgr.dev/chainguard/postgres@sha256:64c33dd94e09026bb01639329e46f2944dc1f794b04d3d2191f268ba7352fab9
FROM ${INCIDENTSEAL_POSTGRES_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/drwbkr1/incidentseal"
COPY --chown=70:70 001-schema.sql /opt/incidentseal/migrations/001-schema.sql
USER 70:70
WORKDIR /opt/incidentseal
ENTRYPOINT ["/usr/bin/psql"]
CMD ["--host=database","--username=incidentseal_admin","--dbname=incidentseal","--set=ON_ERROR_STOP=1","--file=/opt/incidentseal/migrations/001-schema.sql"]
