ARG TOOL_BASE=tuc-go
ARG TUC_IMAGE=tuc
FROM ${TUC_IMAGE} AS runtime
FROM ${TOOL_BASE}
RUN apt-get update && apt-get install -y --no-install-recommends python3 systemd && rm -rf /var/lib/apt/lists/*
COPY --from=runtime /usr/local/bin/tuc /opt/tuc/current/bin/tuc
RUN mkdir -p /opt/tuc/current && ln -s /opt/openssl /opt/tuc/current/openssl && \
    mkdir -p /usr/local/libexec && printf '#!/bin/sh\nexit 1\n' > /usr/local/libexec/tuc-deliver && chmod 755 /usr/local/libexec/tuc-deliver

COPY deploy/tuc /usr/local/bin/tuc
RUN chmod 755 /usr/local/bin/tuc
