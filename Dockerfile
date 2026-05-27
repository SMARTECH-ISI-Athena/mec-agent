FROM python:3.11-alpine

WORKDIR /agent

RUN apk add --no-cache docker-cli iputils

COPY agent.py /agent/agent.py

ENV FLOW_CONTROLLER_URL=http://192.168.0.1:9090
ENV FLOW_DIRECT_PATH=/flow/all/direct
ENV FLOW_CHAIN_PATH=/flow/all/chain
ENV POLL_INTERVAL_SECONDS=2
ENV TELEMETRY_ENABLED=true
ENV PYTHONUNBUFFERED=1
ENV AGENT_ROLE=controller
ENV NODE_NAME=upf-cn
ENV LOCAL_UPF_CONTAINER=oai-upf
ENV N9_CIDR=172.32.0.0/24
ENV N6_CIDR=172.33.0.0/24

CMD ["python", "/agent/agent.py"]
