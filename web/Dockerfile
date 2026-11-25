# Hugging Face Space (Docker SDK). Build context: repository root.
#   docker build -f web/Dockerfile -t capsight-web .
FROM python:3.12-slim

RUN apt-get update \
 && echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 user
WORKDIR /home/user/app
COPY --chown=user . .
RUN pip install --no-cache-dir ".[web]"

USER user
ENV GRADIO_SERVER_NAME=0.0.0.0 GRADIO_SERVER_PORT=7860 \
    CAPSIGHT_SAMPLES=/home/user/app/samples/synthetic
EXPOSE 7860
CMD ["capsight-web"]
