FROM alpine:3.18
LABEL maintainer="Cybersecurity Analyst"

# Install dependencies
RUN apk add --no-cache bash wine strace file coreutils grep python3 py3-pip && \
    pip3 install --no-cache-dir binwalk

# Create user and directories
RUN adduser -D -u 1000 analyst && \
    mkdir -p /home/analyst/samples /home/analyst/output && \
    chown analyst:analyst /home/analyst/samples /home/analyst/output

# Copy and set up auto_analyze.sh
COPY auto_analyze.sh /usr/local/bin/auto_analyze.sh
RUN chmod +x /usr/local/bin/auto_analyze.sh && \
    chown analyst:analyst /usr/local/bin/auto_analyze.sh

USER analyst
WORKDIR /home/analyst
CMD ["/bin/bash"]