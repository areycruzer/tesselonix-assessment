FROM alpine:3.19
RUN apk add --no-cache iptables iproute2 dnsmasq tcpdump
COPY entrypoint.sh /entrypoint.sh
COPY dnsmasq.conf /etc/dnsmasq.conf
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
