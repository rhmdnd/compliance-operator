FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

ARG xml_path
COPY $xml_path/* .
