#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

FROM consensys/web3signer:22.10-jdk11
USER root

RUN apt-get -y update && apt-get -y install python3 python3-pip net-tools

WORKDIR /app
RUN mkdir /app/data
RUN mkdir /app/certs

COPY ./kms/kmstool_enclave_cli ./
COPY ./kms/libnsm.so /usr/lib64/

ARG REGION_ARG
ENV REGION=$REGION_ARG

ARG LOG_LEVEL_ARG
ENV LOG_LEVEL=$LOG_LEVEL_ARG

ENV LD_LIBRARY_PATH=/usr/lib64

RUN mkdir -p ./key_files
COPY requirements.txt ./

COPY enclave.py ./
COPY enclave_functions.py ./

RUN pip3 install -r /app/requirements.txt

COPY run.sh ./
RUN chmod +x /app/run.sh

ENTRYPOINT ["/app/run.sh"]
