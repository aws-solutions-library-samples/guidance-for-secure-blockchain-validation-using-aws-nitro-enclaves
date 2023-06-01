#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set -e
set +x

output=${1}

check_openssl_version() {
  export openssl_minversion=3.0.0
  if echo -e "$(openssl version|awk '{print $2}')\n${openssl_minversion}" | sort -V | head -1 | grep -q ^${openssl_minversion}$;then
    echo "OpenSSL version is correct"
  else
    current_version=$(openssl version|awk '{print $2}')
    echo "Your OpenSSL version is ${current_version}. You need OpenSSL version 3. Exiting."
    exit 1
  fi
}

# NLB DNS name
stack_name=$(jq -r '. |= keys | .[0]' ${output})
enclave_cn=$(jq -r '."'${stack_name}'".SignerELBFQDN' ${output})
client_cn=${USER}_curl

tls_password_enclave=$(openssl rand -hex 20)
tls_password_client=$(openssl rand -hex 20)

folder_suffix=$(openssl rand -hex 5)

enclave_folder="keygen_enclave_${folder_suffix}"
client_folder="keygen_client_${folder_suffix}"

generate_tls_artifact() {
  local fqdn=${1}
  local password=${2}

  openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
  # generate associated public key
  openssl ec -in private-key.pem -pubout -out public-key.pem
  # generate self-signed x509 certificate for EC2 instance
  host=$(echo ${fqdn} | tr "." "\n" | head -n 1)
  # requires openssl > 1.1.1
  openssl req -new -x509 -key private-key.pem -out cert.pem -days 360 -subj "/C=US/O=AWS/OU=Blockchain Compute/CN=${host}" --addext "subjectAltName=DNS:${fqdn},DNS:localhost,IP:127.0.0.1"
  # generate PKCS12 container for key and x509 cert
  openssl pkcs12 -export -out keyStore.p12 -inkey private-key.pem -in cert.pem -password pass:${password}
}

check_openssl_version
# generate enclave artifacts
mkdir ${enclave_folder}
cd ./${enclave_folder}
generate_tls_artifact ${enclave_cn} ${tls_password_enclave}
echo "current folder prefix: $(echo ${folder_suffix})"
echo "tls_keystore_b64: $(cat keyStore.p12 | base64)"
echo "tls_password_b64: $(echo ${tls_password_enclave} | base64)"
cd ..

# generate client keystore
#mkdir ${client_folder}
#cd ./${client_folder}
#generate_tls_artifact ${client_cn} ${tls_password_client}
#sha256=$(openssl x509 -noout -fingerprint -sha256 -in cert.pem | tr "=" "\n" | tail -n 1)
#known_clients_b64=$(echo "${client_cn} ${sha256}" | base64)
#echo "tls_password_client: $(echo ${tls_password_client})"
#echo "tls_keystore_client_b64: $(cat keyStore.p12 | base64)"
#echo "tls_known_clients_b64: $(echo ${known_clients_b64})"
#cd ..
