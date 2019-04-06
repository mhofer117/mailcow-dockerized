#!/bin/bash

source /srv/functions.sh

CERT_DOMAINS=(${DOMAINS[@]})
CERT_DOMAIN=${CERT_DOMAINS[0]}
ACME_BASE=/var/lib/acme

if [[ -z ${CERT_DOMAINS[*]} ]]; then
  log_f "Missing CERT_DOMAINS to obtain a certificate"
  exit 2
fi

if [[ "${LE_STAGING}" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
  log_f "Using Let's Encrypt staging servers"
  STAGING_PARAMETER='--directory-url https://acme-staging-v02.api.letsencrypt.org/directory'
else
  STAGING_PARAMETER=
fi

if [[ -f ${ACME_BASE}/${CERT_DOMAIN}/domains && "$(cat ${ACME_BASE}/${CERT_DOMAIN}/domains)" ==  "${CERT_DOMAINS[*]}" ]]; then
  # Certificate did not change but could be due for renewal (2 weeks)
  if ! openssl x509 -checkend 1209600 -noout -in ${ACME_BASE}/${CERT_DOMAIN}/cert.pem > /dev/null; then
    log_f "Certificate ${CERT_DOMAINS[*]} is due for renewal (< 2 weeks)"
  else
    log_f "Certificate ${CERT_DOMAINS[*]} validation done, neither changed nor due for renewal."
    exit 1
  fi
else
  log_f "Missing certificate with domains: ${CERT_DOMAINS[*]} - start obtaining"
fi

mkdir -p ${ACME_BASE}/${CERT_DOMAIN}
if [[ ! -f ${ACME_BASE}/${CERT_DOMAIN}/key.pem ]]; then
  log_f "Copying shared private key for this certificate..."
  cp ${ACME_BASE}/acme/key.pem ${ACME_BASE}/${CERT_DOMAIN}/key.pem
  chmod 600 ${ACME_BASE}/${CERT_DOMAIN}/key.pem
fi

# Generating CSR
printf "[SAN]\nsubjectAltName=" > /tmp/_SAN
printf "DNS:%s," "${CERT_DOMAINS[@]}" >> /tmp/_SAN
sed -i '$s/,$//' /tmp/_SAN
openssl req -new -sha256 -key ${ACME_BASE}/${CERT_DOMAIN}/key.pem -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf /tmp/_SAN) > ${ACME_BASE}/${CERT_DOMAIN}/acme.csr

# acme-tiny writes info to stderr and ceritifcate to stdout
# The redirects will do the following:
# - redirect stdout to temp certificate file
# - redirect acme-tiny stderr to stdout (logs to variable ACME_RESPONSE)
# - tee stderr to get live output and log to dockerd

ACME_RESPONSE=$(acme-tiny ${STAGING_PARAMETER} \
  --account-key ${ACME_BASE}/acme/account.pem \
  --disable-check \
  --csr ${ACME_BASE}/${CERT_DOMAIN}/acme.csr \
  --acme-dir /var/www/acme/ 2>&1 > /tmp/_cert.pem | tee /dev/fd/5; exit ${PIPESTATUS[0]})
SUCCESS="$?"
ACME_RESPONSE_B64=$(echo "${ACME_RESPONSE}" | openssl enc -e -A -base64)
log_f "${ACME_RESPONSE_B64}" redis_only b64
case "$SUCCESS" in
  0) # cert requested
    log_f "Deploying certificate for ${CERT_DOMAINS[*]}..."
    # Deploy the new certificate and key
    # Moving temp cert to acme/cert.pem
    if verify_hash_match /tmp/_cert.pem ${ACME_BASE}/${CERT_DOMAIN}/key.pem; then
      if [[ -f ${ACME_BASE}/${CERT_DOMAIN}/cert.pem ]]; then
        DATE=$(date +%Y-%m-%d_%H_%M_%S)
        log_f "Creating backup of existing certificate at ${ACME_BASE}/backups/${DATE}/"
        mkdir -p ${ACME_BASE}/backups/${DATE}/
        cp -r ${ACME_BASE}/${CERT_DOMAIN} ${ACME_BASE}/backups/${DATE}/
      fi
      mv -f /tmp/_cert.pem ${ACME_BASE}/${CERT_DOMAIN}/cert.pem
      echo -n ${CERT_DOMAINS[*]} > ${ACME_BASE}/${CERT_DOMAIN}/domains
      rm /var/www/acme/*
      log_f "Certificate successfully obtained"
      exit 0
    else
      log_f "Certificate was successfully requested, but key and certificate have non-matching hashes, ignoring certificate"
      exit 3
    fi
    ;;
  *) # non-zero is non-fun
    log_f "Failed to obtain certificate for ${CERT_DOMAINS[*]}"
    redis-cli -h redis SET ACME_FAIL_TIME "$(date +%s)"
    exit 100${SUCCESS}
    ;;
esac
