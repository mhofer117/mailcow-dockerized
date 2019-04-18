#!/bin/bash
set -o pipefail
exec 5>&1

source /srv/functions.sh
# Thanks to https://github.com/cvmiller -> https://github.com/cvmiller/expand6
source /srv/expand6.sh

# Skipping IP check when we like to live dangerously
if [[ "${SKIP_IP_CHECK}" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
  SKIP_IP_CHECK=y
fi

# Skipping HTTP check when we like to live dangerously
if [[ "${SKIP_HTTP_VERIFICATION}" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
  SKIP_HTTP_VERIFICATION=y
fi

if [[ "${SKIP_LETS_ENCRYPT}" =~ ^([yY][eE][sS]|[yY])+$ ]]; then
  log_f "SKIP_LETS_ENCRYPT=y, skipping Let's Encrypt..."
  sleep 365d
  exec $(readlink -f "$0")
fi

ACME_BASE=/var/lib/acme
SSL_EXAMPLE=/var/lib/ssl-example

# Symlink ECDSA to RSA certificate if not present
[[ ! -f ${ACME_BASE}/ecdsa-cert.pem ]] && [[ ! -L ${ACME_BASE}/ecdsa-cert.pem ]] && ln -s cert.pem ${ACME_BASE}/ecdsa-cert.pem
[[ ! -f ${ACME_BASE}/ecdsa-key.pem ]] && [[ ! -L ${ACME_BASE}/ecdsa-key.pem ]] && ln -s key.pem ${ACME_BASE}/ecdsa-key.pem

log_f "Waiting for Docker API..." no_nl
until ping dockerapi -c1 > /dev/null; do
  sleep 1
done
log_f "OK" no_date

mkdir -p ${ACME_BASE}/acme

# Migrate
[[ -f ${ACME_BASE}/acme/private/privkey.pem ]] && mv ${ACME_BASE}/acme/private/privkey.pem ${ACME_BASE}/acme/key.pem
[[ -f ${ACME_BASE}/acme/private/account.key ]] && mv ${ACME_BASE}/acme/private/account.key ${ACME_BASE}/acme/account.pem
if [[ -f ${ACME_BASE}/acme/key.pem && -f ${ACME_BASE}/acme/cert.pem ]]; then
  if verify_hash_match ${ACME_BASE}/acme/cert.pem ${ACME_BASE}/acme/key.pem; then
    log_f "Migrating to SNI folder structure..."
    CERT_DOMAINS=($(openssl x509 -noout -text -in ${ACME_BASE}/acme/cert.pem | grep "DNS:" | sed -e 's/\(DNS:\)\|,//g' | sed -e 's/^[[:space:]]*//'))
    CERT_DOMAIN=${CERT_DOMAINS[0]}
    mkdir -p ${ACME_BASE}/${CERT_DOMAIN}
    mv ${ACME_BASE}/acme/cert.pem ${ACME_BASE}/${CERT_DOMAIN}/cert.pem
    cp ${ACME_BASE}/acme/key.pem ${ACME_BASE}/${CERT_DOMAIN}/key.pem
    chmod 600 ${ACME_BASE}/${CERT_DOMAIN}/key.pem
    echo -n ${CERT_DOMAINS[*]} > ${ACME_BASE}/${CERT_DOMAIN}/domains
    mv ${ACME_BASE}/acme/acme.csr ${ACME_BASE}/${CERT_DOMAIN}/acme.csr
  fi
fi

[[ ! -f ${ACME_BASE}/dhparams.pem ]] && cp ${SSL_EXAMPLE}/dhparams.pem ${ACME_BASE}/dhparams.pem

CUSTOM_CERT=0
if [[ -f ${ACME_BASE}/cert.pem ]] && [[ -f ${ACME_BASE}/key.pem ]]; then
  ISSUER=$(openssl x509 -in ${ACME_BASE}/cert.pem -noout -issuer)
  if [[ ${ISSUER} != *"Let's Encrypt"* && ${ISSUER} != *"mailcow"* && ${ISSUER} != *"Fake LE Intermediate"* ]]; then
    log_f "Found certificate with issuer other than mailcow snake-oil CA and Let's Encrypt, do not replace server certificate..."

    # Make sure we do not combine Letsencrypt ECDSA with another RSA certificate
    # Remove ECDSA if that is the case
    if [[ -f ${ACME_BASE}/ecdsa-cert.pem ]] && [[ -f ${ACME_BASE}/ecdsa-key.pem ]] && [[ ! -L ${ACME_BASE}/ecdsa-cert.pem ]] && [[ ! -L ${ACME_BASE}/ecdsa-key.pem ]]; then
      ISSUER=$(openssl x509 -in ${ACME_BASE}/ecdsa-cert.pem -noout -issuer)
      if [[ ${ISSUER} == *"Let's Encrypt"* || ${ISSUER} == *"mailcow"* || ${ISSUER} == *"Fake LE Intermediate"* ]]; then
        log_f "Remove Let's Encrypt ECDSA certificate in favour of a custom RSA one"
        ln -sf cert.pem ${ACME_BASE}/ecdsa-cert.pem
        ln -sf key.pem ${ACME_BASE}/ecdsa-key.pem
      fi
    fi
    CUSTOM_CERT=1
  fi
else
  if [[ -f ${ACME_BASE}/acme/cert.pem ]] && [[ -f ${ACME_BASE}/acme/key.pem ]] && verify_hash_match ${ACME_BASE}/acme/cert.pem ${ACME_BASE}/acme/key.pem; then
    log_f "Restoring previous acme certificate and restarting script..."
    cp ${ACME_BASE}/acme/cert.pem ${ACME_BASE}/cert.pem
    cp ${ACME_BASE}/acme/key.pem ${ACME_BASE}/key.pem

    if [[ -f ${ACME_BASE}/acme/ecdsa-cert.pem ]] && [[ -f ${ACME_BASE}/acme/ecdsa-key.pem ]] && verify_hash_match ${ACME_BASE}/acme/ecdsa-cert.pem ${ACME_BASE}/acme/ecdsa-key.pem; then
      # Remove symlink before copying
      cp --remove-destination ${ACME_BASE}/acme/ecdsa-cert.pem ${ACME_BASE}/ecdsa-cert.pem
      cp --remove-destination ${ACME_BASE}/acme/ecdsa-key.pem ${ACME_BASE}/ecdsa-key.pem
    fi
    # Restarting with env var set to trigger a restart,
    exec env TRIGGER_RESTART=1 $(readlink -f "$0")
  else
    log_f "Restoring mailcow snake-oil certificates and restarting script..."
    cp ${SSL_EXAMPLE}/cert.pem ${ACME_BASE}/cert.pem
    cp ${SSL_EXAMPLE}/key.pem ${ACME_BASE}/key.pem
    ln -sf cert.pem ${ACME_BASE}/ecdsa-cert.pem
    ln -sf key.pem ${ACME_BASE}/ecdsa-key.pem
    exec env TRIGGER_RESTART=1 $(readlink -f "$0")
  fi
fi

chmod 600 ${ACME_BASE}/key.pem
chmod 600 ${ACME_BASE}/ecdsa-key.pem

log_f "Waiting for database... " no_nl
while ! mysqladmin status --socket=/var/run/mysqld/mysqld.sock -u${DBUSER} -p${DBPASS} --silent; do
  sleep 2
done
log_f "OK" no_date

log_f "Waiting for Nginx... " no_nl
until $(curl --output /dev/null --silent --head --fail http://nginx:8081); do
  sleep 2
done
log_f "OK" no_date

# Waiting for domain table
log_f "Waiting for domain table... " no_nl
while [[ -z ${DOMAIN_TABLE} ]]; do
  curl --silent http://nginx/ >/dev/null 2>&1
  DOMAIN_TABLE=$(mysql --socket=/var/run/mysqld/mysqld.sock -u ${DBUSER} -p${DBPASS} ${DBNAME} -e "SHOW TABLES LIKE 'domain'" -Bs)
  [[ -z ${DOMAIN_TABLE} ]] && sleep 10
done
log_f "OK" no_date

log_f "Initializing, please wait... "

while true; do

  # Re-using previous acme-mailcow account and domain keys
  if [[ ! -f ${ACME_BASE}/acme/key.pem ]]; then
    log_f "Generating missing domain private rsa key..."
    openssl genrsa 4096 > ${ACME_BASE}/acme/key.pem
  else
    log_f "Using existing domain rsa key ${ACME_BASE}/acme/key.pem"
  fi
  if [[ ! -f ${ACME_BASE}/acme/ecdsa-key.pem ]]; then
    log_f "Generating missing domain private ecdsa key..."
    openssl ecparam -genkey -name secp384r1 -noout > ${ACME_BASE}/acme/ecdsa-key.pem
  else
    log_f "Using existing domain ecdsa key ${ACME_BASE}/acme/ecdsa-key.pem"
  fi
  if [[ ! -f ${ACME_BASE}/acme/account.pem ]]; then
    log_f "Generating missing Lets Encrypt account key..."
    openssl genrsa 4096 > ${ACME_BASE}/acme/account.pem
  else
    log_f "Using existing Lets Encrypt account key ${ACME_BASE}/acme/account.pem"
  fi

  chmod 600 ${ACME_BASE}/acme/key.pem
  chmod 600 ${ACME_BASE}/acme/ecdsa-key.pem
  chmod 600 ${ACME_BASE}/acme/account.pem

  unset EXISTING_CERTS
  declare -a EXISTING_CERTS
  for cert_dir in ${ACME_BASE}/*/ ; do
    if [[ ! -f ${cert_dir}domains ]] || [[ ! -f ${cert_dir}cert.pem ]] || [[ ! -f ${cert_dir}key.pem ]]; then
      continue
    fi
    EXISTING_CERTS+=("$(cat ${cert_dir}domains)")
  done

  # Cleaning up and init validation arrays
  unset SQL_DOMAIN_ARR
  unset ADDITIONAL_VALIDATED_SAN
  unset ADDITIONAL_WC_ARR
  unset ADDITIONAL_SAN_ARR
  unset CERT_ERRORS
  unset CERT_CHANGED
  unset CERT_AMOUNT_CHANGED
  unset VALIDATED_CERTIFICATES
  CERT_ERRORS=0
  CERT_CHANGED=0
  CERT_AMOUNT_CHANGED=0
  declare -a SQL_DOMAIN_ARR
  declare -a ADDITIONAL_VALIDATED_SAN
  declare -a ADDITIONAL_WC_ARR
  declare -a ADDITIONAL_SAN_ARR
  declare -a VALIDATED_CERTIFICATES
  IFS=',' read -r -a TMP_ARR <<< "${ADDITIONAL_SAN}"
  for i in "${TMP_ARR[@]}" ; do
    if [[ "$i" =~ \.\*$ ]]; then
      ADDITIONAL_WC_ARR+=(${i::-2})
    else
      ADDITIONAL_SAN_ARR+=($i)
    fi
  done
  ADDITIONAL_WC_ARR+=('autodiscover')

  # Start IP detection
  log_f "Detecting IP addresses... " no_nl
  IPV4=$(get_ipv4)
  IPV6=$(get_ipv6)
  log_f "OK" no_date

  # Hard-fail on CAA errors for MAILCOW_HOSTNAME
  MH_PARENT_DOMAIN=$(echo ${MAILCOW_HOSTNAME} | cut -d. -f2-)
  MH_CAAS=( $(dig CAA ${MH_PARENT_DOMAIN} +short | sed -n 's/\d issue "\(.*\)"/\1/p') )
  if [[ ! -z ${MH_CAAS} ]]; then
    if [[ ${MH_CAAS[@]} =~ "letsencrypt.org" ]]; then
      echo "Validated CAA for parent domain ${MH_PARENT_DOMAIN}"
    else
      echo "Skipping ACME validation: Lets Encrypt disallowed for ${MAILCOW_HOSTNAME} by CAA record, retrying in 1h..."
      sleep 1h
      exec $(readlink -f "$0")
    fi
  fi

  A_MAILCOW_HOSTNAME=$(dig A ${MAILCOW_HOSTNAME} +short | tail -n 1)
  AAAA_MAILCOW_HOSTNAME=$(dig AAAA ${MAILCOW_HOSTNAME} +short | tail -n 1)
  # Check if CNAME without v6 enabled target
  if [[ ! -z ${AAAA_MAILCOW_HOSTNAME} ]] && [[ -z $(echo ${AAAA_MAILCOW_HOSTNAME} | grep "^\([0-9a-fA-F]\{0,4\}:\)\{1,7\}[0-9a-fA-F]\{0,4\}$") ]]; then
    AAAA_MAILCOW_HOSTNAME=
  fi
  if [[ ! -z ${AAAA_MAILCOW_HOSTNAME} ]]; then
    log_f "Found AAAA record for ${MAILCOW_HOSTNAME}: ${AAAA_MAILCOW_HOSTNAME} - skipping A record check"
    if [[ $(expand ${IPV6:-"0000:0000:0000:0000:0000:0000:0000:0000"}) == $(expand ${AAAA_MAILCOW_HOSTNAME}) ]] || [[ ${SKIP_IP_CHECK} == "y" ]]; then
      if verify_challenge_path "${MAILCOW_HOSTNAME}" 6; then
        log_f "Confirmed AAAA record ${AAAA_MAILCOW_HOSTNAME}"
        VALIDATED_MAILCOW_HOSTNAME=${MAILCOW_HOSTNAME}
      else
        log_f "Confirmed AAAA record ${A_MAILCOW_HOSTNAME}, but HTTP validation failed"
      fi
    else
      log_f "Cannot match your IP ${IPV6:-NO_IPV6_LINK} against hostname ${MAILCOW_HOSTNAME} ($(expand ${AAAA_MAILCOW_HOSTNAME}))"
    fi
  elif [[ ! -z ${A_MAILCOW_HOSTNAME} ]]; then
    log_f "Found A record for ${MAILCOW_HOSTNAME}: ${A_MAILCOW_HOSTNAME}"
    if [[ ${IPV4:-ERR} == ${A_MAILCOW_HOSTNAME} ]] || [[ ${SKIP_IP_CHECK} == "y" ]]; then
      if verify_challenge_path "${MAILCOW_HOSTNAME}" 4; then
        log_f "Confirmed A record ${A_MAILCOW_HOSTNAME}"
        VALIDATED_MAILCOW_HOSTNAME=${MAILCOW_HOSTNAME}
      else
        log_f "Confirmed A record ${A_MAILCOW_HOSTNAME}, but HTTP validation failed"
      fi
    else
      log_f "Cannot match your IP ${IPV4} against hostname ${MAILCOW_HOSTNAME} (${A_MAILCOW_HOSTNAME})"
    fi
  else
    log_f "No A or AAAA record found for hostname ${MAILCOW_HOSTNAME}"
  fi

  for SAN in "${ADDITIONAL_SAN_ARR[@]}"; do
    # Skip on CAA errors for SAN
    SAN_PARENT_DOMAIN=$(echo ${SAN} | cut -d. -f2-)
    SAN_CAAS=( $(dig CAA ${SAN_PARENT_DOMAIN} +short | sed -n 's/\d issue "\(.*\)"/\1/p') )
    if [[ ! -z ${SAN_CAAS} ]]; then
      if [[ ${SAN_CAAS[@]} =~ "letsencrypt.org" ]]; then
        echo "Validated CAA for parent domain ${SAN_PARENT_DOMAIN} of ${SAN}"
      else
        echo "Skipping ACME validation for ${SAN}: Lets Encrypt disallowed for ${SAN} by CAA record"
        continue
      fi
    fi
    if [[ ${SAN} == ${MAILCOW_HOSTNAME} ]]; then
      continue
    fi
    A_SAN=$(dig A ${SAN} +short | tail -n 1)
    AAAA_SAN=$(dig AAAA ${SAN} +short | tail -n 1)
    # Check if CNAME without v6 enabled target
    if [[ ! -z ${AAAA_SAN} ]] && [[ -z $(echo ${AAAA_SAN} | grep "^\([0-9a-fA-F]\{0,4\}:\)\{1,7\}[0-9a-fA-F]\{0,4\}$") ]]; then
      AAAA_SAN=
    fi
    if [[ ! -z ${AAAA_SAN} ]]; then
      log_f "Found AAAA record for ${SAN}: ${AAAA_SAN} - skipping A record check"
      if [[ $(expand ${IPV6:-"0000:0000:0000:0000:0000:0000:0000:0000"}) == $(expand ${AAAA_SAN}) ]] || [[ ${SKIP_IP_CHECK} == "y" ]]; then
        if verify_challenge_path "${SAN}" 6; then
          log_f "Confirmed AAAA record ${AAAA_SAN}"
          ADDITIONAL_VALIDATED_SAN+=("${SAN}")
        else
          log_f "Confirmed AAAA record ${AAAA_SAN}, but HTTP validation failed"
        fi
      else
        log_f "Cannot match your IP ${IPV6:-NO_IPV6_LINK} against hostname ${SAN} ($(expand ${AAAA_SAN}))"
      fi
    elif [[ ! -z ${A_SAN} ]]; then
      log_f "Found A record for ${SAN}: ${A_SAN}"
      if [[ ${IPV4:-ERR} == ${A_SAN} ]] || [[ ${SKIP_IP_CHECK} == "y" ]]; then
        if verify_challenge_path "${SAN}" 4; then
          log_f "Confirmed A record ${A_SAN}"
          ADDITIONAL_VALIDATED_SAN+=("${SAN}")
        else
          log_f "Confirmed A record ${A_SAN}, but HTTP validation failed"
        fi
      else
        log_f "Cannot match your IP ${IPV4} against hostname ${SAN} (${A_SAN})"
      fi
    else
      log_f "No A or AAAA record found for hostname ${SAN}"
    fi
  done

  # Unique elements
  SERVER_SAN_VALIDATED=(${VALIDATED_MAILCOW_HOSTNAME} $(echo ${ADDITIONAL_VALIDATED_SAN[*]} | xargs -n1 | sort -u | xargs))
  if [[ ! -z ${SERVER_SAN_VALIDATED[*]} ]]; then
    CERT_NAME=${SERVER_SAN_VALIDATED[0]}
    VALIDATED_CERTIFICATES+=("$(echo ${SERVER_SAN_VALIDATED[*]})")
    # obtain server certificate if required
    DOMAINS=${SERVER_SAN_VALIDATED[@]} /srv/obtain-certificate.sh
    if [[ "$?" == "0" ]]; then
      if [[ "`printf '_%s_\n' "${EXISTING_CERTS[@]}"`" != *"_${SERVER_SAN_VALIDATED[*]}_"* ]]; then
        CERT_AMOUNT_CHANGED=1
      fi
      CERT_CHANGED=1
      if [[ "${CUSTOM_CERT}" != "1" ]]; then
        # create relative symbolic link as server certificate
        cd ${ACME_BASE}
        ln -sf "./${CERT_NAME}/cert.pem" "./cert.pem"
        ln -sf "./${CERT_NAME}/key.pem" "./key.pem"
      fi
    elif [[ "$?" == "1" ]]; then
      : # certificate exists and no renewel was required
    else
      log_f "Could not obtain server certificate, retrying in 30 minutes..."
      sleep 30m
      exec $(readlink -f "$0")
    fi
  fi

  #########################################
  # IP and webroot challenge verification #
  while read domains; do
    SQL_DOMAIN_ARR+=("${domains}")
  done < <(mysql --socket=/var/run/mysqld/mysqld.sock -u ${DBUSER} -p${DBPASS} ${DBNAME} -e "SELECT domain FROM domain WHERE backupmx=0" -Bs)

  for SQL_DOMAIN in "${SQL_DOMAIN_ARR[@]}"; do
    unset VALIDATED_CONFIG_DOMAINS
    declare -a VALIDATED_CONFIG_DOMAINS
    for SUBDOMAIN in "${ADDITIONAL_WC_ARR[@]}"; do
      if [[  "${SUBDOMAIN}.${SQL_DOMAIN}" != "${MAILCOW_HOSTNAME}" ]]; then
        A_SUBDOMAIN=$(dig A ${SUBDOMAIN}.${SQL_DOMAIN} +short | tail -n 1)
        AAAA_SUBDOMAIN=$(dig AAAA ${SUBDOMAIN}.${SQL_DOMAIN} +short | tail -n 1)
        # Check if CNAME without v6 enabled target
        if [[ ! -z ${AAAA_SUBDOMAIN} ]] && [[ -z $(echo ${AAAA_SUBDOMAIN} | grep "^\([0-9a-fA-F]\{0,4\}:\)\{1,7\}[0-9a-fA-F]\{0,4\}$") ]]; then
          AAAA_SUBDOMAIN=
        fi
        if [[ ! -z ${AAAA_SUBDOMAIN} ]]; then
          log_f "Found AAAA record for ${SUBDOMAIN}.${SQL_DOMAIN}: ${AAAA_SUBDOMAIN} - skipping A record check"
          if [[ $(expand ${IPV6:-"0000:0000:0000:0000:0000:0000:0000:0000"}) == $(expand ${AAAA_SUBDOMAIN}) ]] || [[ ${SKIP_IP_CHECK} == "y" ]]; then
            if verify_challenge_path "${SUBDOMAIN}.${SQL_DOMAIN}" 6; then
              log_f "Confirmed AAAA record ${AAAA_SUBDOMAIN}"
              VALIDATED_CONFIG_DOMAINS+=("${SUBDOMAIN}.${SQL_DOMAIN}")
            else
              log_f "Confirmed AAAA record ${AAAA_SUBDOMAIN}, but HTTP validation failed"
            fi
          else
            log_f "Cannot match your IP ${IPV6:-NO_IPV6_LINK} against hostname ${SUBDOMAIN}.${SQL_DOMAIN} ($(expand ${AAAA_SUBDOMAIN}))"
          fi
        elif [[ ! -z ${A_SUBDOMAIN} ]]; then
          log_f "Found A record for ${SUBDOMAIN}.${SQL_DOMAIN}: ${A_SUBDOMAIN}"
          if [[ ${IPV4:-ERR} == ${A_SUBDOMAIN} ]] || [[ ${SKIP_IP_CHECK} == "y" ]]; then
            if verify_challenge_path "${SUBDOMAIN}.${SQL_DOMAIN}" 4; then
              log_f "Confirmed A record ${A_SUBDOMAIN}"
              VALIDATED_CONFIG_DOMAINS+=("${SUBDOMAIN}.${SQL_DOMAIN}")
            else
              log_f "Confirmed AAAA record ${A_SUBDOMAIN}, but HTTP validation failed"
            fi
          else
            log_f "Cannot match your IP ${IPV4} against hostname ${SUBDOMAIN}.${SQL_DOMAIN} (${A_SUBDOMAIN})"
          fi
        else
          log_f "No A or AAAA record found for hostname ${SUBDOMAIN}.${SQL_DOMAIN}"
        fi
      fi
    done

    unset VALIDATED_CONFIG_DOMAINS_SORTED
    declare -a VALIDATED_CONFIG_DOMAINS_SORTED
    VALIDATED_CONFIG_DOMAINS_SORTED=(${VALIDATED_CONFIG_DOMAINS[0]} $(echo ${VALIDATED_CONFIG_DOMAINS[@]:1} | xargs -n1 | sort -u | xargs))

    if [[ ! -z ${VALIDATED_CONFIG_DOMAINS_SORTED[*]} ]]; then
      CERT_NAME=${VALIDATED_CONFIG_DOMAINS_SORTED[0]}
      VALIDATED_CERTIFICATES+=("$(echo ${VALIDATED_CONFIG_DOMAINS_SORTED[*]})")
      # obtain server certificate if required
      DOMAINS=${VALIDATED_CONFIG_DOMAINS_SORTED[@]} /srv/obtain-certificate.sh
      if [[ "$?" == "0" ]]; then
        if [[ "`printf '_%s_\n' "${EXISTING_CERTS[@]}"`" != *"_${VALIDATED_CONFIG_DOMAINS_SORTED[*]}_"* ]]; then
          CERT_AMOUNT_CHANGED=1
        fi
        CERT_CHANGED=1
      elif [[ "$?" == "1" ]]; then
        : # certificate exists and no renewel was required
      else
        CERT_ERRORS=1
      fi
    fi
  done

  if [[ -z ${VALIDATED_CERTIFICATES[*]} ]]; then
    log_f "Cannot validate any hostnames, skipping Let's Encrypt for 1 hour."
    log_f "Use SKIP_LETS_ENCRYPT=y in mailcow.conf to skip it permanently."
    sleep 1h
    exec $(readlink -f "$0")
  fi

  # find orphaned certificates
  for CERT_DOMAINS in "${EXISTING_CERTS[@]}"; do
    if [[ ! "`printf '_%s_\n' "${VALIDATED_CERTIFICATES[@]}"`" == *"_${CERT_DOMAINS}_"* ]]; then
      CERT_DOMAINS_ARR=(${CERT_DOMAINS})
      if [[ "$(cat ${ACME_BASE}/${CERT_DOMAINS_ARR[0]}/domains)" != "${CERT_DOMAINS}" ]]; then
        # cert was modified so not obsolete
        continue
      fi
      DATE=$(date +%Y-%m-%d_%H_%M_%S)
      log_f "Found orphaned certificate: ${CERT_DOMAINS} - archiving it at ${ACME_BASE}/backups/${DATE}/"
      mkdir -p ${ACME_BASE}/backups/${DATE}/
      cp -r ${ACME_BASE}/${CERT_DOMAINS_ARR[0]} ${ACME_BASE}/backups/${DATE}/
      rm -rf ${ACME_BASE}/${CERT_DOMAINS_ARR[0]}
      CERT_CHANGED=1
      CERT_AMOUNT_CHANGED=1
    fi
  done

  # reload on new or changed certificates
  if [[ "${CERT_CHANGED}" == "1" ]]; then
    CERT_AMOUNT_CHANGED=${CERT_AMOUNT_CHANGED} /srv/reload-configurations.sh
  fi

  case "$CERT_ERRORS" in
    0) # all successful
      log_f "Certificates successfully processed, sleeping 1d"
      sleep 1d
      ;;
    *) # non-zero
      log_f "Some errors occurred, retrying in 30 minutes..."
      redis-cli -h redis SET ACME_FAIL_TIME "$(date +%s)"
      sleep 30m
      exec $(readlink -f "$0")
      ;;
  esac

done
