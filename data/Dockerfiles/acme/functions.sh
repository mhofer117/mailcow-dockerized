#!/bin/bash

log_f() {
  if [[ ${2} == "no_nl" ]]; then
    echo -n "$(date) - ${1}"
  elif [[ ${2} == "no_date" ]]; then
    echo "${1}"
  elif [[ ${2} != "redis_only" ]]; then
    echo "$(date) - ${1}"
  fi
  if [[ ${3} == "b64" ]]; then
    redis-cli -h redis LPUSH ACME_LOG "{\"time\":\"$(date +%s)\",\"message\":\"base64,$(printf '%s' "${1}")\"}" > /dev/null
  else
    redis-cli -h redis LPUSH ACME_LOG "{\"time\":\"$(date +%s)\",\"message\":\"$(printf '%s' "${1}" | \
      tr '%&;$"[]{}-\r\n' ' ')\"}" > /dev/null
  fi
}

verify_hash_match(){
  CERT_HASH=$(openssl x509 -in "${1}" -noout -pubkey | openssl md5)
  KEY_HASH=$(openssl pkey -in "${2}" -pubout | openssl md5)
  if [[ ${CERT_HASH} != ${KEY_HASH} ]]; then
    log_f "Certificate and key hashes do not match!"
    return 1
  else
    log_f "Verified hashes."
    return 0
  fi
}

get_ipv4(){
  local IPV4=
  local IPV4_SRCS=
  local TRY=
  IPV4_SRCS[0]="ip4.mailcow.email"
  IPV4_SRCS[1]="ip4.korves.net"
  until [[ ! -z ${IPV4} ]] || [[ ${TRY} -ge 10 ]]; do
    IPV4=$(curl --connect-timeout 3 -m 10 -L4s ${IPV4_SRCS[$RANDOM % ${#IPV4_SRCS[@]} ]} | grep -E "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    [[ ! -z ${TRY} ]] && sleep 1
    TRY=$((TRY+1))
  done
  echo ${IPV4}
}

get_ipv6(){
  local IPV6=
  local IPV6_SRCS=
  local TRY=
  IPV6_SRCS[0]="ip6.korves.net"
  IPV6_SRCS[1]="ip6.mailcow.email"
  until [[ ! -z ${IPV6} ]] || [[ ${TRY} -ge 10 ]]; do
    IPV6=$(curl --connect-timeout 3 -m 10 -L6s ${IPV6_SRCS[$RANDOM % ${#IPV6_SRCS[@]} ]} | grep "^\([0-9a-fA-F]\{0,4\}:\)\{1,7\}[0-9a-fA-F]\{0,4\}$")
    [[ ! -z ${TRY} ]] && sleep 1
    TRY=$((TRY+1))
  done
  echo ${IPV6}
}

verify_challenge_path(){
  # verify_challenge_path URL 4|6
  RAND_FILE=${RANDOM}${RANDOM}${RANDOM}
  touch /var/www/acme/${RAND_FILE}
  if [[ ${SKIP_HTTP_VERIFICATION} == "y" ]]; then
    echo '(skipping check, returning 0)'
    return 0
  elif [[ "$(curl -${2} http://${1}/.well-known/acme-challenge/${RAND_FILE} --write-out %{http_code} --silent --output /dev/null)" =~ ^(2|3)  ]]; then
    rm /var/www/acme/${RAND_FILE}
    return 0
  else
    rm /var/www/acme/${RAND_FILE}
    return 1
  fi
}
