#!/bin/bash
set -e
IDENTIFIER="# Koii's managed hosts"
HOSTS_ENTRY="127.0.0.1 koiiMongoPrimary koiiMongo2 koiiMongo3"
MONGO_NODES=(koiiMongoPrimary koiiMongo2 koiiMongo3)
NETWORK="koiiMongodbCluster"
COMPOSE_FILE="$(dirname "$0")/compose.yaml"

remove_hosts_entry() {
  echo Removing mongo hosts from /etc/hosts:
  sudo sed -i "\#^${HOSTS_ENTRY}\$#d" /etc/hosts
  sudo -k
}

add_hosts_entry() {
  echo Adding mongo hosts to /etc/hosts:
  if grep -qF "$HOSTS_ENTRY" /etc/hosts; then
    echo "Skipping hosts write."
  elif grep -qF "$IDENTIFIER" /etc/hosts; then
    sudo sed -i "/^${IDENTIFIER}$/a ${HOSTS_ENTRY}" /etc/hosts
    sudo -k
  else
    printf '%s\n%s\n' "$IDENTIFIER" "$HOSTS_ENTRY" | sudo tee -a /etc/hosts > /dev/null
    sudo -k
  fi
}

case "$1" in
  remove)
    remove_hosts_entry
    podman-compose -f "$COMPOSE_FILE" down
    exit 0
    ;;
  stop)
    remove_hosts_entry
    podman-compose -f "$COMPOSE_FILE" stop
    exit 0
    ;;
  start)
    remove_hosts_entry
    podman-compose -f "$COMPOSE_FILE" start
    sleep 5
    podman exec -it koiiMongo2 mongosh --eval "rs.status()"
    add_hosts_entry
    exit 0
    ;;
  init)
    remove_hosts_entry
    podman network ls | grep -q "$NETWORK" || podman network create "$NETWORK"
    podman-compose -f "$COMPOSE_FILE" up -d
    sleep 1
    podman exec -it koiiMongoPrimary mongosh --eval "rs.initiate({
      _id: 'koiiReplicaSet',
      members: [
        {_id: 0, host: 'koiiMongoPrimary'},
        {_id: 1, host: 'koiiMongo2'},
        {_id: 2, host: 'koiiMongo3'}
      ]
    })"
    sleep 5
    podman exec -it koiiMongo2 mongosh --eval "rs.status()"
    add_hosts_entry
    exit 0
    ;;
esac

echo Options:
echo "   up: Create containers."
echo "   down: Remove containers."
echo "   start: Start containers."
echo "   stop: Stop containers."
echo
echo Example: "$0" init
