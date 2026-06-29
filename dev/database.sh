#!/bin/bash
identifier="#Koii's managed hosts"
hosts="127.0.0.1 koiiMongoPrimary koiiMongo2 koiiMongo3"
networks=$(podman network ls)

if [[ "$networks" != *"koiiMongodbCluster"* ]]; then
  podman network create koiiMongodbCluster
fi

if [[ "$1" == "remove" ]]; then
  sudo sed -i "\#^${hosts}\$#d" "/etc/hosts"
  sudo -k
  podman exec -it koiiMongo2 mongosh --eval 'db.shutdownServer({ force: true })'
  podman exec -it koiiMongo3 mongosh --eval 'db.shutdownServer({ force: true })'
  podman exec -it koiiMongoPrimary mongosh --eval 'db.shutdownServer({ force: true })'
  podman rm -f koiiMongoPrimary
  podman rm -f koiiMongo2
  podman rm -f koiiMongo3
  podman rm -f koiiDragonfly
  exit 0
fi

if [[ "$1" == "down" ]]; then
  sudo sed -i "\#^${hosts}\$#d" "/etc/hosts"
  sudo -k
  podman exec -it koiiMongoPrimary mongosh --eval 'db.shutdownServer({ force: true })'
  podman exec -it koiiMongo2 mongosh --eval 'db.shutdownServer({ force: true })'
  podman exec -it koiiMongo3 mongosh --eval 'db.shutdownServer({ force: true })'
  podman stop koiiMongoPrimary
  podman stop koiiMongo2
  podman stop koiiMongo3
  podman stop koiiDragonfly
  exit 0
fi

sudo sed -i "\#^${hosts}\$#d" "/etc/hosts"
sudo -k

podman run -d -p 27017:27017 --name koiiMongoPrimary --network koiiMongodbCluster mongo:8.0.4 mongod --replSet koiiReplicaSet --bind_ip localhost,koiiMongoPrimary
podman run -d -p 27018:27017 --name koiiMongo2 --network koiiMongodbCluster mongo:8.0.4 mongod --replSet koiiReplicaSet --bind_ip localhost,koiiMongo2
podman run -d -p 27019:27017 --name koiiMongo3 --network koiiMongodbCluster mongo:8.0.4 mongod --replSet koiiReplicaSet --bind_ip localhost,koiiMongo3
podman run -d -p 6379:6379 --name koiiDragonfly --ulimit memlock=-1 docker.dragonflydb.io/dragonflydb/dragonfly

podman start koiiMongoPrimary
podman start koiiMongo2
podman start koiiMongo3
podman start koiiDragonfly

sleep 1

podman exec -it koiiMongoPrimary mongosh --eval "rs.initiate({
  _id: \"koiiReplicaSet\",
  members: [
    {_id: 0, host: \"koiiMongoPrimary\"},
    {_id: 1, host: \"koiiMongo2\"},
    {_id: 2, host: \"koiiMongo3\"}
  ]
})"

sleep 1

podman exec -it koiiMongo2 mongosh --eval "rs.status()"

if grep -qF "$hosts" "/etc/hosts"; then
  echo "Skipping hosts write."
elif grep -qF "$identifier" "/etc/hosts"; then
  sudo sed -i "/^${identifier}$/a ${hosts}" "/etc/hosts"
else
  echo "$identifier" | sudo tee -a /etc/hosts
  echo "$hosts" | sudo tee -a /etc/hosts
fi
