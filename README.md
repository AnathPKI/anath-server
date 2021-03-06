[![Build
Status](https://travis-ci.org/AnathPKI/anath-server.svg?branch=master)](https://travis-ci.org/AnathPKI/anath-server)
[![Quality
Gate](https://sonarcloud.io/api/project_badges/measure?project=ch.zhaw.ba%3Aanath-server&metric=alert_status)](https://sonarcloud.io/dashboard?id=ch.zhaw.ba%3Aanath-server)
[![Latest Release](https://github-basic-badges.herokuapp.com/release/AnathPKI/anath-server.svg)](https://github.com/AnathPKI/anath-server/releases/latest)

Bsc Thesis Reference Implementation
===

Anath is the BSc Thesis reference implementation of a self-service
PKI.

Anath features:

* Import of Root CA
* Creation of self-signed CA certificate
* User management
* Configuration templates
* Certificate creation and revocation
 

Images
---

JAR files can be found on the [GitHub
Releases](https://github.com/AnathPKI/anath-server/releases)
page. Alternatively, the [Demo
repository](https://github.com/AnathPKI/demo) provides Docker Compose
files to run Docker images.


Requirements
---

* Java 1.8
* PostgreSQL 9 or later
* Maven (build)
* Redis (optional)
* Docker (optional)


Build Docker Image
---

When docker is installed and running, a docker image can be built locally:

    mvn clean package
    docker build -t anathpki/server:test .

Start Server in Staging Mode Without Redis
---

This mode will sign certificates _without_ confirmation.

Staging mode expects a running PostgreSQL instance listening on `localhost:5432` with two empty databases `anath` and 
`anathusers`, and a user `anath` with password `anath` having full access to both databases.

1. Checkout sources
1. Run

       mvn -Dspring.profiles.active=staging spring-boot:run
       
Start Server in Staging Mode With Redis
---

This mode will sign certificates _with_ confirmation.

Staging mode expects a running PostgreSQL instance listening on `localhost:5432` with two empty databases `anath` and 
`anathusers`, and a user `anath` with password `anath` having full access to both databases.

This mode also expects a local Redis instance to be running listening on `localhost:6379`.

1. Checkout sources
1. Run

       mvn -Dspring.profiles.active=staging,confirm spring-boot:run
