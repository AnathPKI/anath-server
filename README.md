Anath Reference Implementation
===

BSc Thesis reference implementation of a self-service PKI.
 

Requirements
---

* Java 1.8
* PostgreSQL 9 or later
* Maven
* Redis (optional)
* Docker (optional)

Build Docker Image
---

    mvn clean verify
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