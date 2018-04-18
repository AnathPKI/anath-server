FROM openjdk:8-jre-alpine

WORKDIR /
RUN adduser -h /application \
	    -g "Application user" \
	    -D \
	    app

ADD docker/docker-entrypoint.sh .

WORKDIR application
COPY target/*.jar application.jar

USER app

EXPOSE 8080
EXPOSE 8443

ENTRYPOINT ["/docker-entrypoint.sh"]