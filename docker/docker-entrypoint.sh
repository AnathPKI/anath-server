#!/bin/sh
# The script expects the jar to be placed in /application/application.jar and
#
#
# Arguments passed to this script will be relayed as arguments to java.

set -eu

JAVA=java
JAVA_OPTS=${JAVA_OPTS:-}
JAR="-jar application.jar"


exec ${JAVA} ${JAVA_OPTS} ${JAR}
