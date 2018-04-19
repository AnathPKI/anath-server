To Do
===

* RFC 5280 states, that the application/pkix-cert and application/pkix-crl must be DER encoded. RFC 2585 allows for BASE64 encoding when transferred over 7bit transports. We currently return PEM encoded CRL and CA Certs. Make sure we don't violate RFC 5280