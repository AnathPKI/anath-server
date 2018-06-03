1.1.0
===

* Prefix of Spring properties is `anath` instead of `ch.zhaw.ba.anath`.
* Use Spring Boot 1.5.13.RELEASE.

1.0.6
===

* Send correct `Content-Type` when clients retrieve PEM encoded certificates and CRL.
* Send `Content-Disposition` header when  clients retrieve PEM encoded certificates and CRL.

1.0.5
===

* Use proper Ant path matcher for `/public` allowing to retrieve all files and subdirectories.

1.0.4
===

* Make initial admin creation stand out in log.

1.0.3
===

* Changed the default sender address to `anath@localhost.localdomain` for confirmation mails.
* Respect `spring.redis.*` properties.
* Respect `ch.zhaw.ba.anath.confirmation.mail-port` property.

1.0.2
===

* Use Spring Boot 1.5.12.RELEASE.

1.0.1
===

* Allow unauthenticated access to `/public/**`.

1.0.0
===

* Initial release.