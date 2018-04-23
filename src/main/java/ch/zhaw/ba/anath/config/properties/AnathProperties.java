/*
 * Copyright (c) 2018, Rafael Ostertag
 * All rights reserved.
 *
 * Redistribution and  use in  source and binary  forms, with  or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.  Redistributions of  source code  must retain  the above  copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in  binary form must reproduce  the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation   and/or   other    materials   provided   with   the
 *    distribution.
 *
 * THIS SOFTWARE  IS PROVIDED BY  THE COPYRIGHT HOLDERS  AND CONTRIBUTORS
 * "AS  IS" AND  ANY EXPRESS  OR IMPLIED  WARRANTIES, INCLUDING,  BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES  OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE  ARE DISCLAIMED. IN NO EVENT  SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL,  EXEMPLARY,  OR  CONSEQUENTIAL DAMAGES  (INCLUDING,  BUT  NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE  GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS  INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF  LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY,  OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN  ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package ch.zhaw.ba.anath.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author Rafael Ostertag
 */
@Component
@ConfigurationProperties(AnathProperties.CONFIGURATION_PREFIX)
@Data
public class AnathProperties {
    public static final String CONFIGURATION_PREFIX = "ch.zhaw.ba.anath";

    /**
     * The secret key used to encrypt data in the {@link ch.zhaw.ba.anath.pki.services.SecureStoreService}.
     */
    private String secretKey;
    /**
     * Validity of certificates in days.
     */
    private int certificateValidity = 180;
    /**
     * Validity of CRL in days
     */
    private int crlValidity = 30;
    private Authentication authentication = new Authentication();
    private Confirmation confirmation = new Confirmation();

    @Data
    public static class Authentication {
        private JWT jwt = new JWT();
        private Argon2 argon2 = new Argon2();

        @Data
        public static class JWT {
            /**
             * The JWT Secret.
             */
            private String secret;
            /**
             * Expiration time in minutes.
             */
            private int expirationTime = 60;
        }

        /**
         * Configuration taken from https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet (April 2018)
         *
         * <pre>
         *     Configuration to define Argon2 options
         *     See https://github.com/P-H-C/phc-winner-argon2#command-line-utility
         *     See https://github.com/phxql/argon2-jvm/blob/master/src/main/java/de/mkammerer/argon2/Argon2.java
         *     See https://github.com/P-H-C/phc-winner-argon2/issues/59
         * </pre>
         */
        @Data
        public static class Argon2 {

            /**
             * Configuration taken from https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet (April 2018)
             *
             * <pre>
             *     Number of iterations, here adapted to take at least 2 seconds
             *     Tested on the following environments:
             *       ENV NUMBER 1: LAPTOP - 15 Iterations is enough to reach 2 seconds processing time
             *           CPU: Intel Core i7-2670QM 2.20 GHz with 8 logical processors and 4 cores
             *           RAM: 24GB but no customization on JVM (Java8 32 bits)
             *           OS: Windows 10 Pro 64 bits
             *       ENV NUMBER 2: TRAVIS CI LINUX VM - 15 Iterations is NOT enough to reach 2 seconds processing
             *       time (processing time take 1 second)
             *           See details on https://docs.travis-ci
             *           .com/user/reference/overview/#Virtualisation-Environment-vs-Operating-System
             *           "Ubuntu Precise" and "Ubuntu Trusty" using infrastructure "Virtual machine on GCE" were used
             *           (GCE = Google Compute Engine)
             * </pre>
             */
            private int iterations = 40;
            /**
             * Configuration taken from https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet (April 2018)
             *
             * <pre>
             *     The memory usage of 2^N KiB, here set to recommended value from Issue n°9 of PHC project (128 MB)
             *     (April 2018)
             * </pre>
             */
            private int memory = 128000;
            /**
             * Configuration taken from https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet (April 2018)
             *
             * <pre>
             *     Parallelism to N threads here set to recommended value from Issue n°9 of PHC project
             * </pre>
             */
            private int parallelism = 4;
        }
    }

    @Data
    public static class Confirmation {
        /**
         * Token validity in minutes
         */
        private int tokenValidity = 60;
        private String mailServer = "localhost";
        private int mailPort = 25;
        private String sender = "anath@localhost.localdomain";
    }
}
