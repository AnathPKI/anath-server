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

package ch.zhaw.ba.anath.pki.core;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;

import java.math.BigInteger;

/**
 * @author Rafael Ostertag
 */
public final class TestConstants {
    public static final String PKCS12_ENCRYPTED_FILE_NAME = "src/test/resources/ca_encrypted.pkcs12";
    public static final String PKCS12_ENCRYPTED_EMPTY_PASSWORD_FILE_NAME =
            "src/test/resources/ca_encrypted_empty_password.pkcs12";
    public static final String CA_KEY_FILE_NAME = "src/test/resources/cakey.pem";
    public static final String CA_CERT_FILE_NAME = "src/test/resources/cacert.pem";
    public static final String CLIENT_CSR_FILE_NAME = "src/test/resources/client.csr";
    public static final String CLIENT_CSR_NON_MATCHING_ORG_FILE_NAME = "src/test/resources/client_non_matching_org.csr";

    // The content of cacert.pem with a random line removed
    public static final String INVALID_CA_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIID/jCCAuagAwIBAgIJAPQj6jMYDszkMA0GCSqGSIb3DQEBCwUAMIGTMQswCQYD\n" +
            "VQQGEwJDSDEQMA4GA1UECAwHVGh1cmdhdTEQMA4GA1UEBwwHS2VmaWtvbjEYMBYG\n" +
            "A1UECgwPUmFmYWVsIE9zdGVydGFnMQwwCgYDVQQLDANkZXYxGDAWBgNVBAMMD1Jh\n" +
            "ZmFlbCBPc3RlcnRhZzEeMBwGCSqGSIb3DQEJARYPcmFmaUBndWVuZ2VsLmNoMB4X\n" +
            "DTE4MDIyNDE4NDQ1N1oXDTE5MDIyNDE4NDQ1N1owgZMxCzAJBgNVBAYTAkNIMRAw\n" +
            "DgYDVQQIDAdUaHVyZ2F1MRAwDgYDVQQHDAdLZWZpa29uMRgwFgYDVQQKDA9SYWZh\n" +
            "ZWwgT3N0ZXJ0YWcxDDAKBgNVBAsMA2RldjEYMBYGA1UEAwwPUmFmYWVsIE9zdGVy\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQDe9/4o6/YCQ7h3uuepDzJOGu7YmSFjJJ8hE6BH\n" +
            "SckqaNLaqHkSvKmTzPt+CG2ZDaHeH6WhCfUWf8VL8gwt4QCEAjsM8Zs82+BT1HRg\n" +
            "tkaCaBeugLVWreG34clHcBnJgzoCRHFS92WXm16EmLU3ZVCy5ySgrDF0yNfPPWkr\n" +
            "hDFEtqIZ11t2pLNcdUsVnmP+68FEEo0B5zriUcbXUzE9NZLOzyaTWyWr/iipmBxv\n" +
            "D9BSQVx1NP3q3SBkDvNQIagjTxJtSg3ZYm2uzxUkOfSNsIC4yk35ySUL7470WCkF\n" +
            "MQQW4ZCE+KmvlmE+FfD7XIAVOYb7k2uPmO44AclQGjdxMNfZAgMBAAGjUzBRMB0G\n" +
            "A1UdDgQWBBQnZHOL8Uz4l8XpNZ0x/n2QJpTYyzAfBgNVHSMEGDAWgBQnZHOL8Uz4\n" +
            "l8XpNZ0x/n2QJpTYyzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IB\n" +
            "AQCrNT5IwcDNWkdkvnGZzDIPqNvd5Sr/WQeRRCUJ8tM1wYRP+/beilekmaWl3mAl\n" +
            "0x5zGwUxBSgGv45q6j9FJu9rbwgk2x8/rVWycUCdGQJDzciGKUycE9bA4W8nV9dE\n" +
            "89nXXIo6aB2CC6+jiILTEHIiLoSIUeJTECe1tGh+fW4K7zdbVvmgxwEmP5oGwy13\n" +
            "uKpMYjUOaKZGgIjlN5+q+YCZIcwnC+iNma3/re3iNPyyRz5eX5/8h07R7EhL4bvr\n" +
            "ZDg7YsEg4AwLsuuIEz1W3ff+OQu6O4/Qe1PTc+/TDJgKd8wq5Nc1oOIMI6J8Ij21\n" +
            "3Pdg9DnfsOnW5/jb/3/ix9zA\n" +
            "-----END CERTIFICATE-----";

    // The content of cakey.pem with a random line removed
    public static final String INVALID_CA_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDe9/4o6/YCQ7h3\n" +
            "uuepDzJOGu7YmSFjJJ8hE6BHSckqaNLaqHkSvKmTzPt+CG2ZDaHeH6WhCfUWf8VL\n" +
            "8gwt4QCEAjsM8Zs82+BT1HRgtkaCaBeugLVWreG34clHcBnJgzoCRHFS92WXm16E\n" +
            "mLU3ZVCy5ySgrDF0yNfPPWkrhDFEtqIZ11t2pLNcdUsVnmP+68FEEo0B5zriUcbX\n" +
            "UzE9NZLOzyaTWyWr/iipmBxvD9BSQVx1NP3q3SBkDvNQIagjTxJtSg3ZYm2uzxUk\n" +
            "OfSNsIC4yk35ySUL7470WCkFMQQW4ZCE+KmvlmE+FfD7XIAVOYb7k2uPmO44AclQ\n" +
            "GjdxMNfZAgMBAAECggEACGx+IbWoebVtRri8/9ofIGxMEcrXRBOiH3HKYGcdPojv\n" +
            "TmuHB3oxPfBEoCJZYaruLqIrc8YYiF0Taycd5q3VgydCa97E6quz8fbY3r6EM3ET\n" +
            "U/hw4XF4UaYqIJTPpJlcm7FSRrwqDmxESeYrEoi1X8zzyU44IB1maeH8EzTPV7Us\n" +
            "hy/XZ+f+mDUnmJC9h0hcuD3qqM37CnzrcC/LvXCXhDmaAYEBlVbXQ6S8HyF0Op2z\n" +
            "umq9UHyxuZWB3qEC3ln5aM0bqFpSpgowbaeNFL9a8QKBgQD/pl4+nd9lJ3oncjwx\n" +
            "p4oN4yiOMfp8cFZXarwTX3JGBc2qLTLz3LQ+NR6zERx3jdIDLyPXygmib0P4bWX9\n" +
            "G0PIPvYPWB8fSHTSyE3YlNRkkSWhHJvAdmpmqL99NgVvyp5R5boBCcdvZhgzBW9V\n" +
            "xlF7HQ3+oa4TcWPs+DwErhId7wKBgQDfRiqhiGl1pAD4yjd/xjJy87s6qEiRLYzG\n" +
            "L+tlJ+GE+70JpmO7aHuCKfEoyIaz9pT4eZ8mJ4FYtsiE1x5LfosVLngWn80Khp14\n" +
            "1gE1fFdBSq5eyqs2b22FgVxQbJPdfhrizBGbfk+/+s96iNwN1nhoONUydwSZZO1s\n" +
            "sgdFwWuutwKBgHW/Qb8jZaYodZm/grv4B5z32FEN8enor8vZjEB8AJ0BxUUxRjuN\n" +
            "lrLkMnyVUAA8oNL4nlCgbKmVB8BfWs8mBKUxYpGUq9jzvWLsAPbVLbIYLDW1gIM3\n" +
            "xy/7Xx8jh4OC1kKwRWh/AY1sf47YXPwruJG0wyJZg1zPKBAYEUSyjAOfAoGBAMHk\n" +
            "vEbVIMhBqXpkmbfDlbIQCWsSExrIVLUTjjelX4pN10dXEMsCHCfYZo5FPf1wyMPT\n" +
            "UqseqYwyB4adDbj/5qZ5WV5EXhqi9oOmTRx2o4uW4EB/fhniwFitE07gS7SQu6Zz\n" +
            "E2NWWMledOlziq4VrzDLEhImG39ej3TSUdB4/RuXAoGAOnfEOetnL01ZiObA19kt\n" +
            "J4jRlu1hjapxsdph1pOJfOlkOIo7iNqTlbUAWiAcGOzmaA9nhaWyw6v3fVx7gTwo\n" +
            "XJldBre0qE+25GKQD5gQRLk44jq2d8DlkJfsNQL5S9veSst8tab84RlwInlZ9asX\n" +
            "1F/PgrpGOgiDauXLaXTtLmQ=\n" +
            "-----END PRIVATE KEY-----\n";
    public static final X500Name CA_CERT_X500_NAME = new X500NameBuilder()
            .addRDN(RFC4519Style.c, "CH")
            .addRDN(RFC4519Style.o, "Rafael Ostertag")
            .addRDN(RFC4519Style.cn, "Rafael Ostertag")
            .addRDN(RFC4519Style.l, "Kefikon")
            .addRDN(RFC4519Style.st, "Thurgau")
            .addRDN(RFC4519Style.ou, "dev")
            .addRDN(BCStyle.E, "rafi@guengel.ch")
            .build();

    public static final BigInteger CA_CERT_SERIAL = new BigInteger("17592162074607144164");

    private TestConstants() {
        // intentionally empty
    }
}
