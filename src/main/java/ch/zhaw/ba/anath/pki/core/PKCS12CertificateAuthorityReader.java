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

import ch.zhaw.ba.anath.pki.core.exceptions.CertificateAuthorityReaderException;
import ch.zhaw.ba.anath.pki.core.exceptions.PKIException;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateAuthorityReader;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Read a Certificate from a PKCS#12 structure.
 *
 * @author Rafael Ostertag
 */
public final class PKCS12CertificateAuthorityReader implements CertificateAuthorityReader {
    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private CertificateAuthority certificateAuthority;

    public PKCS12CertificateAuthorityReader(InputStream pkcs12CertificateAuthorityStream, String password) {
        readCertificateAuthority(pkcs12CertificateAuthorityStream, password);
    }

    private void readCertificateAuthority(InputStream pkcs12CertificateAuthorityReader, String password) {
        try {
            final ByteArrayInputStream byteArrayInputStream = readContent(pkcs12CertificateAuthorityReader);
            final KeyStore keyStore = readFromInputStream(byteArrayInputStream, password.toCharArray());
            extractCertificateAuthority(keyStore, password.toCharArray());
        } catch (PKIException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateAuthorityReaderException("Cannot read PKCS#12 stream: " + e.getMessage(), e);
        }
    }

    private void extractCertificateAuthority(KeyStore keyStore, char[] password) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateEncodingException {
        final String alias = getFirstAliasOrThrow(keyStore);
        final Certificate certificate = getCertificateOrThrow(keyStore, alias);
        final X509CertificateHolder x509CertificateHolder = certificateToX509CertificateHolder(certificate, alias);
        final Key key = getKeyOrThrow(keyStore, password, alias);
        final PrivateKey privateKey = keyToPrivateKeyOrThrow(key, alias);

        this.certificateAuthority = new CertificateAuthority(privateKey, new ch.zhaw.ba.anath.pki.core.Certificate
                (x509CertificateHolder));
    }

    private X509CertificateHolder certificateToX509CertificateHolder(Certificate certificate, String alias) throws
            CertificateEncodingException {
        if (!(certificate instanceof X509Certificate)) {
            throw new CertificateAuthorityReaderException(String.format("The certificate for the alias '%s' is not a " +
                    "X.509 certificate", alias));
        }

        final X509Certificate x509Certificate = (X509Certificate) certificate;
        return new JcaX509CertificateHolder(x509Certificate);
    }

    private String getFirstAliasOrThrow(KeyStore keyStore) throws KeyStoreException {
        final Enumeration<String> aliases = keyStore.aliases();
        if (!aliases.hasMoreElements()) {
            throw new CertificateAuthorityReaderException("No aliases in PKCS#12 archive");
        }

        return aliases.nextElement();
    }

    private Certificate getCertificateOrThrow(KeyStore keyStore, String alias) throws KeyStoreException {
        final Certificate certificate = keyStore.getCertificate(alias);
        if (certificate == null) {
            throw new CertificateAuthorityReaderException(String.format("Alias '%s' does not have a certificate " +
                            "associated",
                    alias));
        }
        return certificate;
    }

    private PrivateKey keyToPrivateKeyOrThrow(Key key, String alias) {
        if (!(key instanceof PrivateKey)) {
            throw new CertificateAuthorityReaderException(String.format("Key for alias '%s' is not a private key",
                    alias));
        }

        return (PrivateKey) key;
    }

    private Key getKeyOrThrow(KeyStore keyStore, char[] password, String alias) throws KeyStoreException,
            NoSuchAlgorithmException {
        final Key key;
        try {
            key = keyStore.getKey(alias, password);
        } catch (UnrecoverableKeyException e) {
            throw new CertificateAuthorityReaderException("Invalid password for key");
        }
        if (key == null) {
            throw new CertificateAuthorityReaderException(String.format("No key for alias '%s' found", alias));
        }
        return key;
    }

    private KeyStore readFromInputStream(InputStream inputStream, char[] password) throws NoSuchProviderException,
            KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", "BC");
        pkcs12Store.load(inputStream, password);

        return pkcs12Store;
    }

    private ByteArrayInputStream readContent(InputStream pkcs12CertificateAuthorityReader) throws IOException {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        try (InputStream inputStream = new BufferedInputStream(pkcs12CertificateAuthorityReader)) {
            int b;
            while ((b = inputStream.read()) != -1) {
                byteArrayOutputStream.write(b);
            }
        }

        return new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
    }

    @Override
    public CertificateAuthority certificateAuthority() {
        return certificateAuthority;
    }
}
