/*
 * Copyright (c) 2018, Rafael Ostertag, Martin Wittwer
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

import ch.zhaw.ba.anath.pki.core.exceptions.PrivateKeyReaderException;
import ch.zhaw.ba.anath.pki.core.interfaces.PrivateKeyReader;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.Reader;
import java.security.PrivateKey;

/**
 * Read the PEM encoded private key from a file. The {@link PrivateKey} can be obtained by calling
 * {@link #privateKey()}.
 *
 * @author Rafael Ostertag
 */
public final class PEMPrivateKeyReader implements PrivateKeyReader {
    private final PrivateKey privateKey;

    /**
     * Read PEM encoded private key.
     *
     * @param keyReader {@link Reader} instance pointing to the private key file.
     */
    public PEMPrivateKeyReader(Reader keyReader) {
        final Object privateKeyObject = readPrivateKey(keyReader);
        final PrivateKeyInfo privateKeyInfo = getPrivateKeyInfoFromPrivateKeyObject
                (privateKeyObject);
        privateKey = getPrivateKeyFromPrivateKeyInfo(privateKeyInfo);
    }

    private PrivateKey getPrivateKeyFromPrivateKeyInfo(PrivateKeyInfo privateKeyInfo) {
        final JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
        try {
            return jcaPEMKeyConverter.getPrivateKey(privateKeyInfo);
        } catch (PEMException e) {
            throw new PrivateKeyReaderException("Cannot convert to PrivateKey: " + e.getMessage(), e);
        }
    }

    private PrivateKeyInfo getPrivateKeyInfoFromPrivateKeyObject(Object privateKeyObject) {
        if (privateKeyObject instanceof PrivateKeyInfo) {
            return (PrivateKeyInfo) privateKeyObject;
        }

        if (privateKeyObject instanceof PEMKeyPair) {
            final PEMKeyPair pemKeyPair = (PEMKeyPair) privateKeyObject;
            return pemKeyPair.getPrivateKeyInfo();
        }

        throw new PrivateKeyReaderException("Don't know how to handler private key of type: " + privateKeyObject
                .getClass()
                .getName());
    }

    private Object readPrivateKey(Reader privateKeyReader) {
        try (PEMParser pemParser = new PEMParser(privateKeyReader)) {
            return pemParser.readObject();
        } catch (Exception e) {
            throw new PrivateKeyReaderException("Error reading private key: " + e.getMessage(), e);
        }
    }

    @Override
    public PrivateKey privateKey() {
        return privateKey;
    }
}
