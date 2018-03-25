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

import ch.zhaw.ba.anath.pki.core.exceptions.CertificateException;
import lombok.Value;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

/**
 * Abstraction of a {@link X509CertificateHolder}. It is a wrapper around
 * {@link X509CertificateHolder}
 *
 * @author Rafael Ostertag
 */
@Value
public class Certificate {
    private final X509CertificateHolder certificateHolder;

    public X500Name getSubject() {
        return certificateHolder.getSubject();
    }

    public Date getValidFrom() {
        return certificateHolder.getNotBefore();
    }

    public Date getValidTo() {
        return certificateHolder.getNotAfter();
    }

    public BigInteger getSerial() {
        return certificateHolder.getSerialNumber();
    }

    /**
     * Get the certificate as byte array.
     *
     * @return certificate as byte array.
     *
     * @throws CertificateException upon error
     */
    public byte[] getCertificate() {

        try {
            return certificateHolder.getEncoded();
        } catch (IOException e) {
            throw new CertificateException("Error getting certificate", e);
        }
    }
}
