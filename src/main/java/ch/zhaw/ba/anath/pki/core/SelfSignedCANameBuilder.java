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

import ch.zhaw.ba.anath.pki.core.exceptions.CASubjectConstraintException;
import lombok.Builder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;

/**
 * A X.500 Name. Mainly used to create self-signed CA certificates.
 * <p>
 * The only required fields to be set are {@link #organization} and {@link #commonName}.
 *
 * @author Rafael Ostertag
 */
@Builder
public class SelfSignedCANameBuilder {
    private String country;
    private String organization;
    private String organizationalUnit;
    private String location;
    private String state;
    private String commonName;

    public X500Name toX500Name() {
        return getBcX500NameBuilder().build();
    }

    /**
     * Get the BouncyCastle {@link org.bouncycastle.asn1.x500.X500NameBuilder} having all the OID, supported by this
     * class, set.
     * <p>
     * This method requires at least {@link #commonName} and {@link #organization} to be set and non-empty.
     *
     * @return {@link org.bouncycastle.asn1.x500.X500NameBuilder} instance prefilled with OIDs from this instance.
     *
     * @throws ch.zhaw.ba.anath.pki.core.exceptions.CASubjectConstraintException when either {@link #commonName},
     *                                                                           {@link #organization}, or both are null
     *                                                                           or empty.
     */
    protected org.bouncycastle.asn1.x500.X500NameBuilder getBcX500NameBuilder() {
        throwWhenRequiredOIDsAreNotSet();

        org.bouncycastle.asn1.x500.X500NameBuilder bcX500NameBuilder = new org.bouncycastle
                .asn1.x500.X500NameBuilder();

        bcX500NameBuilder = whenSetAdd(bcX500NameBuilder, RFC4519Style.c, country);
        bcX500NameBuilder = whenSetAdd(bcX500NameBuilder, RFC4519Style.o, organization);
        bcX500NameBuilder = whenSetAdd(bcX500NameBuilder, RFC4519Style.ou, organizationalUnit);
        bcX500NameBuilder = whenSetAdd(bcX500NameBuilder, RFC4519Style.l, location);
        bcX500NameBuilder = whenSetAdd(bcX500NameBuilder, RFC4519Style.st, state);
        bcX500NameBuilder = whenSetAdd(bcX500NameBuilder, RFC4519Style.cn, commonName);

        return bcX500NameBuilder;
    }

    /**
     * Throw {@link CASubjectConstraintException} when values for required OIDs are {@code null} or empty.
     * <p>
     * This method tests the {@link #commonName} and {@link #organization} fields.
     *
     * @throws ch.zhaw.ba.anath.pki.core.exceptions.CASubjectConstraintException when either {@link #commonName},
     *                                                                           {@link #organization}, or both are null
     *                                                                           or empty.
     */
    protected void throwWhenRequiredOIDsAreNotSet() {
        if (organization == null || organization.isEmpty()) {
            throw new CASubjectConstraintException("Organization must not be null or empty");
        }

        if (commonName == null || commonName.isEmpty()) {
            throw new CASubjectConstraintException("Organization must not be null or empty");
        }
    }

    /**
     * Add the {@code value} as {@code oid} to the {@link org.bouncycastle.asn1.x500.X500NameBuilder}, only when
     * {@code value} is not {@code null} or empty.
     *
     * @param bcX500NameBuilder the {@link org.bouncycastle.asn1.x500.X500NameBuilder} instance
     * @param oid               {@link ASN1ObjectIdentifier} instance
     * @param value             string value to add
     *
     * @return the {@link org.bouncycastle.asn1.x500.X500NameBuilder} instance.
     */
    protected org.bouncycastle.asn1.x500.X500NameBuilder whenSetAdd(
            org.bouncycastle.asn1.x500.X500NameBuilder bcX500NameBuilder,
            ASN1ObjectIdentifier oid,
            String value) {
        if (value == null || value.isEmpty()) {
            return bcX500NameBuilder;
        }

        return bcX500NameBuilder.addRDN(oid, value);
    }
}
