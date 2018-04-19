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

import ch.zhaw.ba.anath.pki.core.exceptions.CertificateConstraintException;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateConstraintProvider;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Test if the Organization of the Subject matches the Issuer organization. Additionally, test if the Common Name is
 * set.
 *
 * Multi value RDN is supported on the subject.
 *
 * @author Rafael Ostertag
 */
public class OrganizationCertificateConstraint implements CertificateConstraintProvider {
    @Override
    public void validateSubject(X500Name subjectName, X500Name issuerName) {
        organizationSetOrThrow(subjectName);
        doOrganizationsMatchOrThrow(subjectName, issuerName);
    }

    private void doOrganizationsMatchOrThrow(X500Name subjectName, X500Name issuerName) {
        final String issuerOrganizationName = issuerName.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();
        matchesOidValueInRdnOrThrow(
                subjectName,
                BCStyle.O,
                issuerOrganizationName,
                String.format("Subject's Organization does not match Issuer's Organization '%s'",
                        issuerOrganizationName));
    }

    private void organizationSetOrThrow(X500Name subjectName) {
        existsOidInRdnOrThrow(subjectName, BCStyle.O, "Organization not set");
    }

    /**
     * Test if a given OID exists in a X500 name. If the OID does not exist, throw a
     * {@link CertificateConstraintException} with a provided message.
     *
     * @param x500Name         the test subject
     * @param oid              {@link ASN1ObjectIdentifier} to test
     * @param exceptionMessage message of {@link CertificateConstraintException} if the OID is not found in the test
     *                         subject.
     */
    protected void existsOidInRdnOrThrow(X500Name x500Name, ASN1ObjectIdentifier oid, String exceptionMessage) {
        if (x500Name.getRDNs(oid).length == 0) {
            throw new CertificateConstraintException(exceptionMessage);
        }
    }

    /**
     * Test if a given value matches the value of the provided OID in a X500 name. If the value of the OID does not
     * match, throw a {@link CertificateConstraintException} with the provided message.
     * <p>
     * This method has limited support for multivalu
     *
     * @param x500Name         the test subject.
     * @param oid              {@link ASN1ObjectIdentifier} to match against the value
     * @param expectedValue    expected value of the OID
     * @param exceptionMessage message of {@link CertificateConstraintException} if the OID value does not match.
     */
    protected void matchesOidValueInRdnOrThrow(X500Name x500Name, ASN1ObjectIdentifier oid, String expectedValue, String
            exceptionMessage) {
        final RDN[] rdnsHavingOid = x500Name.getRDNs(oid);
        if (rdnsHavingOid.length == 0) {
            throw new CertificateConstraintException(exceptionMessage);
        }

        for (RDN rdn : rdnsHavingOid) {
            for (AttributeTypeAndValue attributeTypeAndValue : rdn.getTypesAndValues()) {
                if (attributeTypeAndValue.getType().equals(oid) &&
                        !attributeTypeAndValue.getValue().toString().equals(expectedValue)) {
                    throw new CertificateConstraintException(exceptionMessage);
                }
            }
        }
    }
}
