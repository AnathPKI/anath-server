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

package ch.zhaw.ba.anath.pki;

import ch.zhaw.ba.anath.pki.exceptions.CertificateConstraintException;
import ch.zhaw.ba.anath.pki.interfaces.CertificateConstraintProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Test if the Organization of the Subject matches the Issuer organization. Additionally, test if the Common Name is
 * set.
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
        final String subjectOrganizationName = subjectName.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();
        final String issuerOrganizationName = issuerName.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();

        if (!subjectOrganizationName.equals(issuerOrganizationName)) {
            throw new CertificateConstraintException(String.format("Subject's Organization '%s' does not match " +
                            "Issuer's Organization '%s'",
                    subjectOrganizationName, issuerOrganizationName));
        }
    }

    private void organizationSetOrThrow(X500Name subjectName) {
        if (subjectName.getRDNs(BCStyle.O).length != 1) {
            throw new CertificateConstraintException("Organization not set");
        }
    }
}
