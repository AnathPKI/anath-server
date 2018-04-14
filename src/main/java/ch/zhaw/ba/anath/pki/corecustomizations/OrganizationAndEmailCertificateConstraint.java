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

package ch.zhaw.ba.anath.pki.corecustomizations;

import ch.zhaw.ba.anath.authentication.AnathSecurityHelper;
import ch.zhaw.ba.anath.pki.core.OrganizationCertificateConstraint;
import ch.zhaw.ba.anath.pki.core.exceptions.CertificateConstraintException;
import ch.zhaw.ba.anath.users.dto.UserDto;
import ch.zhaw.ba.anath.users.services.UserService;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Validate the Certificate Signing Request like {@link OrganizationCertificateConstraint}.
 * In addition, it validates the emailAddress and CN RDN part using the currently logged in user. If the emailAddress
 * or CN does not match or is missing, it throws a {@link CertificateConstraintException}.
 * <p>
 * The email address is assumed to be the user name of the currently logged in user in the Spring Security
 * {@link SecurityContextHolder}.
 *
 * @author Rafael Ostertag
 */
public class OrganizationAndEmailCertificateConstraint extends OrganizationCertificateConstraint {
    private final UserService userService;

    public OrganizationAndEmailCertificateConstraint(UserService userService) {
        this.userService = userService;
    }

    @Override
    public void validateSubject(X500Name subjectName, X500Name issuerName) {
        super.validateSubject(subjectName, issuerName);

        emailSetOrThrow(subjectName);
        doEmailsMatchOrThrow(subjectName);

        cnSetOrThrow(subjectName);
        doesCnMatchOrThrow(subjectName);
    }

    private void doesCnMatchOrThrow(X500Name subjectName) {
        final UserDto user = userService.getUser(AnathSecurityHelper.getUsername());

        final String commonName = subjectName.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();

        final String expectedCommonName = user.getFirstname() + " " + user.getLastname();
        if (!commonName.equals(expectedCommonName)) {
            throw new CertificateConstraintException("CN in CSR and last- and firstname of currently logged in user " +
                    "do not match");
        }
    }

    private void doEmailsMatchOrThrow(X500Name subjectName) {
        final String subjectEmail = subjectName.getRDNs(BCStyle.E)[0].getFirst().getValue().toString();

        final String name = AnathSecurityHelper.getUsername();

        if (!name.equals(subjectEmail)) {
            throw new CertificateConstraintException("emailAddress in CSR and email of currently logged in user do " +
                    "not match");
        }
    }

    private void emailSetOrThrow(X500Name subjectName) {
        fieldPresentOrThrow(subjectName, BCStyle.E, "emailAddress not set");
    }

    private void cnSetOrThrow(X500Name subjectName) {
        fieldPresentOrThrow(subjectName, BCStyle.CN, "CN not set");
    }

    private void fieldPresentOrThrow(X500Name subjectName, ASN1ObjectIdentifier asn1ObjectIdentifier, String
            errorMessage) {
        if (subjectName.getRDNs(asn1ObjectIdentifier).length != 1) {
            throw new CertificateConstraintException(errorMessage);
        }
    }
}
