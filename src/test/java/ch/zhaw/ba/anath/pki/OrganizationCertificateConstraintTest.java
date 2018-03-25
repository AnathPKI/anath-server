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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Rafael Ostertag
 */
public class OrganizationCertificateConstraintTest {
    private X500Name name1;
    private X500Name name2;

    @Before
    public void setUp() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        name1 = x500NameBuilder
                .addRDN(BCStyle.C, "CH")
                .addRDN(BCStyle.ST, "Thurgau")
                .addRDN(BCStyle.L, "Kefikon")
                .addRDN(BCStyle.O, "Rafael Ostertag")
                .addRDN(BCStyle.OU, "dev")
                .addRDN(BCStyle.CN, "Rafael Ostertag")
                .addRDN(BCStyle.E, "rafi@guengel.ch")
                .build();
        x500NameBuilder = new X500NameBuilder();
        name2 = x500NameBuilder
                .addRDN(BCStyle.C, "CH")
                .addRDN(BCStyle.ST, "Thurgau")
                .addRDN(BCStyle.L, "Kefikon")
                .addRDN(BCStyle.O, "Rafael Ostertag")
                .addRDN(BCStyle.OU, "dev")
                .addRDN(BCStyle.CN, "Rafael Ostertag")
                .addRDN(BCStyle.E, "rafi@guengel.ch")
                .build();
    }

    @Test
    public void validateSubject() {
        new OrganizationCertificateConstraint().validateSubject(name1, name2);
    }

    @Test(expected = CertificateConstraintException.class)
    public void validateNonMatchingSubjects() {
        final X500NameBuilder x500NameBuilder = new X500NameBuilder();
        final X500Name nonMatchingName = x500NameBuilder
                .addRDN(BCStyle.C, "CH")
                .addRDN(BCStyle.ST, "Thurgau")
                .addRDN(BCStyle.L, "Kefikon")
                .addRDN(BCStyle.O, "Rafi")
                .addRDN(BCStyle.OU, "dev")
                .addRDN(BCStyle.CN, "Rafael Ostertag")
                .addRDN(BCStyle.E, "rafi@guengel.ch")
                .build();
        new OrganizationCertificateConstraint().validateSubject(nonMatchingName, name1);
    }

    @Test(expected = CertificateConstraintException.class)
    public void validateIssuerWithoutOrganization() {
        final X500NameBuilder x500NameBuilder = new X500NameBuilder();
        final X500Name nonMatchingName = x500NameBuilder
                .addRDN(BCStyle.C, "CH")
                .addRDN(BCStyle.ST, "Thurgau")
                .addRDN(BCStyle.L, "Kefikon")
                .addRDN(BCStyle.OU, "dev")
                .addRDN(BCStyle.CN, "Rafael Ostertag")
                .addRDN(BCStyle.E, "rafi@guengel.ch")
                .build();
        new OrganizationCertificateConstraint().validateSubject(nonMatchingName, name1);
    }
}