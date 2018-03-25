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

import ch.zhaw.ba.anath.pki.exceptions.CASubjectConstraintException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author Rafael Ostertag
 */
public class SelfSignedCANameBuilderTest {
    @Test(expected = CASubjectConstraintException.class)
    public void testRequiredFieldsNoFieldsFilled() {
        SelfSignedCANameBuilder.builder().build().toX500Name();
    }

    @Test(expected = CASubjectConstraintException.class)
    public void testOnlyOFieldSet() {

        SelfSignedCANameBuilder.builder().organization("o").build().toX500Name();
    }

    @Test(expected = CASubjectConstraintException.class)
    public void testOnlyCNFieldSet() {
        SelfSignedCANameBuilder.builder().commonName("cn").build().toX500Name();
    }

    @Test
    public void allRequiredFieldsSet() {
        final X500Name x500Name = SelfSignedCANameBuilder
                .builder()
                .organization("o")
                .commonName("cn")
                .build()
                .toX500Name();

        final X500Name expected = new X500NameBuilder()
                .addRDN(RFC4519Style.o, "o")
                .addRDN(RFC4519Style.cn, "cn")
                .build();

        assertEquals(x500Name, expected);
    }

    @Test
    public void testNameBuilding() {
        final X500Name x500Name = SelfSignedCANameBuilder
                .builder()
                .commonName("cn")
                .country("c")
                .organization("o")
                .organizationalUnit("ou")
                .location("l")
                .state("st")
                .build()
                .toX500Name();

        final X500Name expected = new X500NameBuilder()
                .addRDN(RFC4519Style.c, "c")
                .addRDN(RFC4519Style.o, "o")
                .addRDN(RFC4519Style.cn, "cn")
                .addRDN(RFC4519Style.l, "l")
                .addRDN(RFC4519Style.st, "st")
                .addRDN(RFC4519Style.ou, "ou")
                .build();

        assertEquals(x500Name, expected);
    }
}