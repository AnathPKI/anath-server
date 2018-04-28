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

package ch.zhaw.ba.anath.pki.corecustomizations;

import ch.zhaw.ba.anath.pki.core.exceptions.CertificateConstraintException;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateConstraintProvider;
import ch.zhaw.ba.anath.users.dto.UserDto;
import ch.zhaw.ba.anath.users.services.UserService;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Collections;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * @author Rafael Ostertag
 */
public class OrganizationAndEmailCertificateConstraintTest {

    private static final Collection<? extends GrantedAuthority> DEFAULT_USER_ROLES = Collections.singleton(new
            SimpleGrantedAuthority("USER"));
    private static final String TEST_ORGANIZATION = "ACME";
    private static final String TEST_EMAIL = "user@example.com";
    private static final String TEST_NAME = "James Kirk";
    private static final int FIRSTNAME_INDEX = 0;
    private static final int LASTNAME_INDEX = 1;
    private CertificateConstraintProvider organizationAndEmailCertficateConstraint;
    private X500Name issuerName;
    private UserService userServiceMock;

    @Before
    public void setUp() {
        issuerName = buildIssuerName();
        SecurityContextHolder.clearContext();

        userServiceMock = mock(UserService.class);
        organizationAndEmailCertficateConstraint = new
                OrganizationAndEmailCertificateConstraint(userServiceMock);
    }

    @Test
    public void validateSubject() {
        setUpTestUser(TEST_EMAIL);
        setUpUserServiceMock(TEST_EMAIL, TEST_NAME);
        final X500Name subject = buildSubjectName(TEST_ORGANIZATION, TEST_EMAIL, TEST_NAME);

        organizationAndEmailCertficateConstraint.validateSubject(subject, issuerName);
        // Not throwing an exception is the test
    }

    @Test
    public void validateMultiValueSubject() {
        setUpTestUser(TEST_EMAIL);
        setUpUserServiceMock(TEST_EMAIL, TEST_NAME);

        final X500NameBuilder x500NameBuilder = new X500NameBuilder();
        final X500Name subject = x500NameBuilder
                .addMultiValuedRDN(
                        new AttributeTypeAndValue[]{
                                new AttributeTypeAndValue(BCStyle.C, new DERUTF8String("CH")),
                                new AttributeTypeAndValue(BCStyle.ST, new DERUTF8String("Thurgau")),
                                new AttributeTypeAndValue(BCStyle.L, new DERUTF8String("Kefikon")),
                                new AttributeTypeAndValue(BCStyle.O, new DERUTF8String(TEST_ORGANIZATION)),
                                new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String("dev")),
                                new AttributeTypeAndValue(BCStyle.CN, new DERUTF8String(TEST_NAME)),
                                new AttributeTypeAndValue(BCStyle.E, new DERUTF8String(TEST_EMAIL))
                        }
                ).build();

        organizationAndEmailCertficateConstraint.validateSubject(subject, issuerName);
        // Not throwing an exception is the test
    }

    @Test(expected = CertificateConstraintException.class)
    public void validateMultiValueSubjectWithMissingCN() {
        setUpTestUser(TEST_EMAIL);
        setUpUserServiceMock(TEST_EMAIL, TEST_NAME);

        final X500NameBuilder x500NameBuilder = new X500NameBuilder();
        final X500Name nonMatchingName = x500NameBuilder
                .addMultiValuedRDN(
                        new AttributeTypeAndValue[]{
                                new AttributeTypeAndValue(BCStyle.C, new DERUTF8String("CH")),
                                new AttributeTypeAndValue(BCStyle.ST, new DERUTF8String("Thurgau")),
                                new AttributeTypeAndValue(BCStyle.L, new DERUTF8String("Kefikon")),
                                new AttributeTypeAndValue(BCStyle.O, new DERUTF8String(TEST_ORGANIZATION)),
                                new AttributeTypeAndValue(BCStyle.OU, new DERUTF8String("dev")),
                                new AttributeTypeAndValue(BCStyle.E, new DERUTF8String(TEST_EMAIL))
                        }
                ).build();
        organizationAndEmailCertficateConstraint.validateSubject(nonMatchingName, issuerName);
    }

    private void setUpUserServiceMock(String testEmail, String testName) {
        final UserDto userDto = new UserDto();
        final String[] nameComponents = testName.split(" ");
        userDto.setFirstname(nameComponents[FIRSTNAME_INDEX]);
        userDto.setLastname(nameComponents[LASTNAME_INDEX]);
        given(userServiceMock.getUser(testEmail)).willReturn(userDto);
    }

    @Test(expected = CertificateConstraintException.class)
    public void validateNonMatchingOrganization() {
        setUpTestUser(TEST_EMAIL);
        setUpUserServiceMock(TEST_EMAIL, TEST_NAME);
        final X500Name subject = buildSubjectName(TEST_ORGANIZATION + "another", TEST_EMAIL, TEST_NAME);

        organizationAndEmailCertficateConstraint.validateSubject(subject, issuerName);
    }

    @Test(expected = CertificateConstraintException.class)
    public void validateNonMatchingEmail() {
        setUpTestUser(TEST_EMAIL);
        setUpUserServiceMock("user2@example.com", TEST_NAME);
        final X500Name subject = buildSubjectName(TEST_ORGANIZATION, "user2@example.com", TEST_NAME);

        organizationAndEmailCertficateConstraint.validateSubject(subject, issuerName);
    }

    @Test(expected = CertificateConstraintException.class)
    public void validateNonMatchingCN() {
        setUpTestUser(TEST_EMAIL);
        setUpUserServiceMock(TEST_EMAIL, "Jean-Luc Piccard");
        final X500Name subject = buildSubjectName(TEST_ORGANIZATION, TEST_EMAIL, TEST_NAME);

        organizationAndEmailCertficateConstraint.validateSubject(subject, issuerName);
    }

    @Test(expected = CertificateConstraintException.class)
    public void validateNoEmailInSubject() {
        setUpTestUser(TEST_EMAIL);
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        final X500Name subject = x500NameBuilder
                .addRDN(BCStyle.C, "CH")
                .addRDN(BCStyle.ST, "Thurgau")
                .addRDN(BCStyle.L, "Kefikon")
                .addRDN(BCStyle.O, TEST_ORGANIZATION)
                .addRDN(BCStyle.OU, "dev")
                .addRDN(BCStyle.CN, TEST_NAME)
                .build();

        organizationAndEmailCertficateConstraint.validateSubject(subject, issuerName);
    }

    @Test(expected = CertificateConstraintException.class)
    public void validateNoCNInSubject() {
        setUpTestUser(TEST_EMAIL);
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        final X500Name subject = x500NameBuilder
                .addRDN(BCStyle.C, "CH")
                .addRDN(BCStyle.ST, "Thurgau")
                .addRDN(BCStyle.L, "Kefikon")
                .addRDN(BCStyle.O, TEST_ORGANIZATION)
                .addRDN(BCStyle.OU, "dev")
                .build();

        organizationAndEmailCertficateConstraint.validateSubject(subject, issuerName);
    }

    private UsernamePasswordAuthenticationToken setUpTestUser(String username) {
        final User testUser = new User(username, "", DEFAULT_USER_ROLES);
        final UsernamePasswordAuthenticationToken authentication = new
                UsernamePasswordAuthenticationToken(testUser, "", DEFAULT_USER_ROLES);

        SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return authentication;
    }

    private X500Name buildIssuerName() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        return x500NameBuilder
                .addRDN(BCStyle.C, "CH")
                .addRDN(BCStyle.ST, "Thurgau")
                .addRDN(BCStyle.L, "Kefikon")
                .addRDN(BCStyle.O, TEST_ORGANIZATION)
                .addRDN(BCStyle.OU, "another")
                .addRDN(BCStyle.CN, "The CA")
                .build();
    }

    private X500Name buildSubjectName(String organization, String email, String testName) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        return x500NameBuilder
                .addRDN(BCStyle.C, "CH")
                .addRDN(BCStyle.ST, "Thurgau")
                .addRDN(BCStyle.L, "Kefikon")
                .addRDN(BCStyle.O, organization)
                .addRDN(BCStyle.OU, "dev")
                .addRDN(BCStyle.CN, testName)
                .addRDN(BCStyle.E, email)
                .build();
    }
}