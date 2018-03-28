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

package ch.zhaw.ba.anath.pki.entities;

import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.persistence.*;
import java.math.BigInteger;
import java.sql.Timestamp;

/**
 * X.509 Certificate Entity.
 *
 * @author Rafael Ostertag
 */
@Entity
@Table(name = "certificates")
@Data
@EqualsAndHashCode(of = "id")
public class CertificateEntity {
    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "serial_number", unique = true, nullable = false, precision = 48, scale = 0)
    private BigInteger serial;

    @Column(name = "not_valid_before", nullable = false)
    private Timestamp notValidBefore;

    @Column(name = "not_valid_after", nullable = false)
    private Timestamp notValidAfter;

    // The subject must only be unique for non-expired, non-revoked certificates. We handle this logic in the
    // business logic.
    @Column(name = "subject", nullable = false, unique = false)
    private String subject;

    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    private CertificateStatus status;

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "x509_cert_pem", nullable = false)
    private byte[] x509PEMCertificate;

    @OneToOne
    @JoinColumn(name = "certificate_use", nullable = false)
    private UseEntity use;
}
