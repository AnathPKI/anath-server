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

package ch.zhaw.ba.anath.pki.services;

import ch.zhaw.ba.anath.pki.entities.CertificateEntity;

/**
 * Confirmable Certificate Persistence Layer. Anath supports persisting certificates to Database after
 * confirmation. Thus persisting Signed Certificates is abstracted by this interface which is used by
 * {@link SigningService}.
 * <p>
 * Abstracting enables switching out the persisting layer using spring profiles.
 *
 * @author Rafael Ostertag
 */
public interface ConfirmableCertificatePersistenceLayer {
    /**
     * Store the {@link CertificateEntity}. Implementations are free to choose between immediate persistence or
     * tentative persistence. Upon tentative persistence, implementations must return a token identifying the
     * {@link CertificateEntity} which may be passed to {@link #confirm(String, String)} later on.
     *
     * @param certificateEntity {@link CertificateEntity} to store.
     *
     * @return Token as String.
     */
    String store(CertificateEntity certificateEntity);

    /**
     * Confirm the token and persist the {@link CertificateEntity} permanently.
     *
     * @param token  token as received by a call to {@link #store(CertificateEntity)}.
     * @param userId the user id the confirmation token belongs to.
     *
     * @return the {@link CertificateEntity}.
     */
    CertificateEntity confirm(String token, String userId);
}
