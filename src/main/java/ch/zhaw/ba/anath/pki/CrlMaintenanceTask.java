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

import ch.zhaw.ba.anath.pki.services.RevocationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * Update the CRL if it is nearing its nextUpdate date.
 *
 * @author Rafael Ostertag
 */
@Component
@Profile("!tests")
@Slf4j
public class CrlMaintenanceTask {
    private static final long ONE_HOUR_IN_MILLIS = 60 * 60 * 1000L;
    private final RevocationService revocationService;

    public CrlMaintenanceTask(RevocationService revocationService) {
        this.revocationService = revocationService;
    }

    @Scheduled(fixedRate = ONE_HOUR_IN_MILLIS)
    public void keepCrlFresh() {
        try {
            log.info("Start CRL refresh task");
            final Date now = new Date();
            final Date nextUpdate = revocationService.getNextUpdate();

            log.info("Next update of CRL is due on {}. Current time {}", nextUpdate, now);

            final long timeDelta = getTimeDelta(nextUpdate, now);
            if (timeDelta < ONE_HOUR_IN_MILLIS) {
                log.info("CRL is going to expire in less than an hour");
                log.info("Initiate CRL update");
                revocationService.updateCertificateRevocationList();
            } else {
                log.info("CRL is not expiring within the next hour. Not performing update");
            }

            log.info("End CRL refresh task");
        } catch (Exception e) {
            log.error("Error during CRL refresh task: {}", e.getMessage());
        }
    }

    /**
     * Compute t1 - t2.
     *
     * @param t1 {@link Date} instance
     * @param t2 {@link Date} instance
     *
     * @return result of t1 - t2 in milliseconds.
     */
    private long getTimeDelta(Date t1, Date t2) {
        return t1.getTime() - t2.getTime();
    }
}
