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

import ch.zhaw.ba.anath.AnathException;
import ch.zhaw.ba.anath.config.properties.AnathProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;

/**
 * Send a confirmation token via SMTP. This Service is only available when the "confirm" Spring profile is enabled.
 *
 * @author Rafael Ostertag
 */
@Service
@Profile("confirm")
@Slf4j
public class ConfirmationMailNotificationServiceImpl implements ConfirmationNotificationService {
    private static final String SUBJECT = "Certificate Signing Request Confirmation Required";
    private final AnathProperties anathProperties;
    private final Session mailSession;

    public ConfirmationMailNotificationServiceImpl(AnathProperties anathProperties) {
        this.anathProperties = anathProperties;
        final Properties defaultSessionProperties = new Properties(System.getProperties());
        defaultSessionProperties.setProperty("mail.smtp.host", anathProperties.getConfirmation().getMailServer());

        mailSession = Session.getDefaultInstance(defaultSessionProperties);

        log.info("ConfirmationMailNotificationService initialized");
    }

    @Override
    public void sendMail(String confirmationToken, String recipient) {
        try {
            MimeMessage message = new MimeMessage(mailSession);
            message.setFrom(getSender());
            message.addRecipient(Message.RecipientType.TO, makeRecipient(recipient));
            message.setSubject(getSubject());
            message.setText(makeText(confirmationToken));

            Transport.send(message);
            log.info("Confirmation message sent to {}", recipient);
        } catch (MessagingException e) {
            log.error("Error sending confirmation message to {}: {}", recipient, e.getMessage());
            throw new AnathException("Error sending confirmation message", e);
        }
    }

    private String makeText(String confirmationToken) {
        return String.format("Please confirm signing request. The confirmation token is: %s%n%nYours truly%nAnath",
                confirmationToken);
    }

    private String getSubject() {
        return SUBJECT;
    }

    private InternetAddress makeRecipient(String recipient) throws AddressException {
        return new InternetAddress(recipient);
    }

    private InternetAddress getSender() throws AddressException {
        return new InternetAddress(anathProperties.getConfirmation().getSender());
    }
}
