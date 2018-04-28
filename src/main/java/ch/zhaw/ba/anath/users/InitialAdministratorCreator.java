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

package ch.zhaw.ba.anath.users;

import ch.zhaw.ba.anath.users.entities.UserEntity;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Create an initial administrator if no administrator exists in the user database.
 * <p>
 * It listens on {@link ApplicationReadyEvent}.
 *
 * @author Rafael Ostertag
 */
@Component
@Profile("!tests")
@Transactional(transactionManager = "userTransactionManager")
@Slf4j
public class InitialAdministratorCreator {
    private static final int ASSUMED_LINE_LENGTH = 78;
    private static final char NULL_CHARACTER = '\0';
    private static final char EYE_CATCHER_CHARACTER = '>';
    private final UserRepository userRepository;
    private final ApplicationContext applicationContext;
    private final PasswordEncoder passwordEncoder;

    public InitialAdministratorCreator(UserRepository userRepository, ApplicationContext applicationContext,
                                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.applicationContext = applicationContext;
        this.passwordEncoder = passwordEncoder;
    }

    @EventListener
    public void processApplicationPreparedEvent(ApplicationReadyEvent event) {
        if (!event.getApplicationContext().getId().equals(applicationContext.getId())) {
            return;
        }

        final List<UserEntity> allByAdmin = userRepository.findAllByAdmin(true);
        if (!allByAdmin.isEmpty()) {
            log.info("Admin user(s) found. Not going to create initial administrator user");
            return;
        }

        log.info("No admin user found in database, going to create initial administrator");
        createInitialAdministrator();
    }

    private void createInitialAdministrator() {
        final UserEntity initialAdminUser = new UserEntity();
        initialAdminUser.setAdmin(true);
        initialAdminUser.setFirstname("Initial");
        initialAdminUser.setLastname("Administrator");
        initialAdminUser.setEmail("admin@localhost.localdomain");

        final String initialPassword = UUID.randomUUID().toString();
        initialAdminUser.setPassword(passwordEncoder.encode(initialPassword));

        userRepository.save(initialAdminUser);

        final String eyeCatcher = new String(new char[ASSUMED_LINE_LENGTH])
                .replace(NULL_CHARACTER, EYE_CATCHER_CHARACTER);
        final String logMessage = "\n" +
                eyeCatcher +
                "\n\n" +
                "Created initial administrator\n\tusername: {}\n\tpassword: {}" +
                "\n\n" +
                eyeCatcher;
        log.info(logMessage, initialAdminUser.getEmail(), initialPassword);
    }
}
