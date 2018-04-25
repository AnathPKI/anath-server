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

package ch.zhaw.ba.anath.authentication;

import ch.zhaw.ba.anath.users.entities.UserEntity;
import ch.zhaw.ba.anath.users.exceptions.UserDoesNotExistException;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * @author Rafael Ostertag
 */
@RestController
@RequestMapping(path = "/whoami",
        produces = MediaType.APPLICATION_JSON_UTF8_VALUE
)
@Api(tags = {"Misc"})
@Slf4j
@Transactional(transactionManager = "userTransactionManager")
public class WhoAmIController {
    private final UserRepository userRepository;

    public WhoAmIController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    public WhoAmIDto whoAmiI(HttpServletRequest httpServletRequest) {
        // TODO: refactor. Pulling in the repository is ugly, may be it can be solved using the UserService.
        final String userName = httpServletRequest.getUserPrincipal().getName();
        final Optional<UserEntity> optionalUser = userRepository.findOneByEmail(userName);
        final UserEntity userEntity = optionalUser.orElseThrow(() -> {
            log.error("User '{}' not found", userName);
            return new UserDoesNotExistException("User does not exist");
        });

        final WhoAmIDto whoAmIDto = new WhoAmIDto();
        whoAmIDto.setAdmin(userEntity.getAdmin());
        whoAmIDto.setUser(userEntity.getEmail());
        whoAmIDto.setFirstname(userEntity.getFirstname());
        whoAmIDto.setLastname(userEntity.getLastname());

        return whoAmIDto;
    }
}
