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

package ch.zhaw.ba.anath.users.controllers;

import ch.zhaw.ba.anath.users.dto.*;
import ch.zhaw.ba.anath.users.services.UserService;
import org.springframework.hateoas.Link;
import org.springframework.hateoas.Resources;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.List;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

/**
 * @author Rafael Ostertag
 */
@RestController
@RequestMapping(path = "/users",
        consumes = AnathUserMediaType.APPLICATION_VND_ANATH_USER_V1_JSON_VALUE,
        produces = AnathUserMediaType.APPLICATION_VND_ANATH_USER_V1_JSON_VALUE)
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN')")
    public Resources<UserLinkDto> getAll() {
        final List<UserLinkDto> all = userService.getAll();
        all.stream().forEach(x -> x.add(linkTo(UserController.class).slash(x.getUserId()).withSelfRel()));
        return new Resources<>(all);
    }

    @GetMapping(path = "/{id}")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN') or (hasRole('USER') and hasPermission(#id,'user','get'))")
    public UserDto getUser(@PathVariable long id) {
        final UserDto user = userService.getUser(id);
        user.add(linkTo(methodOn(UserController.class).getUser(id)).withSelfRel());
        return user;
    }

    @PutMapping(path = "/{id}")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN')")
    public UserLinkDto updateUser(@PathVariable long id, @RequestBody @Validated UpdateUserDto updateUserDto) {
        final UserLinkDto userLinkDto = userService.updateUser(id, updateUserDto);
        userLinkDto.add(linkTo(methodOn(UserController.class).getUser(id)).withSelfRel());
        return userLinkDto;
    }

    @DeleteMapping(path = "/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(@PathVariable long id) {
        userService.deleteUser(id);
    }

    @PutMapping(path = "/{id}/password")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('USER') and hasPermission(#id,'user','changePassword')")
    public UserLinkDto changePassword(@PathVariable long id, @RequestBody @Validated ChangePasswordDto
            changePasswordDto) {
        final UserLinkDto userLinkDto = userService.changePassword(id, changePasswordDto);
        userLinkDto.add(linkTo(methodOn(UserController.class).getUser(id)).withSelfRel());
        return userLinkDto;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ADMIN')")
    public HttpEntity<Void> createUser(@RequestBody @Validated CreateUserDto createUserDto) {
        final UserLinkDto user = userService.createUser(createUserDto);
        final Link link = linkTo(methodOn(UserController.class).getUser(user.getUserId())).withSelfRel();
        return ResponseEntity.created(URI.create(link.getHref())).build();
    }


}
