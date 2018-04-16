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

import ch.zhaw.ba.anath.AnathExtensionMediaType;
import ch.zhaw.ba.anath.pki.services.RevocationService;
import ch.zhaw.ba.anath.users.dto.*;
import ch.zhaw.ba.anath.users.services.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.hateoas.Link;
import org.springframework.hateoas.ResourceSupport;
import org.springframework.hateoas.Resources;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
        consumes = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE,
        produces = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE)
@Api(tags = {"User Management"})
public class UserController {
    private final UserService userService;
    private final RevocationService revocationService;

    public UserController(UserService userService, RevocationService revocationService) {
        this.userService = userService;
        this.revocationService = revocationService;
    }

    @GetMapping(
            consumes = MediaType.ALL_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN')")
    @ApiOperation(value = "Get All Users")
    public Resources<UserLinkDto> getAll() {
        final List<UserLinkDto> all = userService.getAll();
        all.stream().forEach(x -> x.add(linkTo(UserController.class).slash(x.getUserId()).withSelfRel()));
        return new Resources<>(all);
    }

    @GetMapping(
            path = "/{id}",
            consumes = MediaType.ALL_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN') or (hasRole('USER') and hasPermission(#id,'user','get'))")
    @ApiOperation(value = "Get a User")
    public UserDto getUser(@PathVariable long id) {
        final UserDto user = userService.getUser(id);
        user.add(linkTo(methodOn(UserController.class).getUser(id)).withSelfRel());
        return user;
    }

    @PutMapping(path = "/{id}")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN')")
    @ApiOperation(value = "Update a User")
    public UserLinkDto updateUser(@PathVariable long id, @RequestBody @Validated UpdateUserDto updateUserDto) {
        final UserLinkDto userLinkDto = userService.updateUser(id, updateUserDto);
        userLinkDto.add(linkTo(methodOn(UserController.class).getUser(id)).withSelfRel());
        return userLinkDto;
    }

    @DeleteMapping(
            path = "/{id}",
            consumes = MediaType.ALL_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN')")
    @ApiOperation(value = "Delete a User")
    public ResourceSupport deleteUser(@PathVariable long id) {
        final UserDto userInformation = userService.getUser(id);

        userService.deleteUser(id);
        revocationService.revokeAllCertificatesByUser(userInformation.getEmail(), "User deleted");

        final ResourceSupport resourceSupport = new ResourceSupport();
        resourceSupport.add(linkTo(methodOn(UserController.class).getAll()).withRel("list"));
        return resourceSupport;
    }

    @PutMapping(path = "/{id}/password")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('USER') and hasPermission(#id,'user','changePassword')")
    @ApiOperation(value = "Change Password of a User")
    public UserLinkDto changePassword(@PathVariable long id, @RequestBody @Validated ChangePasswordDto
            changePasswordDto) {
        final UserLinkDto userLinkDto = userService.changePassword(id, changePasswordDto);
        userLinkDto.add(linkTo(methodOn(UserController.class).getUser(id)).withSelfRel());
        return userLinkDto;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ADMIN')")
    @ApiOperation(value = "Create a New User")
    public HttpEntity<Void> createUser(@RequestBody @Validated CreateUserDto createUserDto) {
        final UserLinkDto user = userService.createUser(createUserDto);
        final Link link = linkTo(methodOn(UserController.class).getUser(user.getUserId())).withSelfRel();
        return ResponseEntity.created(URI.create(link.getHref())).build();
    }


}
