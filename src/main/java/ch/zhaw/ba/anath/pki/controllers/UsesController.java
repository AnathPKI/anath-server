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

package ch.zhaw.ba.anath.pki.controllers;

import ch.zhaw.ba.anath.AnathExtensionMediaType;
import ch.zhaw.ba.anath.pki.dto.UpdateUseDto;
import ch.zhaw.ba.anath.pki.dto.UseDto;
import ch.zhaw.ba.anath.pki.dto.UseItemDto;
import ch.zhaw.ba.anath.pki.services.UseService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
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
@RequestMapping(value = "/uses",
        consumes = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE,
        produces = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE
)
@Api(tags = {"Certificate Authority"})
public class UsesController {
    private static final String LIST_REL = "list";
    private final UseService useService;

    public UsesController(UseService useService) {
        this.useService = useService;
    }

    @GetMapping(
            consumes = MediaType.ALL_VALUE,
            produces = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    @ApiOperation(value = "Get all Known Certificate Uses")
    public Resources<UseItemDto> getAll() {
        final List<UseItemDto> all = useService.getAll();
        for (UseItemDto item : all) {
            item.add(linkTo(methodOn(UsesController.class).getUse(item.getUse())).withSelfRel());
            item.add(linkTo(methodOn(UsesController.class).deleteUse(item.getUse())).withRel("delete"));
            item.add(linkTo(methodOn(UsesController.class).updateUse(item.getUse(), new UpdateUseDto())).withRel
                    ("update"));
        }

        return new Resources<>(all, linkTo(methodOn(UsesController.class).createUse(new UseDto())).withRel("new"));
    }

    @GetMapping(
            value = "/{key:.*}",
            consumes = MediaType.ALL_VALUE,
            produces = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN')")
    @ApiOperation(value = "Get a Certificate Use")
    public UseDto getUse(@PathVariable String key) {
        final UseDto use = useService.getUse(key);
        use.add(linkTo(methodOn(UsesController.class).getUse(key)).withSelfRel());
        return use;
    }

    @PostMapping(
            consumes = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE,
            produces = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('ADMIN')")
    @ApiOperation(value = "Create a new Certificate Use")
    public HttpEntity<Void> createUse(@RequestBody @Validated UseDto useDto) {
        useService.create(useDto);
        final URI uri = linkTo(methodOn(UsesController.class).getUse(useDto.getUse())).toUri();
        return ResponseEntity.created(uri).build();
    }

    @PutMapping(
            value = "/{key:.*}",
            consumes = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE,
            produces = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN')")
    @ApiOperation(value = "Update an Existing Certificate Use")
    public UseItemDto updateUse(@PathVariable String key, @RequestBody @Validated UpdateUseDto updateUseDto) {
        final UseItemDto useItemDto = useService.updateUse(key, updateUseDto.getConfiguration());
        useItemDto.add(linkTo(methodOn(UsesController.class).getUse(key)).withSelfRel());
        useItemDto.add(linkTo(methodOn(UsesController.class).getAll()).withRel(LIST_REL));

        return useItemDto;
    }

    @DeleteMapping(
            value = "/{key:.*}",
            consumes = MediaType.ALL_VALUE,
            produces = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN')")
    @ApiOperation(value = "Delete a Certificate Use")
    public ResourceSupport deleteUse(@PathVariable String key) {
        useService.delete(key);

        final ResourceSupport resourceSupport = new ResourceSupport();
        resourceSupport.add(linkTo(methodOn(UsesController.class).getAll()).withRel(LIST_REL));
        return resourceSupport;
    }
}
