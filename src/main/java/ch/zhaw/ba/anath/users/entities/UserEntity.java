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

package ch.zhaw.ba.anath.users.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.hateoas.ResourceSupport;

import javax.persistence.*;
import javax.validation.constraints.Max;

/**
 * @author Rafael Ostertag
 */
@Entity
@Table(name = "users")
@Data
@EqualsAndHashCode(of = {"id"}, callSuper = false)
public class UserEntity extends ResourceSupport {
    @Id
    @GeneratedValue
    private Long id;
    @Column(name = "firstname", nullable = false, unique = false)
    @NotEmpty
    @Max(value = 512, message = "Maximum 512 characters")
    private String firstname;
    @Column(name = "lasttname", nullable = false, unique = false)
    @NotEmpty
    @Max(value = 512, message = "Maximum 512 characters")
    private String lastname;
    @Column(name = "email", nullable = false, unique = true)
    @NotEmpty
    @Max(value = 1024, message = "Maximum 1024 characters")
    private String email;
    @Column(name = "password", nullable = false, unique = false)
    @NotEmpty
    @Max(value = 1024, message = "Maximum 1024 characters")
    private String password;
    @Column(name = "admin", nullable = false, unique = false)
    private Boolean admin;

    @JsonIgnore
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
