package ch.zhaw.ba.anath.authentication;

import lombok.Data;

/**
 * @author Rafael Ostertag
 */
@Data
public class WhoAmIDto {
    private String user;
    private boolean admin;
    private String firstname;
    private String lastname;
}
