package br.gabriel.springrestspecialist.auth.core;

import br.gabriel.springrestspecialist.auth.domain.ResourceOwner;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

@Getter
public class AuthUser extends User {
    private String name;

    public AuthUser(ResourceOwner user) {
        super(user.getEmail(), user.getPassword(), Collections.emptyList());

        this.name = user.getName();
    }
}
