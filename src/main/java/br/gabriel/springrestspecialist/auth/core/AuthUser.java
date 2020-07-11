package br.gabriel.springrestspecialist.auth.core;

import br.gabriel.springrestspecialist.auth.domain.TheUser;
import lombok.Getter;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

@Getter
public class AuthUser extends User {
    private String name;

    public AuthUser(TheUser user) {
        super(user.getEmail(), user.getPassword(), Collections.emptyList());

        this.name = user.getName();
    }
}
