package br.gabriel.springrestspecialist.auth.core;

import br.gabriel.springrestspecialist.auth.domain.ResourceOwner;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
public class AuthUser extends User {
    private final Long id;

    private final String name;

    public AuthUser(ResourceOwner user, Collection<? extends GrantedAuthority> authorities) {
        super(user.getEmail(), user.getPassword(), authorities);

        this.id = user.getId();
        this.name = user.getName();
    }
}
