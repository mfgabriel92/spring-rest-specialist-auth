package br.gabriel.springrestspecialist.auth.core;

import br.gabriel.springrestspecialist.auth.domain.ResourceOwner;
import br.gabriel.springrestspecialist.auth.domain.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.stream.Collectors;

@Service
public class TheUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository repository;

    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        ResourceOwner user = repository
            .findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException(String.format("User with email '%s' not found", email)));

        return new AuthUser(user, getAuthorities(user));
    }

    private Collection<GrantedAuthority> getAuthorities(ResourceOwner user) {
        return user.getGroups().stream()
            .flatMap(group -> group.getPermissions().stream().map(
                permission -> new SimpleGrantedAuthority(permission.getName().toUpperCase())
            ))
            .collect(Collectors.toSet());
    }
}
