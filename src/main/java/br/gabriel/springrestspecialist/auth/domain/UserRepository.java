package br.gabriel.springrestspecialist.auth.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<TheUser, Integer> {
    Optional<TheUser> findByEmail(String email);
}
