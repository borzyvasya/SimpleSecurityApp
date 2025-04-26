package ru.me.springcourse.SimpleSecurityApp.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.me.springcourse.SimpleSecurityApp.models.Person;

import java.util.Optional;


@Repository
public interface PeopleRepository extends JpaRepository<Person, Integer> {
    Optional<Person> findByUsername(String username);
}
