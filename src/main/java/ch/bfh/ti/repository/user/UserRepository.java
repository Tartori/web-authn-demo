package ch.bfh.ti.repository.user;

import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class UserRepository {
    private Set<User> users;

    public UserRepository(){
       this.users = new HashSet<>();
       addTestData();
    }

    public Set<User> getUsers(){
        return Collections.unmodifiableSet(users);
    }

    public Optional<User> getUserByUsername(final String username){
        return users.stream().filter(user->user.getUsername().equals(username)).findFirst();
    }

    public User addUser(User user){
        users.add(user);
        return user;
    }

    private void addTestData(){

        User alice = new User();
        alice.setUsername("alice");
        users.add(alice);
        User bob = new User();
        bob.setUsername("bob");
        users.add(bob);
        User eve = new User();
        eve.setUsername("eve");
        users.add(eve);
        users.add(eve);

    }
}
