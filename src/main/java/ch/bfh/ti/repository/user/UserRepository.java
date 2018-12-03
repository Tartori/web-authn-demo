package ch.bfh.ti.repository.user;

import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserRepository {
    private Set<SensitiveUser> users;

    public UserRepository(){
       this.users = new HashSet<>();
       addTestData();
    }

    public Set<User> getSafeUsers(){
        return Collections.unmodifiableSet(users.stream().map(User::getStrippedUser).collect(Collectors.toSet()));
    }

    public Optional<SensitiveUser> getUserByChallengeAndRegistered(final String challenge, final boolean isRegistered){
        return users.stream().filter(user -> user.isRegistered()==isRegistered && user.getChallenge().equals(challenge)).findFirst();
    }

    public Optional<SensitiveUser> getUserByCredential(final String credential){
        return users.stream().filter(user -> user.getCredentialId().equals(credential)).findFirst();
    }

    public Set<SensitiveUser> getSensitiveUsers(){
        return Collections.unmodifiableSet(users);
    }

    public Optional<SensitiveUser> getUserByUsername(final String username){
        return users.stream().filter(user->user.getUsername().equals(username)).findFirst();
    }

    public User addUser(SensitiveUser user){
        users.add(user);
        return user;
    }

    public User updateUser(SensitiveUser user){
        if(getUserByUsername(user.getUsername()).isPresent())
            users.remove(user);
        users.add(user);
        return user;
    }

    public SensitiveUser sensitiveUserFromUser(User user){
        if(user instanceof SensitiveUser)
            return (SensitiveUser) user;
        Optional<SensitiveUser> inRepo=getUserByUsername(user.getUsername());
        return inRepo.orElseGet(() -> new SensitiveUser(user));
    }

    private void addTestData(){

        SensitiveUser alice = new SensitiveUser();
        alice.setUsername("alice");
        users.add(alice);
        SensitiveUser bob = new SensitiveUser();
        bob.setUsername("bob");
        users.add(bob);
        SensitiveUser eve = new SensitiveUser();
        eve.setUsername("eve");
        users.add(eve);
        users.add(eve);

    }
}
