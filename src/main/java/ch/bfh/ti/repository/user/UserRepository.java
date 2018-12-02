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
        final SensitiveUser adjusted = new SensitiveUser();
        getUserByUsername(user.getUsername()).ifPresent(
                oldUser->{
                    adjusted.setName(oldUser.getName());
                    adjusted.setUsername(oldUser.getUsername());
                    adjusted.setRegistered(oldUser.isRegistered());
                }
        );
        users.remove(adjusted);
        adjusted.setRegistered(user.isRegistered());
        adjusted.setName(user.getName());
        users.add(adjusted);
        return adjusted;
    }

    public SensitiveUser sensitiveUserFromUser(User user){
        if(user instanceof SensitiveUser)
            return (SensitiveUser) user;
        Optional<SensitiveUser> inRepo=getUserByUsername(user.getUsername());
        if(inRepo.isPresent()){
            return inRepo.get();
        }
        return new SensitiveUser(user);
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
