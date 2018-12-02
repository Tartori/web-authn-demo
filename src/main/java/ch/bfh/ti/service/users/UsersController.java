package ch.bfh.ti.service.users;

import ch.bfh.ti.repository.user.User;
import ch.bfh.ti.repository.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;

@RestController
@RequestMapping(UsersController.RESOURCE)
public class UsersController {
    static final String RESOURCE = "/users";
    private static final String UserName = "/{username}";

    @Autowired
    private UserRepository userRepository;

    @GetMapping
    public ResponseEntity<Set<User>> read() {
        return new ResponseEntity<>(userRepository.getSafeUsers(), HttpStatus.OK);
    }

    @GetMapping(UserName)
    public ResponseEntity<User> read(@PathVariable final String username) {
        return userRepository
                .getUserByUsername(username)
                .map(User::getStrippedUser)
                .map(user -> new ResponseEntity<>(user, HttpStatus.OK))
                .orElse(notFoundResponse());
    }



    private ResponseEntity<User> notFoundResponse() {
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }
}
