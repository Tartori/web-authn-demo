package ch.bfh.ti.service.users;

import ch.bfh.ti.repository.user.User;
import ch.bfh.ti.repository.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
    private ObjectMapper objectMapper;
    @Autowired
    private UserRepository userRepository;

    @GetMapping
    public ResponseEntity<Set<User>> read() {
        return new ResponseEntity<>(userRepository.getSafeUsers(), HttpStatus.OK);
    }

    @GetMapping(UserName)
    public ObjectNode read(@PathVariable final String username) {
    return userRepository
        .getUserByUsername(username)
        .map(User::getStrippedUser)
        .map(
            user ->
                objectMapper
                    .createObjectNode()
                    .put("name", user.getName())
                    .put(
                        "theSecret", "'<img width=\"250px\" src=\"img/theworstofthesecrets.jpg\">'")
                    .put("status", "ok"))
        .orElse(notFoundResponse());
    }



    private ObjectNode notFoundResponse() {
        return objectMapper.createObjectNode().put("error", "Bad Request");
    }
}
