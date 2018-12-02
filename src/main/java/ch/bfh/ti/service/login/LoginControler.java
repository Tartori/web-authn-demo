package ch.bfh.ti.service.login;

import ch.bfh.ti.repository.user.User;
import ch.bfh.ti.repository.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping(LoginControler.RESOURCE)
public class LoginControler {
    static final String RESOURCE = "/login";
    private static final String UserName = "/{username}";

    @Autowired
    private UserRepository userRepository;


    @PostMapping
    public ResponseEntity<User> create(@RequestBody final User dataOffer) {
        return new ResponseEntity<>(userRepository.addUser(dataOffer), HttpStatus.CREATED);
    }
}
