package ch.bfh.ti.service.register;

import ch.bfh.ti.repository.user.SensitiveUser;
import ch.bfh.ti.repository.user.User;
import ch.bfh.ti.repository.user.UserRepository;
import ch.bfh.ti.utils.ChallangeGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;

@RestController
@RequestMapping(RegistrationController.RESOURCE)
public class RegistrationController {
    static final String RESOURCE = "/register";

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private ChallangeGenerator challangeGenerator;
    @Value("${fido.domain}")
    private String domain;
    @PostMapping
    public ObjectNode create(@RequestBody final User user) {
        if(user.getUsername().isEmpty() || user.getName().isEmpty()){
            System.out.println("create didn't work: "+user.toString());
            return badRequestResponse();
        }

        if (userRepository.getUserByUsername(user.getUsername()).isPresent()) {
          return badRequestResponse();
        }

        SensitiveUser sensitiveUser = userRepository.sensitiveUserFromUser(user);
        sensitiveUser.setRegistered(false);
        sensitiveUser.setId(new SecureRandom().nextInt()&Integer.MAX_VALUE);
        sensitiveUser.setChallenge(challangeGenerator.generateNewChallange());
        ObjectNode node = objectMapper.createObjectNode();
        node.put("challenge", sensitiveUser.getChallenge());
        node.put("user.id", sensitiveUser.getId());
        node.put("domain", domain);
        userRepository.addUser(sensitiveUser);
        return node;
    }

    private ObjectNode badRequestResponse() {
        return objectMapper.createObjectNode().put("error", "Bad Request");
    }

}
