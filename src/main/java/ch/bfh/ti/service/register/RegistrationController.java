package ch.bfh.ti.service.register;

import ch.bfh.ti.repository.user.SensitiveUser;
import ch.bfh.ti.repository.user.User;
import ch.bfh.ti.repository.user.UserRepository;
import ch.bfh.ti.utils.Base64StringGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(RegistrationController.RESOURCE)
public class RegistrationController {
    static final String RESOURCE = "/register";

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private Base64StringGenerator base64StringGenerator;
    @Value("${fido.domain}")
    private String domain;
    @PostMapping
    public ObjectNode create(@RequestBody final User user) {
        if(user.getUsername().isEmpty() || user.getName().isEmpty()){
            System.out.println("create didn't work: "+user.toString());
            return badRequestResponse();
        }

//        if (userRepository.getUserByUsername(user.getUsername()).isPresent()) {
//          return badRequestResponse();
//        }

        SensitiveUser sensitiveUser = userRepository.sensitiveUserFromUser(user);
        sensitiveUser.setRegistered(false);
        sensitiveUser.setId(base64StringGenerator.generateNewString());
        sensitiveUser.setChallenge(base64StringGenerator.generateNewString());
        ObjectNode node = objectMapper
                .createObjectNode()
                .putObject("publicKey");
        node.put("challenge", sensitiveUser.getChallenge());
        node.put("fidoResponse", "direct");
        node.putObject("rp")
                .put("name", "BFH") ;
        node.putObject("user")
                .put("id", sensitiveUser.getId())
                .put("name", sensitiveUser.getUsername())
                .put("displayName", sensitiveUser.getName());
        node.putArray("pubKeyCredParams")
                .addObject()
                .put("type","public-key")
                .put("alg", -7);
        node.put("timeout", 60*1000);
        node.put("errorMessage", "");
        node.put("status", "ok");
        userRepository.updateUser(sensitiveUser);
        return node;
    }

    private ObjectNode badRequestResponse() {
        return objectMapper.createObjectNode().put("error", "Bad Request");
    }

}
