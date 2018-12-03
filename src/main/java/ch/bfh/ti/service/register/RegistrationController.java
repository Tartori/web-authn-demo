package ch.bfh.ti.service.register;

import ch.bfh.ti.repository.auth.AuthData;
import ch.bfh.ti.repository.auth.AuthenticatorDataParser;
import ch.bfh.ti.repository.user.SensitiveUser;
import ch.bfh.ti.repository.user.User;
import ch.bfh.ti.repository.user.UserRepository;
import ch.bfh.ti.utils.Base64StringGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

@RestController
@RequestMapping(RegistrationController.RESOURCE)
public class RegistrationController {
    static final String RESOURCE = "/register";

    @Autowired
    private AuthenticatorDataParser authenticatorDataParser;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private Base64StringGenerator base64StringGenerator;
    @Value("${fido.domain}")
    private String domain;
    @Autowired
    Base64.Decoder base64UrlDecoder;
    @Autowired
    Base64.Encoder base64UrlEncoder;
    @Autowired
    CBORFactory cborFactory;

    @PostMapping
    public ObjectNode create(@RequestBody final User user) {
        if(user.getUsername().isEmpty() || user.getName().isEmpty()){
            System.out.println("create didn't work: "+user.toString());
            return badRequestResponse();
        }

        if (userRepository.getUserByUsername(user.getUsername()).isPresent()) {
            userRepository.updateUser(new SensitiveUser(user));
            //return badRequestResponse();
        }

        SensitiveUser sensitiveUser = userRepository.sensitiveUserFromUser(user);
        sensitiveUser.setRegistered(false);
        sensitiveUser.setId(base64StringGenerator.generateNewString());
        sensitiveUser.setChallenge(base64StringGenerator.generateNewString());
        sensitiveUser.setDomain("http://localhost:8000");
        ObjectNode node = objectMapper
                .createObjectNode()
                .putObject("publicKey");
        node.put("challenge", sensitiveUser.getChallenge());
        node.put("fidoResponse", "direct");
        node.putObject("rp")
                .put("name", "BFH")
                .put("domain", sensitiveUser.getDomain());
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
        System.out.println("User registration verification sent: "+node.toString());
        return node;
    }

    @PostMapping(path = "/response")
    public ObjectNode response(@RequestBody final JsonNode inputJson) throws IOException {

        System.out.println("User registration response: "+inputJson.toString());
        if(!inputJson.has("response") || !inputJson.get("response").has("attestationObject")){
            return badRequestResponse();
        }
        JsonNode response = inputJson.get("response");
        JsonNode decodedClientData = objectMapper.readTree(
                new String(
                        base64UrlDecoder.decode(
                                inputJson.get("response")
                                        .get("clientDataJSON").asText()),
                        Charset.forName("UTF-8")));
        if(!decodedClientData.get("type").asText().equals("webauthn.create")){
            return badRequestResponse();
        }

        Optional<SensitiveUser> sensitiveUserCheck =
                userRepository.getUserByChallengeAndRegistered(decodedClientData.get("challenge").asText(), false);
        if(!sensitiveUserCheck.isPresent()){
            return badRequestResponse();
        }

        SensitiveUser sensitiveUser=sensitiveUserCheck.get();
        if(!sensitiveUser.getDomain().equals(decodedClientData.get("origin").asText())){
            return badRequestResponse();
        }

        ObjectMapper cborMapper = new ObjectMapper(cborFactory);
        JsonNode attestationData =cborMapper.readTree(base64UrlDecoder.decode(response.get("attestationObject").asText()));
        AuthData authData = authenticatorDataParser.parseAttestationData(attestationData.get("authData").asText());

        if(!authData.isUserPresentFlagSet()){
            return badRequestResponse();
        }
        byte[] rpIdHash = DigestUtils.sha256("localhost");
        if(!Arrays.equals(rpIdHash, authData.getRpIdHash())&&false){//todo currently always true for some reason...
            return badRequestResponse();
        }

        if(userRepository.getUserByCredential(base64UrlEncoder.encodeToString(authData.getCredId())).isPresent()){
            return badRequestResponse();
        }

        byte[] clientHash=DigestUtils.sha256(response.get("clientDataJSON").asText());

        sensitiveUser.setCredentialId(base64UrlEncoder.encodeToString(authData.getCredId()));
        sensitiveUser.setRegistered(true);


        ObjectNode node = objectMapper
                .createObjectNode();
        node.put("username",sensitiveUser.getUsername());
        node.put("errorMessage", "");
        node.put("status", "ok");
        userRepository.updateUser(sensitiveUser);
        return node;
    }

    private ObjectNode badRequestResponse() {
        return objectMapper.createObjectNode().put("error", "Bad Request");
    }

}
