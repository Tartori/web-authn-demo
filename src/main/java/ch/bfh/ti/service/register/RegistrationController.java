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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

@RestController
@RequestMapping(RegistrationController.RESOURCE)
public class RegistrationController {
    static final String RESOURCE = "/register";


    boolean failIfCredentialIsAlreadyInUse = true;
    boolean checkUserVerified=false;

    @Autowired
    private AuthenticatorDataParser authenticatorDataParser;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private Base64StringGenerator base64StringGenerator;
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
            return badRequestResponse(0);
        }

        if (userRepository.getUserByUsername(user.getUsername()).isPresent()) {
            userRepository.updateUser(new SensitiveUser(user));
            //return badRequestResponse();
        }

        SensitiveUser sensitiveUser = userRepository.sensitiveUserFromUser(user);
        sensitiveUser.setRegistered(false);
        sensitiveUser.setId(base64StringGenerator.generateNewString());
        sensitiveUser.setChallenge(base64StringGenerator.generateNewString());
        sensitiveUser.setDomain("dev.webauthn.demo");
        ObjectNode node = objectMapper
                .createObjectNode()
                .putObject("publicKey");
        node.put("challenge", sensitiveUser.getChallenge());
        node.put("fidoResponse", "direct");
        node.putObject("rp")
                .put("name", "BFH")
                .put("id", sensitiveUser.getDomain());
        node.putObject("user")
                .put("id", sensitiveUser.getId())
                .put("name", sensitiveUser.getUsername())
                .put("displayName", sensitiveUser.getName());
        node.putArray("pubKeyCredParams")
                .addObject()
                .put("type","public-key")
                .put("alg", -7);
        node.put("attestation", "direct");
        node.put("timeout", 60*1000);
        node.put("errorMessage", "");
        node.put("status", "ok");
        userRepository.updateUser(sensitiveUser);
        System.out.println("User registration verification sent: "+node.toString());
        return node;
    }

    @PostMapping(path = "/response")
    public ObjectNode response(@RequestBody final JsonNode inputJson) throws IOException {
        SensitiveUser sensitiveUser;
        try {
            sensitiveUser = performRegistrationSteps(inputJson);
        }catch (RegistrationFailedException ex){
            return badRequestResponse(ex.getStep());
        }

        ObjectNode node = objectMapper
                .createObjectNode();
        node.put("username", sensitiveUser.getUsername());
        node.put("errorMessage", "");
        node.put("status", "ok");
        userRepository.updateUser(sensitiveUser);
        return node;

    }

    private SensitiveUser performRegistrationSteps(final JsonNode inputJson)throws RegistrationFailedException{
        JsonNode response = step1(inputJson);//basic validation of input
        JsonNode decodedClientData = step2(inputJson);//decode client data
        step3(decodedClientData);//check for correct method
        SensitiveUser sensitiveUser = step4(decodedClientData);//check if challenge was sent
        step5(decodedClientData, sensitiveUser);//check origin
        step6(decodedClientData);//check token binding
        byte[] clientHash=step7(response); //calculate client hash because why not?
        AuthData authData = step8(response); //perform CBOR decoding
        step9(authData); //check rpid hash to origin - hashed
        step10(authData); //check for userPresent flag
        step11(authData); //check for userVerified flag
        step12(); //various checks on extensions in authData
        step13(); //check check fmt format
        step14(); // check attStmt signature
        step15(); //obtain trust anchors
        step16(); // assess the trustworthiness
        step17(authData); // check if credential not already in use
        step18(sensitiveUser, authData); // associate credential to user
        step19(); //check whether we want to fail based on invalid step 16 or not?

        return sensitiveUser;
    }

    private JsonNode step1(final JsonNode inputJson) throws RegistrationFailedException {
        System.out.println("User registration response: "+inputJson.toString());
        if(!inputJson.has("response") || !inputJson.get("response").has("attestationObject")){
            throw new RegistrationFailedException(1);
        }
        return inputJson.get("response");
    }

    private JsonNode step2(final JsonNode inputJson) throws RegistrationFailedException {
        try {
            return objectMapper.readTree(
                    new String(
                            base64UrlDecoder.decode(
                                    inputJson.get("response")
                                            .get("clientDataJSON").asText()),
                            Charset.forName("UTF-8")));
        } catch (IOException e) {
            throw new RegistrationFailedException(2);
        }
    }

    private void step3(final JsonNode decodedClientData) throws RegistrationFailedException {
        if(!decodedClientData.get("type").asText().equals("webauthn.create")){
            throw new RegistrationFailedException(3);
        }
    }

    private SensitiveUser step4(final JsonNode decodedClientData) throws RegistrationFailedException {
        Optional<SensitiveUser> sensitiveUserCheck =
                userRepository.getUserByChallengeAndRegistered(decodedClientData.get("challenge").asText(), false);
        if(!sensitiveUserCheck.isPresent()){
            throw new RegistrationFailedException(4);
        }
        return sensitiveUserCheck.get();
    }

    private void step5(JsonNode decodedClientData, SensitiveUser sensitiveUser) throws RegistrationFailedException {
        if(!(decodedClientData.get("origin").asText()).contains(sensitiveUser.getDomain())){
            throw new RegistrationFailedException(5);
        }
    }

    private void step6(JsonNode decodedClientData) throws RegistrationFailedException {
        if(!decodedClientData.has("tokenBinding")&&false){
            //well currently we don't check this.
            throw new RegistrationFailedException(6);
        }
    }

    private byte[] step7(JsonNode response) {
        return DigestUtils.sha256(response.get("clientDataJSON").asText());
    }

    private AuthData step8(JsonNode response) throws RegistrationFailedException {
        try {
          ObjectMapper cborMapper = new ObjectMapper(cborFactory);
          JsonNode attestationData =
              cborMapper.readTree(base64UrlDecoder.decode(response.get("attestationObject").asText()));
          return authenticatorDataParser.parseAttestationData(attestationData.get("authData").asText());
        } catch (IOException e) {
          throw new RegistrationFailedException(8);
        }
    }

    private void step9(AuthData authData) throws RegistrationFailedException {
        byte[] rpIdHash = DigestUtils.sha256("dev.webauthn.demo");
        if(!Arrays.equals(rpIdHash, authData.getRpIdHash())){
            throw new RegistrationFailedException(9);
        }
    }

    private void step10(AuthData authData) throws RegistrationFailedException {
        if(!authData.isUserPresentFlagSet()){
            throw new RegistrationFailedException(10);
        }
    }

    private void step11(AuthData authData) throws RegistrationFailedException {
        if(!authData.isUserVerifiedFlagSet()&&checkUserVerified){
            throw new RegistrationFailedException(11);
        }
    }

    private void step12() throws RegistrationFailedException {}

    private void step13() throws RegistrationFailedException {}

    private void step14() throws RegistrationFailedException {}

    private void step15() throws RegistrationFailedException {}

    private void step16() throws RegistrationFailedException {}

    private void step17(AuthData authData) throws RegistrationFailedException {
        if(userRepository.getUserByCredential(base64UrlEncoder.encodeToString(authData.getCredId())).isPresent() && failIfCredentialIsAlreadyInUse){
            throw new RegistrationFailedException(17);
        }
    }

    private void step18(SensitiveUser sensitiveUser, AuthData authData){
        sensitiveUser.setCredentialId(base64UrlEncoder.encodeToString(authData.getCredId()));
        sensitiveUser.setRegistered(true);
    }

    private void step19() throws RegistrationFailedException  {}

    private ObjectNode badRequestResponse(int step) {
        return objectMapper.createObjectNode().put("error", "Bad Request at step "+step);
    }

}
