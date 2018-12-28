package ch.bfh.ti.service.login;

import ch.bfh.ti.repository.auth.AuthData;
import ch.bfh.ti.repository.auth.AuthenticatorDataParser;
import ch.bfh.ti.repository.user.SensitiveUser;
import ch.bfh.ti.repository.user.UserRepository;
import ch.bfh.ti.utils.Base64StringGenerator;
import ch.bfh.ti.utils.CertificateParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Optional;

@RestController
@RequestMapping(LoginControler.RESOURCE)
public class LoginControler {

    static final String RESOURCE = "/login";
    private static final String UserName = "/{username}";
    private static final int COSE_ALG_ECDSA_W_SHA256 = -7;
    private static final boolean checkUserVerified=false;
    private static final boolean checkTokenBinding=false;

    @Autowired
    private AuthenticatorDataParser authenticatorDataParser;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private Base64StringGenerator base64StringGenerator;
    @Autowired
    private Base64.Decoder base64UrlDecoder;
    @Autowired
    private Base64.Encoder base64UrlEncoder;
    @Autowired
    private CBORFactory cborFactory;
    @Autowired
    private CertificateParser certificateParser;
    @Autowired
    private BouncyCastleProvider bouncyCastleProvider;

    @PostMapping
    public ObjectNode create(@RequestBody final JsonNode input) {
        if(!input.hasNonNull("username")){
            return badRequestResponse(0);
        }
        String userName = input.get("username").asText();
        if(userName.isEmpty()){
            System.out.println("create didn't work: "+userName);
            return badRequestResponse(0);
        }
        Optional<SensitiveUser> maybeUser = userRepository.getUserByUsername(userName);
        if(!maybeUser.isPresent()){
            return badRequestResponse(0);
        }
        SensitiveUser sensitiveUser = maybeUser.get();
        if(!sensitiveUser.isRegistered()){
            return badRequestResponse(0);
        }
        sensitiveUser.setChallenge(base64StringGenerator.generateNewString());
        ObjectNode node = objectMapper
                .createObjectNode()
                .putObject("publicKey");
        node.put("challenge", sensitiveUser.getChallenge());
        node.put("rpId", sensitiveUser.getDomain());
        node.putArray("allowCredentials")
                .addObject()
                .put("type", "public-key")
                .put("id", sensitiveUser.getCredentialId());
        node.putObject("extensions").put("appId", "https://"+sensitiveUser.getDomain());
        node.put("userVerification", "preferred");
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
            sensitiveUser = performLoginSteps(inputJson);
        }catch (LoginFailedException ex){
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

    private SensitiveUser performLoginSteps(final JsonNode inputJson)
      throws LoginFailedException {
        if(!inputJson.hasNonNull("response")){
            throw new LoginFailedException(0);
        }
        JsonNode response = inputJson.get("response");
        SensitiveUser user = step1(inputJson);
        step2(response, user);
        String publicKey=step3(user);
        String cData = step4(response, "clientDataJSON");
        String authData = step4(response, "authenticatorData");
        String sig = step4(response, "signature");
        JsonNode decodedClientData = step5and6(cData);
        step7(decodedClientData);
        step8(decodedClientData,user);
        step10(decodedClientData);
        AuthData authDataParsed = step11(authData);
        step8(decodedClientData,user);
        return user;
    }

    private SensitiveUser step1(final JsonNode inputJson) throws LoginFailedException {
        Optional<SensitiveUser> optionalSensitiveUser =  userRepository.getUserByCredential(inputJson.get("id").asText());
        if(!optionalSensitiveUser.isPresent()){
            throw new LoginFailedException(1);
        }
        SensitiveUser user = optionalSensitiveUser.get();
        if(!user.isRegistered()||user.getChallenge().isEmpty()){
            throw new LoginFailedException(1);
        }
        return user;
    }

    private void step2(final JsonNode response, final SensitiveUser user) throws LoginFailedException {
        if(!response.hasNonNull("userHandle")){
            return;
        }
        String userHandle=response.get("userHandle").asText();
        if(userHandle.isEmpty()){
            return;
        }
        if(!userHandle.equals(user.getUsername())){
            throw new LoginFailedException(2);
        }
    }

    private String step3(final SensitiveUser user) throws LoginFailedException {
        return user.getPublicKey();
    }

    private String step4(final JsonNode response, String fieldName) throws LoginFailedException {
        if(!response.hasNonNull(fieldName)){
            throw new LoginFailedException(4);
        }
        return response.get(fieldName).asText();
    }

    private JsonNode step5and6(final String cData) throws LoginFailedException {
        try {
            return objectMapper.readTree(
                    new String(
                            base64UrlDecoder.decode(cData),
                            Charset.forName("UTF-8")));
        } catch (IOException e) {
            throw new LoginFailedException(2);
        }
    }

    private void step7(JsonNode clientData) throws LoginFailedException {
        if(!clientData.get("type").asText().equals("webauthn.get")){
            throw new LoginFailedException(7);
        }
    }

    private void step8(JsonNode clientData, SensitiveUser user) throws LoginFailedException{
        if(!clientData.get("challenge").asText().equals(user.getChallenge())){
            throw new LoginFailedException(8);
        }
    }

    private void step9(JsonNode clientData, SensitiveUser user) throws LoginFailedException{
        if(!clientData.get("origin").asText().contains(user.getDomain())){
            throw new LoginFailedException(9);
        }
    }
    private void step10(JsonNode clientData) throws LoginFailedException{
        if(!clientData.has("tokenBinding")&&checkTokenBinding){
            //well currently we don't check this.
            throw new LoginFailedException(10);
        }
    }
    private AuthData step11(String authData) throws LoginFailedException{
        return authenticatorDataParser.parseAssertionData(authData);
    }
    private void step12(JsonNode clientData, SensitiveUser user) throws LoginFailedException{

    }
    private void step13(JsonNode clientData, SensitiveUser user) throws LoginFailedException{

    }
    private void step14(JsonNode clientData, SensitiveUser user) throws LoginFailedException{

    }
    private void step15(JsonNode clientData, SensitiveUser user) throws LoginFailedException{

    }
    private void step16(JsonNode clientData, SensitiveUser user) throws LoginFailedException{

    }
    private void step17(JsonNode clientData, SensitiveUser user) throws LoginFailedException{

    }
    private void step18(JsonNode clientData, SensitiveUser user) throws LoginFailedException{

    }

    private ObjectNode badRequestResponse(int step) {
        return objectMapper.createObjectNode().put("error", "Bad Request at step "+step);
    }
}
