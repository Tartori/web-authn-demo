package ch.bfh.ti.service.login;

import ch.bfh.ti.repository.auth.AuthData;
import ch.bfh.ti.repository.auth.AuthenticatorDataParser;
import ch.bfh.ti.repository.user.SensitiveUser;
import ch.bfh.ti.repository.user.UserRepository;
import ch.bfh.ti.service.register.RegistrationController;
import ch.bfh.ti.utils.Base64StringGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.upokecenter.cbor.CBORObject;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.*;
import java.util.*;

@RestController
@RequestMapping(LoginControler.RESOURCE)
public class LoginControler {

    static final String RESOURCE = "/login";
    private static final String UserName = "/{username}";
    private static final int COSE_ALG_ECDSA_W_SHA256 = -7;
    private static final boolean checkUserVerified=false;
    private static final boolean checkTokenBinding=false;

    private Hashtable<String, JsonNode> assertions = new Hashtable<>();

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
        node.put("timeout", 60*1000);
        node.put("errorMessage", "");
        node.put("status", "ok");
        userRepository.updateUser(sensitiveUser);
        System.out.println("User login request sent: "+node.toString());
        assertions.put(userName, node);
        return node;
    }

    @PostMapping(path = "/response")
    public ObjectNode response(@RequestBody final JsonNode inputJson) {
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
        SensitiveUser user = step1(inputJson); //retrieve user and check credential id
        step2(response, user); //check userhandle
        String publicKey=step3(user); // retrieve pk
        String cData = step4(response, "clientDataJSON"); //parse clientdatajson
        String authData = step4(response, "authenticatorData"); //parse authenticator data
        String sig = step4(response, "signature"); //parse signature
        JsonNode decodedClientData = step5and6(cData); //decode client data
        step7(decodedClientData); // check type = webauthn.get
        step8(decodedClientData,user); // check challenge
        step9(decodedClientData); // check origin
        step10(decodedClientData); // check token binding
        AuthData authDataParsed = getAuthData(authData); //parse authenticator data
        step11(authDataParsed); // check rpid hash
        step12(authDataParsed); //check user present
        step13(authDataParsed); //check user verified
        step14(authDataParsed); //check extensions
        byte[] clientHash = step15(cData); //hash client data
        step16(publicKey, authData, clientHash, sig); //check signature
        step17(authDataParsed, user); //check sign count and update.
        return user;
    }

    private SensitiveUser step1(final JsonNode inputJson) throws LoginFailedException {
        Optional<SensitiveUser> optionalSensitiveUser =  userRepository.getUserByCredential(inputJson.get("id").asText());
        if(!optionalSensitiveUser.isPresent()){
            throw new LoginFailedException(1);
        }
        SensitiveUser user = optionalSensitiveUser.get();
        if(!user.isRegistered()||user.getChallenge().isEmpty()||!assertions.containsKey(user.getUsername())){
                throw new LoginFailedException(1);
        }
        JsonNode assertion = assertions.get(user.getUsername());
        assertions.remove(user.getUsername());
        if(!assertion.get("allowCredentials").get(0).get("id").asText().equals(inputJson.get("id").asText())){
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

    private void step9(JsonNode clientData) throws LoginFailedException{
        if(!clientData.get("origin").asText().contains(RegistrationController.DOMAIN)){
            throw new LoginFailedException(9);
        }
    }

    private void step10(JsonNode clientData) throws LoginFailedException{
        if(!clientData.has("tokenBinding")&&checkTokenBinding){
            //well currently we don't check this.
            throw new LoginFailedException(10);
        }
    }

    private AuthData getAuthData(String authData){
        return authenticatorDataParser.parseAssertionData(authData);
    }

    private void step11(AuthData authData) throws LoginFailedException{
        byte[] rpIdHash = DigestUtils.sha256(RegistrationController.DOMAIN);
        if(!Arrays.equals(rpIdHash, authData.getRpIdHash())){
            throw new LoginFailedException(11);
        }
    }

    private void step12(AuthData authData) throws LoginFailedException {
        if(!authData.isUserPresentFlagSet()){
            throw new LoginFailedException(12);
        }
    }

    private void step13(AuthData authData) throws LoginFailedException {
        if(!authData.isUserVerifiedFlagSet()&&checkUserVerified){
            throw new LoginFailedException(13);
        }
    }

    private void step14(AuthData authData) throws LoginFailedException{
        if (authData.isExtensionDataIncludedFlagSet()) {
            throw new LoginFailedException(14);
        }
    }

    private byte[] step15(String clientData) {
        return DigestUtils.sha256(base64UrlDecoder.decode(clientData));
    }

    private void step16(String cosePublicKey, String authDataBin, byte[] clientDataHash, String sig) throws LoginFailedException{
        final String signatureAlgorithmName = "SHA256withECDSA";

        try {
            PublicKey publicKey = getPublicKey(cosePublicKey);
            byte[] signedData = ArrayUtils.addAll(base64UrlDecoder.decode(authDataBin), clientDataHash);
            Signature signatureVerifier = Signature.getInstance(signatureAlgorithmName, bouncyCastleProvider);
            signatureVerifier.initVerify(publicKey);
            signatureVerifier.update(signedData);
            if(!signatureVerifier.verify(base64UrlDecoder.decode(sig))){
                throw new LoginFailedException(16);
            }
        } catch (IOException | SignatureException | InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException | InvalidParameterSpecException e) {
            throw new LoginFailedException(16);
        }
    }

    private String cborToJsonString(String cosePublicKey){
        return CBORObject.DecodeFromBytes(base64UrlDecoder.decode(cosePublicKey)).ToJSONString();
    }

    private PublicKey getPublicKey(String cosePublicKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidParameterSpecException, IOException {
        JsonNode jsonPublicKey = objectMapper.readTree(cborToJsonString(cosePublicKey));

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = parameters.getParameterSpec(ECParameterSpec.class);
        BigInteger x = new BigInteger(1,base64UrlDecoder.decode(jsonPublicKey.get("-2").asText()));
        BigInteger y = new BigInteger(1,base64UrlDecoder.decode(jsonPublicKey.get("-3").asText()));
        final ECPoint w = new ECPoint(x, y);
        final ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, params);

        final KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(ecPublicKeySpec);
    }

    private void step17(AuthData authData, SensitiveUser user) throws LoginFailedException{
        if(authData.getSignCount().compareTo(user.getAuthData().getSignCount())<1){
            throw new LoginFailedException(17);
        }
        user.setAuthData(authData);
    }

    private void step18(JsonNode clientData, SensitiveUser user) throws LoginFailedException{

    }

    private ObjectNode badRequestResponse(int step) {
        return objectMapper.createObjectNode().put("error", "Bad Request at step "+step);
    }
}
