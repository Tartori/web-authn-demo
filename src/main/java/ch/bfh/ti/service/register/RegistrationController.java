package ch.bfh.ti.service.register;

import ch.bfh.ti.repository.auth.AuthData;
import ch.bfh.ti.repository.auth.AuthenticatorDataParser;
import ch.bfh.ti.repository.user.SensitiveUser;
import ch.bfh.ti.repository.user.User;
import ch.bfh.ti.repository.user.UserRepository;
import ch.bfh.ti.utils.Base64StringGenerator;
import ch.bfh.ti.utils.CertificateParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Hashtable;
import java.util.Optional;

@RestController
@RequestMapping(RegistrationController.RESOURCE)
public class RegistrationController {
    static final String RESOURCE = "/register";
    private static final int COSE_ALG_ECDSA_W_SHA256 = -7;
    private static final boolean failIfCredentialIsAlreadyInUse = true;
    private static final boolean checkUserVerified=false;
    private static final boolean checkTokenBinding=false;
    public static final String DOMAIN="dev.webauthn.demo";
    public static final String AAGUID_YUBIKEY_5="fa2b99dc9e3942578f924a30d23c4118";
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
        sensitiveUser.setDomain(DOMAIN);
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
                .put("alg", COSE_ALG_ECDSA_W_SHA256);
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
        step5(decodedClientData);//check origin
        step6(decodedClientData);//check token binding
        byte[] clientHash=step7(response.get("clientDataJSON")); //calculate client hash because why not?
        JsonNode attestationData = getAttestationData(response);
        AuthData authData = step8(attestationData); //perform CBOR decoding
        step9(authData); //check rpid hash to origin - hashed
        step10(authData); //check for userPresent flag
        step11(authData); //check for userVerified flag
        step12(authData); //various checks on extensions in authData
        step13(attestationData); //check check fmt format
        X509Certificate cert = getCertificate(attestationData);
        validateCert(cert);
        JsonNode sig = attestationData.get("attStmt").get("sig");
        step14(attestationData.get("authData"), attestationData.get("attStmt"), clientHash, cert); // check attStmt signature
        step15(authData.getAaguid()); // obtain trust anchors
        step16(cert); // assess the trustworthiness
        step17(authData); // check if credential not already in use
        step18(sensitiveUser, authData); // associate credential to user
        step19(); //check whether we want to fail based on invalid step 16 or not?

        return sensitiveUser;
    }

    private JsonNode step1(final JsonNode inputJson) throws RegistrationFailedException {
        System.out.println("User registration response: "+inputJson.toString());
        if(!inputJson.has("response")
                || !inputJson.get("response").has("attestationObject")
                || !inputJson.get("response").has("clientDataJSON")){
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

    private void step5(JsonNode decodedClientData) throws RegistrationFailedException {
        if(!(decodedClientData.get("origin").asText()).contains(DOMAIN)){
            throw new RegistrationFailedException(5);
        }
    }

    private void step6(JsonNode decodedClientData) throws RegistrationFailedException {
        if(!decodedClientData.has("tokenBinding")&&checkTokenBinding){
            //well currently we don't check this.
            throw new RegistrationFailedException(6);
        }
    }

    private byte[] step7(JsonNode clientData) {
        return DigestUtils.sha256(base64UrlDecoder.decode(clientData.asText()));
    }

    private JsonNode getAttestationData(JsonNode response) throws RegistrationFailedException {
        try {
            ObjectMapper cborMapper = new ObjectMapper(cborFactory);
            return cborMapper.readTree(base64UrlDecoder.decode(response.get("attestationObject").asText()));
        } catch (IOException e) {
            throw new RegistrationFailedException(8);
        }
    }

    private AuthData step8(JsonNode attestationData){
          return authenticatorDataParser.parseAttestationData(attestationData.get("authData").asText());
    }

    private void step9(AuthData authData) throws RegistrationFailedException {
        byte[] rpIdHash = DigestUtils.sha256(DOMAIN);
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

    private void step12(AuthData authData) throws RegistrationFailedException {
        if(authData.isExtensionDataIncludedFlagSet()){
            throw new RegistrationFailedException(12);
        }
    }

    private void step13(JsonNode attestationData) throws RegistrationFailedException {
        if(!attestationData.get("fmt").asText().equals("packed")){//should be extended to a list of values that are permitted
            throw new RegistrationFailedException(13);
        }
    }

    private X509Certificate getCertificate(JsonNode attestationData) throws RegistrationFailedException{
        X509Certificate certificate;
        try {
            Optional<X509Certificate> x509CertificateOptional = certificateParser.getX5cAttestationCert(attestationData.get("attStmt"));
            if(!x509CertificateOptional.isPresent()){
                throw new RegistrationFailedException(14);
            }
            certificate=x509CertificateOptional.get();
        } catch (CertificateException e) {
            throw new RegistrationFailedException(14);
        }
        return certificate;
    }

    private void validateCert(X509Certificate cert) throws RegistrationFailedException{
        if(cert.getVersion()!=3){
            throw new RegistrationFailedException(14);
        }
        Hashtable<String, String> dn = splitDn(cert.getSubjectDN().getName());

        if(!(dn.containsKey("C")&&dn.containsKey("O")&&dn.containsKey("OU")&&dn.containsKey("CN"))){
            throw new RegistrationFailedException(14);
        }
        if(!(dn.get("C").equals("SE")&&dn.get("O").equals("Yubico AB")&&dn.get("OU").equals("Authenticator Attestation")&&dn.get("CN").contains("Yubico U2F EE Serial"))){
            throw new RegistrationFailedException(14);
        }
        if(cert.getBasicConstraints()>=0){
            throw new RegistrationFailedException(14);
        }
    }

    private Hashtable<String, String> splitDn(String dn){
        Hashtable<String, String> table = new Hashtable<>();
        for (String part : dn.split(",")) {
            String[] kv = part.split("=");
            table.put(kv[0],kv[1]);
        }
        return table;
    }

    private void step14(JsonNode authDataBin, JsonNode attStatement, byte[] clientDataHash, X509Certificate cert) throws RegistrationFailedException {
        JsonNode sig = attStatement.get("sig");
        final String signatureAlgorithmName = "SHA256withECDSA";
        try {
            byte[] signedData = ArrayUtils.addAll(authDataBin.binaryValue(), clientDataHash);
            Signature signatureVerifier = Signature.getInstance(signatureAlgorithmName, bouncyCastleProvider);
            signatureVerifier.initVerify(cert.getPublicKey());
            signatureVerifier.update(signedData);
            if(!signatureVerifier.verify(sig.binaryValue())){
                throw new RegistrationFailedException(14);
            }
        }  catch (Exception e) {
            throw new RegistrationFailedException(14);
        }
    }

    private void step15(byte[] aaguid) throws RegistrationFailedException {
        String aaguidHex =  Hex.encodeHexString(aaguid);
        if(!aaguidHex.equals(AAGUID_YUBIKEY_5)){
            throw new RegistrationFailedException(15);
        }
    }

    private void step16(X509Certificate cert) throws RegistrationFailedException {
        try {
            String fidoU2F=
                    "MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ" +
                    "dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw" +
                    "MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290" +
                    "IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK" +
                    "AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk" +
                    "5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep" +
                    "8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw" +
                    "nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT" +
                    "9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw" +
                    "LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ" +
                    "hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN" +
                    "BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4" +
                    "MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt" +
                    "hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k" +
                    "LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U" +
                    "sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc" +
                    "U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==";
            byte[] decoded = Base64.getDecoder().decode(fidoU2F);
            X509Certificate root = certificateParser.parseDer(decoded);
            cert.verify(root.getPublicKey());
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            throw new RegistrationFailedException(16);
        }

    }

    private X509Certificate decodeStringCert(String cert) throws CertificateException {
        byte[] decoded = Base64.getDecoder().decode(cert);
        return  certificateParser.parseDer(decoded);
    }

    private void step17(AuthData authData) throws RegistrationFailedException {
        if(userRepository.getUserByCredential(base64UrlEncoder.encodeToString(authData.getCredId())).isPresent() && failIfCredentialIsAlreadyInUse){
            throw new RegistrationFailedException(17);
        }
    }

    private void step18(SensitiveUser sensitiveUser, AuthData authData){
        sensitiveUser.setCredentialId(base64UrlEncoder.encodeToString(authData.getCredId()));
        sensitiveUser.setPublicKey(base64UrlEncoder.encodeToString(authData.getCOSEPublicKey()));
        sensitiveUser.setAuthData(authData);
        sensitiveUser.setChallenge("");
        sensitiveUser.setRegistered(true);
    }

    private void step19() throws RegistrationFailedException  {}

    private ObjectNode badRequestResponse(int step) {
        return objectMapper.createObjectNode().put("error", "Bad Request at step "+step);
    }

}
