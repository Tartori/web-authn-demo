package ch.bfh.ti.repository.auth;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthenticatorDataParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticatorDataParser.class);
    @Autowired
    private Base64.Decoder base64UrlDecoder;

    private Base64.Decoder base64Decoder = Base64.getDecoder();

    public AuthData parseAttestationData(String incomingAuthData){
        return parse(incomingAuthData, true);
    }

    public AuthData parseAssertionData(String incomingAuthData) {
        return parse(incomingAuthData, false);
    }

    private AuthData parse(String incomingAuthData, boolean isAttestation){
        AuthData authData = new AuthData();
        authData.setAuthDataEncoded(incomingAuthData.getBytes());
        byte[] buffer;

        if (isAttestation)
            buffer = base64Decoder.decode(incomingAuthData.getBytes());
        else {
            buffer = base64UrlDecoder.decode(incomingAuthData.getBytes());
        }
        authData.setAuthDataDecoded(buffer.clone());
        int offset = 0;
        authData.setRpIdHash(Arrays.copyOfRange(buffer, offset, offset+=32));
        authData.setFlagsBuf(Arrays.copyOfRange(buffer, offset, offset+=1));
        authData.setCounters(Arrays.copyOfRange(buffer, offset, offset+=4));
        if(authData.isAttestedCredentialDataFlagSet()){
            authData.setAaguid(Arrays.copyOfRange(buffer, offset, offset+=16));
            short credLength = ByteBuffer.wrap(Arrays.copyOfRange(buffer, offset, offset+=2)).asShortBuffer().get();
            authData.setCredId(Arrays.copyOfRange(buffer, offset, offset+=credLength));
            authData.setCOSEPublicKey(Arrays.copyOfRange(buffer, offset, buffer.length));
            authData.setKeyType(-7);//todo read that out of the buffer, magically.
        }
        return authData;
    }
}

