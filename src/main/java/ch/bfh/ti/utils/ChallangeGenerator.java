package ch.bfh.ti.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

@Service
public class ChallangeGenerator {
    @Autowired
    Base64.Encoder base64UrlEncoder;

    public String generateNewChallange(){
        byte[] buf= new byte[32];
        new SecureRandom().nextBytes(buf);
        return base64UrlEncoder.encodeToString(buf);
    }
}
