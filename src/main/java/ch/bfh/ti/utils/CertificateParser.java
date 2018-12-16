package ch.bfh.ti.utils;

import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
public class CertificateParser {

    private final static List<String> FIXSIG = Arrays.asList(
            "CN=Yubico U2F EE Serial 776137165",
            "CN=Yubico U2F EE Serial 1086591525",
            "CN=Yubico U2F EE Serial 1973679733",
            "CN=Yubico U2F EE Serial 13503277888",
            "CN=Yubico U2F EE Serial 13831167861",
            "CN=Yubico U2F EE Serial 14803321578"
    );

    private static final int UNUSED_BITS_BYTE_INDEX_FROM_END = 257;

    @Autowired
    private BouncyCastleProvider bouncyCastleProvider;


    public Optional<X509Certificate> getX5cAttestationCert(JsonNode attStmt) throws CertificateException {
        JsonNode x5cNode = attStmt.get("x5c");

        if (x5cNode != null && x5cNode.isArray()) {
            List<X509Certificate> certs = new ArrayList<>(x5cNode.size());

            for (JsonNode binary : x5cNode) {
                if (binary.isBinary()) {
                    try {
                        certs.add(parseDer(binary.binaryValue()));
                    } catch (IOException e) {
                        throw new RuntimeException("binary.isBinary() was true but binary.binaryValue() failed", e);
                    }
                } else {
                    throw new IllegalArgumentException(String.format(
                            "Each element of \"x5c\" property of attestation statement must be a binary value, was: %s",
                            binary.getNodeType()
                    ));
                }
            }

            return Optional.of(certs.get(0));
        } else {
            return Optional.empty();
        }
    }

    public X509Certificate parseDer(byte[] in) throws CertificateException {
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509", bouncyCastleProvider).generateCertificate(new ByteArrayInputStream(in));
        //Some known certs have an incorrect "unused bits" value, which causes problems on newer versions of BouncyCastle.
        if(FIXSIG.contains(cert.getSubjectDN().getName())) {
            byte[] encoded = cert.getEncoded();

            if (encoded.length >= UNUSED_BITS_BYTE_INDEX_FROM_END) {
                encoded[encoded.length - UNUSED_BITS_BYTE_INDEX_FROM_END] = 0;  // Fix the "unused bits" field (should always be 0).
            } else {
                throw new IllegalArgumentException(String.format(
                        "Expected DER encoded cert to be at least %d bytes, was %d: %s",
                        UNUSED_BITS_BYTE_INDEX_FROM_END,
                        encoded.length,
                        cert
                ));
            }

            cert = (X509Certificate) CertificateFactory.getInstance("X.509", bouncyCastleProvider).generateCertificate(new ByteArrayInputStream(encoded));
        }
        return cert;
    }
}
