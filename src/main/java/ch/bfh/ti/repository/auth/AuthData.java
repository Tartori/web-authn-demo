package ch.bfh.ti.repository.auth;

import java.nio.ByteBuffer;

public class AuthData {
    public static final int ED_FLAG = 0x80;
    public static final int AT_FLAG = 0x40;
    public static final int UV_FLAG = 0x04;
    public static final int UP_FLAG = 0x01;

    private byte[] rpIdHash;
    private byte[] flagsBuf;
    private byte flags;
    private byte[] counters;
    private byte[] aaguid;
    private byte[] credId;
    private byte[] signatureBaseFields;
    private byte[] attestationBuffer;
    private int keyType;
    private byte[] authDataDecoded;
    private byte[] authDataEncoded;

    public byte[] getRpIdHash() {
        return rpIdHash;
    }

    public AuthData setRpIdHash(byte[] rpIdHash) {
        this.rpIdHash = rpIdHash;
        return this;
    }

    public byte[] getFlagsBuf() {
        return flagsBuf;
    }

    public AuthData setFlagsBuf(byte[] flagsBuf) {
        this.flagsBuf = flagsBuf;
        return this;
    }

    public byte[] getCounters() {
        return counters;
    }

    public AuthData setCounters(byte[] counters) {
        this.counters = counters;
        return this;
    }

    public long getCounter(){
        //in the buffer is an unsigned int... that's why we use a long
        return ByteBuffer.wrap(getCounters()).asLongBuffer().get();
    }

    public byte[] getAaguid() {
        return aaguid;
    }

    public AuthData setAaguid(byte[] aaguid) {
        this.aaguid = aaguid;
        return this;
    }

    public byte[] getCredId() {
        return credId;
    }

    public AuthData setCredId(byte[] credId) {
        this.credId = credId;
        return this;
    }

    public byte[] getCOSEPublicKey() {
        return COSEPublicKey;
    }

    public AuthData setCOSEPublicKey(byte[] COSEPublicKey) {
        this.COSEPublicKey = COSEPublicKey;
        return this;
    }

    private byte[] COSEPublicKey;

    public byte[] getAttestationBuffer() {
        return attestationBuffer;
    }

    public void setAttestationBuffer(byte[] attestationBuffer) {
        this.attestationBuffer = attestationBuffer;
    }

    public int getKeyType() {
        return keyType;
    }

    public void setKeyType(int keyType) {
        this.keyType = keyType;
    }

    public byte[] getAuthDataDecoded() {
        return authDataDecoded;
    }

    public void setAuthDataDecoded(byte[] authDataDecoded) {
        this.authDataDecoded = authDataDecoded;
    }

    public boolean isAttestedCredentialDataFlagSet(){
        return (flagsBuf[0]&AT_FLAG)==AT_FLAG;
    }
    public boolean isUserPresentFlagSet(){
        return (flagsBuf[0]&UP_FLAG)==UP_FLAG;
    }
    public boolean isUserVerifiedFlagSet(){
        return (flagsBuf[0]&UV_FLAG)==UV_FLAG;
    }
    public boolean isExtensionDataIncludedFlagSet(){
        return (flagsBuf[0]&ED_FLAG)==ED_FLAG;
    }

    public PubKey getPubKey(){
        return new PubKey(getCOSEPublicKey());
    }

    public byte getFlags() {
        return flagsBuf[0];
    }

    public byte[] getAuthDataEncoded() {
        return authDataEncoded;
    }

    public void setAuthDataEncoded(byte[] authDataEncoded) {
        this.authDataEncoded = authDataEncoded;
    }
}
