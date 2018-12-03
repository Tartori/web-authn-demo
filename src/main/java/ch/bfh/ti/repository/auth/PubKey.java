package ch.bfh.ti.repository.auth;

import com.upokecenter.cbor.CBORObject;

public class PubKey {
    private byte[] cosePubKey;

    public PubKey(byte[] cosePubKey){
        this.cosePubKey=cosePubKey;
    }

    public byte[] getCosePubKey() {
        return cosePubKey;
    }

    public byte[] getXValue(){
        return CBORObject.DecodeFromBytes(cosePubKey).get(CBORObject.FromObject(-2)).EncodeToBytes();
    }
    public byte[] getYValue(){
        return CBORObject.DecodeFromBytes(cosePubKey).get(CBORObject.FromObject(-3)).EncodeToBytes();
    }
    public byte[] getType(){
        return CBORObject.DecodeFromBytes(cosePubKey).get(CBORObject.FromObject(3)).EncodeToBytes();
    }
    public byte[] getCrv(){
        return CBORObject.DecodeFromBytes(cosePubKey).get(CBORObject.FromObject(-1)).EncodeToBytes();
    }
    public byte[] getAlg(){
        return CBORObject.DecodeFromBytes(cosePubKey).get(CBORObject.FromObject(1)).EncodeToBytes();
    }
}
