package ch.bfh.ti.repository.user;

import ch.bfh.ti.repository.auth.AuthData;

public class SensitiveUser extends User {
    private boolean registered=false;
    private String id="";
    private String challenge ="";
    private String domain="";
    private String credentialId="";
    private String publicKey="";
    private AuthData authData;

    public SensitiveUser(){}

    public SensitiveUser(User user) {
        super(user);
    }

    public boolean isRegistered() {
        return registered;
    }

    public void setRegistered(boolean registered) {
        if(registered) {
            this.registered = registered;
        }
    }

    @Override
    public String toString() {
        return "SensitiveUser{" +
                "registered=" + registered +","+
                "id="+id+","+
                super.toString() +
                '}';
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public AuthData getAuthData() {
        return authData;
    }

    public void setAuthData(AuthData authData) {
        this.authData = authData;
    }
}
