package ch.bfh.ti.repository.user;

public class SensitiveUser extends User {
    private boolean registered=false;
    private String id="";
    private String challenge ="";
    private String domain="";
    private String credentialId="";

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
}
