package ch.bfh.ti.repository.user;

public class SensitiveUser extends User {
    private boolean registered=false;
    private String id="";
    private String challenge ="";


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
}
