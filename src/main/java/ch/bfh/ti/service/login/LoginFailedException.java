package ch.bfh.ti.service.login;

public class LoginFailedException extends Exception {
    private int step;
    public LoginFailedException(int step){
        this.step=step;
    }

    public int getStep() {
        return step;
    }
}
