package ch.bfh.ti.service.register;

public class RegistrationFailedException extends Exception {
    private int step;
    public RegistrationFailedException(int step){
        this.step=step;
    }

    public int getStep() {
        return step;
    }
}
