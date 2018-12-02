package ch.bfh.ti.repository.user;

import java.util.Objects;

public class User{
    private String username;
    private String name="";

    public User(){

    }
    public User(User user){
        this.username=user.getUsername();
        this.name=user.getName();
    }

    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                ", name='" + name + '\'' +
                '}';
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        if(!name.isEmpty()) {
            this.name = name;
        }
    }

    public User getStrippedUser(){
        User user = new User();
        user.setUsername(this.getUsername());
        user.setName(this.getName());
        return user;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(username, user.username) &&
                Objects.equals(name, user.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, name);
    }
}
