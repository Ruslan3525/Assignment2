package kz.kalybayevv.Application.controllers.userController;


public class User {
    private int id;
    private String username;
    private String password;
    private String role;
    private String first_name;
    private String last_name;

    public User() {

    }

    public User(int id, String username, String password, String role, String first_name, String last_name) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.role = role;
        this.first_name = first_name;
        this.last_name = last_name;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getFirst_name() {
        return first_name;
    }

    public void setFirst_name(String first_name) {
        this.first_name = first_name;
    }

    public String getLast_name() {
        return last_name;
    }

    public void setLast_name(String last_name) {
        this.last_name = last_name;
    }
}
