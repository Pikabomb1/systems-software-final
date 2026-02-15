
 
 
 
package com.mycompany.javafxapplication1;

import javafx.beans.property.SimpleStringProperty;

public class User {
    private SimpleStringProperty user;
    private SimpleStringProperty pass;
    private SimpleStringProperty role; 

    // Constructor
    User(String user, String pass, String role) {
        this.user = new SimpleStringProperty(user);
        this.pass = new SimpleStringProperty(pass);
        this.role = new SimpleStringProperty(role);
    }

    public String getUser() { return user.get(); }
    public void setUser(String user) { this.user.set(user); }

    public String getPass() { return pass.get(); }
    public void setPass(String pass) { this.pass.set(pass); }

    // Getters/Setters for Role
    public String getRole() { return role.get(); }
    public void setRole(String role) { this.role.set(role); }
}
