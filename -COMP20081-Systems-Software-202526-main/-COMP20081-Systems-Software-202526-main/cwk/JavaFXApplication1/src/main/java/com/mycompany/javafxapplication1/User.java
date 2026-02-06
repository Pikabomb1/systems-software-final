/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.javafxapplication1;

import javafx.beans.property.SimpleStringProperty;

public class User {
    private SimpleStringProperty user;
    private SimpleStringProperty pass;
    private SimpleStringProperty role; // <--- NEW

    // Updated Constructor
    User(String user, String pass, String role) {
        this.user = new SimpleStringProperty(user);
        this.pass = new SimpleStringProperty(pass);
        this.role = new SimpleStringProperty(role);
    }

    public String getUser() { return user.get(); }
    public void setUser(String user) { this.user.set(user); }

    public String getPass() { return pass.get(); }
    public void setPass(String pass) { this.pass.set(pass); }

    // New Getters/Setters for Role
    public String getRole() { return role.get(); }
    public void setRole(String role) { this.role.set(role); }
}
