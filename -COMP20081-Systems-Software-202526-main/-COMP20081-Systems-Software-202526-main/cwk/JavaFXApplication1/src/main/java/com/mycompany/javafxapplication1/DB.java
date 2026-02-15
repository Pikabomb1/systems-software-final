package com.mycompany.javafxapplication1;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Scanner;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;
import java.util.HashMap;
import java.util.Map;
import com.mycompany.javafxapplication1.SecondaryController.MyFile; // Import MyFile

public class DB {
    
    private static final String SQLITE_URL = "jdbc:sqlite:comp20081.db";
    // NOTE: Use "comp20081-mysql" if inside VM, "localhost" if outside
    private static final String MYSQL_URL = "jdbc:mysql://comp20081-mysql:3306/comp20081_cloud?allowPublicKeyRetrieval=true&useSSL=false";
    private static final String MYSQL_USER = "root";
    private static final String MYSQL_PASS = "rootpassword";

    private Random random = new SecureRandom();
    private String characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private int iterations = 10000;
    private int keylength = 256;
    private String saltValue;

    public DB() {
        initSalt();
        initTables();
    }

    private Connection getRemoteConnection() throws SQLException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            return DriverManager.getConnection(MYSQL_URL, MYSQL_USER, MYSQL_PASS);
        } catch (ClassNotFoundException e) {
            throw new SQLException("MySQL Driver not found", e);
        }
    }

    private Connection getLocalConnection() throws SQLException {
        return DriverManager.getConnection(SQLITE_URL);
    }

    private void initTables() {
        // 1. Remote MySQL: Users and Files
        try (Connection conn = getRemoteConnection(); Statement stmt = conn.createStatement()) {
            // Users Table
            String sqlUser = "CREATE TABLE IF NOT EXISTS Users (" +
                         "id INT PRIMARY KEY AUTO_INCREMENT, " +
                         "name VARCHAR(255) UNIQUE, " +
                         "password VARCHAR(255), " +
                         "role VARCHAR(50))";
            stmt.executeUpdate(sqlUser);
            
            // Files Table (Stores Metadata + Permissions)
            String sqlFiles = "CREATE TABLE IF NOT EXISTS Files (" +
                         "id INT PRIMARY KEY AUTO_INCREMENT, " +
                         "filename VARCHAR(255), " +
                         "owner VARCHAR(255), " +
                         "size VARCHAR(50), " +
                         "permissions TEXT)"; // Stores "User1:READ,User2:WRITE"
            stmt.executeUpdate(sqlFiles);
            
        } catch (SQLException e) {
            System.err.println("[Remote] Error initializing MySQL: " + e.getMessage());
        }

        // 2. Local SQLite
        try (Connection conn = getLocalConnection(); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS Session (" +
                               "id INTEGER PRIMARY KEY, " +
                               "username TEXT, " +
                               "role TEXT, " +
                               "login_time DATETIME DEFAULT CURRENT_TIMESTAMP)");
            
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS CachedUsers (" +
                               "name TEXT PRIMARY KEY, " +
                               "role TEXT)");
        } catch (SQLException e) {
            System.err.println("[Local] Error initializing SQLite: " + e.getMessage());
        }
    }

    // --- FILE MANAGEMENT  ---

    public void addFile(String filename, String owner, String size) {
        try (Connection conn = getRemoteConnection()) {
            String sql = "INSERT INTO Files (filename, owner, size, permissions) VALUES (?, ?, ?, ?)";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, filename);
            pstmt.setString(2, owner);
            pstmt.setString(3, size);
            pstmt.setString(4, ""); // Empty permissions initially
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void deleteFile(String filename) {
        try (Connection conn = getRemoteConnection()) {
            String sql = "DELETE FROM Files WHERE filename = ?";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, filename);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void updateFilePermissions(String filename, String permString) {
        try (Connection conn = getRemoteConnection()) {
            String sql = "UPDATE Files SET permissions = ? WHERE filename = ?";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, permString);
            pstmt.setString(2, filename);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public ObservableList<MyFile> getAllFiles() {
        ObservableList<MyFile> files = FXCollections.observableArrayList();
        try (Connection conn = getRemoteConnection()) {
            String sql = "SELECT * FROM Files";
            ResultSet rs = conn.createStatement().executeQuery(sql);
            
            while (rs.next()) {
                String name = rs.getString("filename");
                String owner = rs.getString("owner");
                String size = rs.getString("size");
                String permStr = rs.getString("permissions");
                
                // Create File Object (Start with 1.0 progress as these are existing files)
                MyFile f = new MyFile(name, owner, size, 1.0);
                
                // Parse Permissions (Format: "Bob:READ,Alice:WRITE")
                if (permStr != null && !permStr.isEmpty()) {
                    String[] pairs = permStr.split(",");
                    for (String pair : pairs) {
                        String[] kv = pair.split(":");
                        if (kv.length == 2) {
                            f.addPermission(kv[0], kv[1]);
                        }
                    }
                }
                files.add(f);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return files;
    }

    // --- USER MANAGEMENT ---

     /**
     * Registers a new user.
     * Returns true if successful, false if username exists.
     */
    public boolean registerUser(String user, String password) {
        try (Connection conn = getRemoteConnection()) {
            // Check if table is empty to assign Admin role
            Statement countStmt = conn.createStatement();
            ResultSet rs = countStmt.executeQuery("SELECT COUNT(*) FROM Users");
            rs.next();
            String role = (rs.getInt(1) == 0) ? "admin" : "standard";

            // Attempt to insert
            String sql = "INSERT INTO Users (name, password, role) VALUES (?, ?, ?)";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user);
            pstmt.setString(2, generateSecurePassword(password));
            pstmt.setString(3, role);
            pstmt.executeUpdate();
            
            syncUsers(); // Update local cache
            
            // LOGGING
            logAction(user, "REGISTER", "New user registered as " + role);
            
            return true; // SUCCESS

        } catch (java.sql.SQLIntegrityConstraintViolationException e) {
            // This specific error means "Duplicate User"
            System.out.println("[WARN] Registration failed: Username '" + user + "' already exists.");
            return false; // FAILED (Duplicate)
            
        } catch (Exception e) {
            e.printStackTrace();
            return false; // FAILED (Other error)
        }
    }

    public boolean login(String user, String pass) {
        try (Connection conn = getRemoteConnection()) {
            String sql = "SELECT password, role FROM Users WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                String storedHash = rs.getString("password");
                if (storedHash.equals(generateSecurePassword(pass))) {
                    createLocalSession(user, rs.getString("role"));
                    return true;
                }
            }
        } catch (Exception e) { e.printStackTrace(); }
        return false;
    }

    private void createLocalSession(String user, String role) {
        try (Connection conn = getLocalConnection()) {
            conn.createStatement().executeUpdate("DELETE FROM Session");
            String sql = "INSERT INTO Session (username, role) VALUES (?, ?)";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, user); pstmt.setString(2, role);
            pstmt.executeUpdate();
        } catch (SQLException e) { e.printStackTrace(); }
    }

    public void logout() {
        try (Connection conn = getLocalConnection()) {
            conn.createStatement().executeUpdate("DELETE FROM Session");
        } catch (SQLException e) { e.printStackTrace(); }
    }

    public User getCurrentSessionUser() {
        try (Connection conn = getLocalConnection()) {
            ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM Session LIMIT 1");
            if (rs.next()) return new User(rs.getString("username"), "", rs.getString("role"));
        } catch (SQLException e) { e.printStackTrace(); }
        return null;
    }

    public void syncUsers() {
        ObservableList<User> remoteUsers = FXCollections.observableArrayList();
        try (Connection conn = getRemoteConnection()) {
            ResultSet rs = conn.createStatement().executeQuery("SELECT name, role FROM Users");
            while (rs.next()) remoteUsers.add(new User(rs.getString("name"), "", rs.getString("role")));
        } catch (SQLException e) { return; }

        try (Connection conn = getLocalConnection()) {
            conn.setAutoCommit(false);
            Statement stmt = conn.createStatement();
            stmt.executeUpdate("DELETE FROM CachedUsers");
            String sql = "INSERT INTO CachedUsers (name, role) VALUES (?, ?)";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            for (User u : remoteUsers) {
                pstmt.setString(1, u.getUser()); pstmt.setString(2, u.getRole());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
            conn.commit();
        } catch (SQLException e) { e.printStackTrace(); }
    }

    public ObservableList<User> getCachedUsers() {
        ObservableList<User> result = FXCollections.observableArrayList();
        try (Connection conn = getLocalConnection()) {
            ResultSet rs = conn.createStatement().executeQuery("SELECT * FROM CachedUsers");
            while (rs.next()) result.add(new User(rs.getString("name"), "********", rs.getString("role")));
        } catch (SQLException e) { e.printStackTrace(); }
        return result;
    }
    
    public void updateUserRole(String username, String newRole) {
        try (Connection conn = getRemoteConnection()) {
            String sql = "UPDATE Users SET role = ? WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, newRole);
            pstmt.setString(2, username);
            pstmt.executeUpdate();
            syncUsers();
        } catch (SQLException e) { e.printStackTrace(); }
    }
    
    public void deleteUser(String username) {
        try (Connection conn = getRemoteConnection()) {
            String sql = "DELETE FROM Users WHERE name = ?";
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, username);
            pstmt.executeUpdate();
            syncUsers();
        } catch (SQLException e) { e.printStackTrace(); }
    }

    private void initSalt() {
        try { File fp = new File(".salt"); if (!fp.exists()) { saltValue = getSaltvalue(30); try (FileWriter myWriter = new FileWriter(fp)) { myWriter.write(saltValue); } } else { try (Scanner myReader = new Scanner(fp)) { while (myReader.hasNextLine()) { saltValue = myReader.nextLine(); } } } } catch (IOException e) { e.printStackTrace(); }
    }
    private String getSaltvalue(int length) { StringBuilder finalval = new StringBuilder(length); for (int i = 0; i < length; i++) { finalval.append(characters.charAt(random.nextInt(characters.length()))); } return finalval.toString(); }
    public String generateSecurePassword(String password) throws InvalidKeySpecException { PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltValue.getBytes(), iterations, keylength); Arrays.fill(password.toCharArray(), Character.MIN_VALUE); try { SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1"); return Base64.getEncoder().encodeToString(skf.generateSecret(spec).getEncoded()); } catch (NoSuchAlgorithmException e) { throw new AssertionError("Error hashing password: " + e.getMessage(), e); } finally { spec.clearPassword(); } }
    
    public void logAction(String username, String action, String details) {
        String timestamp = java.time.LocalDateTime.now().toString();
        String logEntry = String.format("[%s] USER: %s | ACTION: %s | DETAILS: %s", 
                                        timestamp, username, action, details);
        
        // 1. Print to Console (for debugging)
        System.out.println(logEntry);
        
        // 2. Write to Persistent File (audit_log.txt)
        try (FileWriter fw = new FileWriter("audit_log.txt", true); // 'true' means append mode
             java.io.BufferedWriter bw = new java.io.BufferedWriter(fw)) {
            
            bw.write(logEntry);
            bw.newLine();
            
        } catch (IOException e) {
            System.err.println("Failed to write to audit log: " + e.getMessage());
        }
    }
}
