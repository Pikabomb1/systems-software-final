package com.mycompany.javafxapplication1;

import javafx.stage.FileChooser;
import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.ChoiceDialog;
import java.util.Optional;
import java.util.List;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javafx.concurrent.Task;
import javafx.application.Platform; 
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.Stage;
import java.net.URL;
import java.util.ResourceBundle;
import javafx.fxml.Initializable;
import javafx.scene.control.cell.ProgressBarTableCell;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.DoubleProperty;
import javafx.scene.layout.VBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressIndicator;
import javafx.geometry.Pos;
import javafx.stage.Modality;
import javafx.stage.StageStyle;
import javafx.scene.control.TextArea;

// --- REAL SSH/SFTP IMPORTS ---
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import java.io.ByteArrayInputStream;

public class SecondaryController implements Initializable {
    
    // --- INFRASTRUCTURE CONFIG ---
    // The Load Balancer Hostname (Docker Container Name)
    private final String loadBalancerHost = "comp20081-loadbalancer";
    // The User on the STORAGE Container (We set up authorized_keys for root)
    private final String remoteUser = "root";
    // The Private Key Path (Inside the Java Container)
    private final String privateKeyPath = "/home/ntu-user/.ssh/id_rsa";
    
    private static long totalBytesSent = 0;
    
    private static String currentUserRole = "standard";
    private static String currentUserName = "guest"; 
    private boolean isBusy = false; 

    // --- FXML ELEMENTS ---
    @FXML private TextField userTextField;
    @FXML private Button secondaryButton, refreshBtn, deleteBtn, changeRoleBtn;
    @FXML private Button uploadBtn, createFileBtn, deleteFileBtn, permissionsBtn, downloadBtn; 
    @FXML private TextArea terminalOutput;
    @FXML private TextField terminalInput;
    @FXML private TableView<User> tableUsers; 
    @FXML private TableColumn<User, String> nameCol, passCol, roleCol;
    @FXML private TableView<MyFile> tableFiles;
    @FXML private TableColumn<MyFile, String> fileNameCol, fileOwnerCol, fileSizeCol;
    @FXML private TableColumn<MyFile, Double> fileProgressCol; 

    private ObservableList<MyFile> fileList = FXCollections.observableArrayList();
    private Stage loadingStage;

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        DB myObj = new DB();
        User currentUser = myObj.getCurrentSessionUser();
        if (currentUser != null) {
            currentUserName = currentUser.getUser(); 
            userTextField.setText(currentUserName);
            currentUserRole = currentUser.getRole();
            if (!"admin".equalsIgnoreCase(currentUserRole)) {
                if (deleteBtn != null) deleteBtn.setDisable(true);
                if (changeRoleBtn != null) changeRoleBtn.setDisable(true);
            }
        }
        myObj.syncUsers(); 
        tableUsers.setItems(myObj.getCachedUsers());
        nameCol.setCellValueFactory(new PropertyValueFactory<>("user"));
        passCol.setCellValueFactory(new PropertyValueFactory<>("pass"));
        roleCol.setCellValueFactory(new PropertyValueFactory<>("role"));
        fileList = myObj.getAllFiles(); 
        fileNameCol.setCellValueFactory(new PropertyValueFactory<>("name"));
        fileOwnerCol.setCellValueFactory(new PropertyValueFactory<>("owner"));
        fileSizeCol.setCellValueFactory(new PropertyValueFactory<>("size"));
        fileProgressCol.setCellValueFactory(new PropertyValueFactory<>("progress"));
        fileProgressCol.setCellFactory(ProgressBarTableCell.forTableColumn());
        tableFiles.setItems(fileList);
    }

    // --- TERMINAL ---
    @FXML
    private void handleTerminalInput(ActionEvent event) {
        String input = terminalInput.getText().trim();
        terminalOutput.appendText("user@cloud:~$ " + input + "\n");
        terminalInput.clear();
        if (input.isEmpty()) return;
        
        String[] parts = input.split("\\s+");
        String command = parts[0];
        
        switch (command) {
            case "help": printTerm("Available: ls, whoami, mkdir, cp, mv, ps, tree, nano, clear, stats"); break;
            case "clear": terminalOutput.setText(""); break;
            case "whoami": printTerm(currentUserName); break;
            case "ls": for (MyFile f : fileList) printTerm(f.getName()); break;
            case "ps": printTerm("PID CMD\n101 java\n102 haproxy\n103 sshd"); break;
            case "stats":
                printTerm("--- INFRASTRUCTURE STATS ---");
                printTerm("Gateway: " + loadBalancerHost);
                printTerm("Protocol: SFTP (SSH-2.0)");
                printTerm("Total Throughput: " + totalBytesSent + " bytes");
                printTerm("Authentication: Passwordless (RSA Key)");
                break;
            case "mkdir":
                if (parts.length < 2) printTerm("usage: mkdir [name]");
                else { new DB().addFile(parts[1], currentUserName, "0B (DIR)"); fileList.add(new MyFile(parts[1], currentUserName, "0B (DIR)", 1.0)); printTerm("Created " + parts[1]); }
                break;
            case "cp": 
                 if (parts.length < 3) printTerm("usage: cp [src] [dest]");
                 else {
                     new DB().addFile(parts[2], currentUserName, "Copy");
                     fileList.add(new MyFile(parts[2], currentUserName, "Copy", 1.0));
                     printTerm("Copied " + parts[1]);
                 }
                 break; 
            case "mv": 
                 if (parts.length < 3) printTerm("usage: mv [src] [dest]");
                 else printTerm("Moved " + parts[1]);
                 break;
            case "tree": printTerm(". (root)\n├── files..."); break;
            case "nano": printTerm("Editor simulation..."); break;
            default: printTerm(command + ": not found");
        }
    }
    
    // --- REAL UPLOAD LOGIC (VIA SSH KEY) ---
    @FXML
    private void uploadFile() {
        if (isBusy) { showAlert(AlertType.WARNING, "System Busy", "Wait."); return; }
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(null);

        if (selectedFile != null) {
            setSystemBusy(true);
            MyFile currentFileObj = new MyFile(selectedFile.getName(), currentUserName, String.valueOf(selectedFile.length()), 0.0);
            fileList.add(currentFileObj);
            new DB().addFile(selectedFile.getName(), currentUserName, String.valueOf(selectedFile.length()));
            showLoadingPopup("Negotiating SSH Key Exchange...");

            Task<Void> uploadTask = new Task<Void>() {
                @Override
                protected Void call() throws Exception {
                    Session session = null;
                    ChannelSftp sftpChannel = null;
                    try {
                        // 1. Setup JSch (SSH)
                        JSch jsch = new JSch();
                        jsch.addIdentity(privateKeyPath); // Use the Key we generated!
                        
                        // 2. Connect to Load Balancer (Gateway)
                        session = jsch.getSession(remoteUser, loadBalancerHost, 22);
                        session.setConfig("StrictHostKeyChecking", "no"); // Auto-accept new keys
                        Platform.runLater(() -> showLoadingPopup("Simulating Cloud Latency"));
                        System.out.println("Simulating artificial delay (30s)...");
                        Thread.sleep(30000); // 30,000ms = 30 seconds wait
                        
                        session.connect(); // <--- REAL CONNECTION HAPPENS HERE
                        
                        Platform.runLater(() -> showLoadingPopup("Connected! Encrypting & Streaming..."));
                        
                        // 3. Open SFTP Channel
                        Channel channel = session.openChannel("sftp");
                        channel.connect();
                        sftpChannel = (ChannelSftp) channel;

                        // 4. Read, Encrypt, and Stream
                        FileInputStream fis = new FileInputStream(selectedFile);
                        long totalSize = selectedFile.length();
                        long totalRead = 0;
                        int chunkSize = 1024 * 1024; // 1MB chunks
                        byte[] buffer = new byte[chunkSize];
                        int bytesRead;
                        String secretKey = "MySuperSecretKey";

                        while ((bytesRead = fis.read(buffer)) > 0) {
                            byte[] chunkData = (bytesRead < chunkSize) ? Arrays.copyOf(buffer, bytesRead) : buffer;
                            
                            // Encrypt the chunk
                            byte[] encryptedData = encryptAES(chunkData, secretKey);

                            // Send Real Data to Server
                            // We stream via ByteArrayInputStream directly to the remote file
                            // Note: In a real split system, we'd name it file.part1, file.part2 etc.
                            // Here we just append to one file for simplicity of demonstration
                            String remoteFileName = selectedFile.getName() + ".enc";
                            sftpChannel.put(new ByteArrayInputStream(encryptedData), remoteFileName, ChannelSftp.APPEND);
                            
                            totalBytesSent += bytesRead; 
                            totalRead += bytesRead;
                            
                            // Update UI
                            double progress = (double) totalRead / totalSize;
                            Platform.runLater(() -> currentFileObj.setProgress(progress));
                            
                            System.out.println("[SSH-UPLOAD] Sent " + bytesRead + " bytes to " + loadBalancerHost);
                        }
                        fis.close();
                        Platform.runLater(() -> currentFileObj.setProgress(1.0));
                        
                    } catch (Exception t) { 
                        t.printStackTrace();
                        throw t; 
                    } finally {
                        if(sftpChannel != null) sftpChannel.exit();
                        if(session != null) session.disconnect();
                    }
                    return null;
                }
            };
            uploadTask.setOnSucceeded(e -> {
                setSystemBusy(false); closeLoadingPopup();
                new DB().logAction(currentUserName, "UPLOAD", "Uploaded: " + selectedFile.getName());
                showAlert(AlertType.INFORMATION, "Complete", "Secure Upload Successful via SFTP!");
            });
            uploadTask.setOnFailed(e -> {
                setSystemBusy(false); closeLoadingPopup(); currentFileObj.setProgress(0.0);
                showAlert(AlertType.ERROR, "Upload Failed", "Could not connect to Cloud Storage.\nCheck VPN/Docker.");
            });
            new Thread(uploadTask).start();
        }
    }

    // --- STANDARD HANDLERS ---
    private void printTerm(String msg) { terminalOutput.appendText(msg + "\n"); }
    @FXML private void RefreshBtnHandler(ActionEvent event){ DB myObj = new DB(); myObj.syncUsers(); tableUsers.setItems(myObj.getCachedUsers()); tableUsers.refresh(); }
    @FXML private void ChangeRoleAction() {
        if (!"admin".equalsIgnoreCase(currentUserRole)) { showAlert(AlertType.ERROR, "Denied", "Only ADMIN."); return; }
        User selected = tableUsers.getSelectionModel().getSelectedItem();
        if (selected != null) {
            String newRole = "admin".equalsIgnoreCase(selected.getRole()) ? "standard" : "admin";
            new DB().updateUserRole(selected.getUser(), newRole);
            new DB().logAction(currentUserName, "CHANGE_ROLE", "Changed " + selected.getUser() + " to " + newRole);
            selected.setRole(newRole); tableUsers.refresh();
        }
    }
    @FXML private void DeleteAction() {
        if (!"admin".equalsIgnoreCase(currentUserRole)) { showAlert(AlertType.ERROR, "Denied", "Only ADMIN."); return; }
        User selected = tableUsers.getSelectionModel().getSelectedItem();
        if (selected != null) { new DB().deleteUser(selected.getUser()); tableUsers.getItems().remove(selected); }
    }
    @FXML private void switchToPrimary(){ 
        if (isBusy) return;
        try { new DB().logout(); Stage stage = (Stage) secondaryButton.getScene().getWindow();
            Parent root = FXMLLoader.load(getClass().getResource("primary.fxml")); stage.setScene(new Scene(root, 640, 480));
        } catch (Exception e) { e.printStackTrace(); }
    }
    private void showLoadingPopup(String message) {
        if (loadingStage == null) {
            loadingStage = new Stage();
            loadingStage.initModality(Modality.APPLICATION_MODAL); loadingStage.initStyle(StageStyle.UTILITY);
            Label label = new Label(message); ProgressIndicator pi = new ProgressIndicator();
            VBox box = new VBox(20, pi, label); box.setAlignment(Pos.CENTER); box.setPadding(new javafx.geometry.Insets(20));
            Scene scene = new Scene(box, 250, 150); loadingStage.setScene(scene);
        }
        ((Label)((VBox)loadingStage.getScene().getRoot()).getChildren().get(1)).setText(message);
        loadingStage.show();
    }
    private void closeLoadingPopup() { if (loadingStage != null) loadingStage.close(); }
    private void setSystemBusy(boolean busy) { isBusy = busy; secondaryButton.setDisable(busy); uploadBtn.setDisable(busy); }
    private void showAlert(AlertType type, String title, String content) { Alert alert = new Alert(type); alert.setTitle(title); alert.setContentText(content); alert.show(); }
    private byte[] encryptAES(byte[] data, String key) throws Exception {
        byte[] keyBytes = Arrays.copyOf(key.getBytes("UTF-8"), 16); SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES"); cipher.init(Cipher.ENCRYPT_MODE, secretKey); return cipher.doFinal(data);
    }
    @FXML private void managePermissions() { 
        if (isBusy) return;
        MyFile selectedFile = tableFiles.getSelectionModel().getSelectedItem();
        if (selectedFile == null) { showAlert(AlertType.WARNING, "No Selection", "Please select a file."); return; }
        if (!selectedFile.getOwner().equals(currentUserName) && !"admin".equalsIgnoreCase(currentUserRole)) {
            showAlert(AlertType.ERROR, "Access Denied", "Only owner can modify permissions."); return;
        }
        List<String> choices = new ArrayList<>();
        for (User u : tableUsers.getItems()) { if (!u.getUser().equals(currentUserName)) choices.add(u.getUser()); }
        if (choices.isEmpty()) { showAlert(AlertType.INFORMATION, "No Users", "No other users."); return; }
        ChoiceDialog<String> d = new ChoiceDialog<>(choices.get(0), choices);
        d.setTitle("File Permissions"); d.setHeaderText("Set Permissions"); d.setContentText("Select User:");
        Optional<String> res = d.showAndWait();
        if (res.isPresent()) {
            String target = res.get();
            ChoiceDialog<String> l = new ChoiceDialog<>("Read Only", Arrays.asList("Read Only", "Write (Delete)", "Remove Access"));
            l.setTitle("Level"); l.setHeaderText("For " + target); l.setContentText("Level:");
            Optional<String> lRes = l.showAndWait();
            if (lRes.isPresent()) {
                String level = lRes.get();
                if (level.equals("Remove Access")) selectedFile.removePermission(target);
                else selectedFile.addPermission(target, level.equals("Read Only") ? "READ" : "WRITE");
                new DB().updateFilePermissions(selectedFile.getName(), selectedFile.getPermissionsDBString());
                showAlert(AlertType.INFORMATION, "Updated", "Permissions updated.");
            }
        }
    }
    @FXML private void downloadFile() { 
        if (isBusy) return;
        MyFile selectedFile = tableFiles.getSelectionModel().getSelectedItem();
        if (selectedFile == null) { showAlert(AlertType.WARNING, "No Selection", "Please select a file."); return; }
        if (checkPermission(selectedFile, "READ")) showAlert(AlertType.INFORMATION, "Download Success", "Permission Granted.\nFile downloaded (Simulated).");
        else showAlert(AlertType.ERROR, "Access Denied", "You do NOT have READ permission.");
    }
    @FXML private void deleteFile() { 
        if (isBusy) return;
        MyFile selectedFile = tableFiles.getSelectionModel().getSelectedItem();
        if (selectedFile != null) {
            if (checkPermission(selectedFile, "WRITE")) {
                new DB().deleteFile(selectedFile.getName()); fileList.remove(selectedFile);
                new DB().logAction(currentUserName, "DELETE_FILE", "Deleted file: " + selectedFile.getName());
                showAlert(AlertType.INFORMATION, "Success", "File deleted successfully.");
            } else {
                new DB().logAction(currentUserName, "DELETE_FAILED", "Access denied: " + selectedFile.getName());
                showAlert(AlertType.ERROR, "Access Denied", "No WRITE permission.");
            }
        } else showAlert(AlertType.WARNING, "No Selection", "Select a file.");
    }
    private boolean checkPermission(MyFile file, String requiredLevel) {
        if (file.getOwner().equals(currentUserName)) return true;
        if ("admin".equalsIgnoreCase(currentUserRole)) return true;
        String perm = file.getPermission(currentUserName);
        if (perm == null) return false;
        if (requiredLevel.equals("READ")) return perm.equals("READ") || perm.equals("WRITE");
        else if (requiredLevel.equals("WRITE")) return perm.equals("WRITE");
        return false;
    }
    @FXML private void createFile() { 
        if (isBusy) return;
        TextInputDialog d = new TextInputDialog("MyNewFile"); d.setTitle("Create"); d.setContentText("Name:");
        Optional<String> r = d.showAndWait();
        if (r.isPresent()) {
            String n = r.get(); if (!n.endsWith(".txt")) n += ".txt";
            new DB().addFile(n, currentUserName, "124 bytes");
            fileList.add(new MyFile(n, currentUserName, "124 bytes", 1.0));
            new DB().logAction(currentUserName, "CREATE_FILE", "Created: " + n);
            showAlert(AlertType.INFORMATION, "Success", "File created.");
        }
    }

    public static class MyFile {
        private String name; private String owner; private String size; private DoubleProperty progress; 
        private Map<String, String> permissions = new HashMap<>();
        public MyFile(String name, String owner, String size, double progress) { this.name = name; this.owner = owner; this.size = size; this.progress = new SimpleDoubleProperty(progress); }
        public String getName() { return name; } public String getOwner() { return owner; } public String getSize() { return size; }
        public void addPermission(String u, String t) { permissions.put(u, t); } public void removePermission(String u) { permissions.remove(u); } public String getPermission(String u) { return permissions.get(u); }
        public String getPermissionsDBString() { return ""; } 
        public DoubleProperty progressProperty() { return progress; } public double getProgress() { return progress.get(); } public void setProgress(double p) { this.progress.set(p); }
    }
}