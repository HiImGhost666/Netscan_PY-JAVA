package com.inventariado.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.inventariado.core.scanner.NetworkScanner;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class NetworkScannerGUI extends Application {
    private static final Logger logger = LoggerFactory.getLogger(NetworkScannerGUI.class);

    // UI Components
    private Stage primaryStage;
    private TableView<Device> resultsTable;
    private TextArea generalTextArea;
    private TextArea cpuTextArea;
    private TextArea ramTextArea;
    private TextArea storageTextArea;
    private TextArea servicesTextArea;
    private TextArea vulnsTextArea;
    private TextArea recsTextArea;
    private ProgressBar progressBar;
    private Label statusLabel;
    private Label progressLabel;

    // Data
    private ObservableList<Device> scanResults = FXCollections.observableArrayList();
    private ObservableList<Device> filteredResults = FXCollections.observableArrayList();
    private Device selectedDevice;

    // Form fields
    private TextField networkRangeField;
    private TextField searchFilterField;
    private CheckBox saveCredentialsCheck;
    private CheckBox riskAnalysisCheck;

    // Credential fields
    private TextField sshUsernameField;
    private PasswordField sshPasswordField;
    private TextField sshKeyFileField;
    private TextField snmpCommunityField;
    private TextField wmiUsernameField;
    private PasswordField wmiPasswordField;

    // Buttons
    private Button scanButton;
    private Button stopButton;
    private Button exportCsvButton;
    private Button exportJsonButton;
    private Button importCsvButton;

    @Override
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;
        primaryStage.setTitle("Herramienta de Escaneo de Red - Laberit");

        // Create main layout
        BorderPane root = new BorderPane();
        Scene scene = new Scene(root, 1200, 700);

        // Create menu bar
        root.setTop(createMenuBar());

        // Create main content
        SplitPane mainContent = new SplitPane();
        mainContent.setDividerPositions(0.25);

        // Left panel (configuration)
        VBox leftPanel = createLeftPanel();

        // Right panel (results)
        VBox rightPanel = createRightPanel();

        mainContent.getItems().addAll(leftPanel, rightPanel);
        root.setCenter(mainContent);

        // Status bar
        root.setBottom(createStatusBar());

        // Configure stage
        primaryStage.setScene(scene);
        primaryStage.setMinWidth(900);
        primaryStage.setMinHeight(600);

        // Load logo
        try {
            Image logo = new Image(getClass().getResourceAsStream("/images/logo_laberit.png"));
            primaryStage.getIcons().add(logo);
        } catch (Exception e) {
            logger.error("Error loading logo", e);
        }

        primaryStage.show();
    }

    private MenuBar createMenuBar() {
        MenuBar menuBar = new MenuBar();

        // File menu
        Menu fileMenu = new Menu("Archivo");
        MenuItem exitItem = new MenuItem("Salir");
        exitItem.setOnAction(e -> handleExit());
        fileMenu.getItems().add(exitItem);

        // Tools menu
        Menu toolsMenu = new Menu("Herramientas");
        MenuItem credentialsItem = new MenuItem("Gestión de Credenciales");
        credentialsItem.setOnAction(e -> showCredentialsDialog());
        toolsMenu.getItems().add(credentialsItem);

        // Help menu
        Menu helpMenu = new Menu("Ayuda");
        MenuItem aboutItem = new MenuItem("Acerca de");
        aboutItem.setOnAction(e -> showAboutDialog());
        helpMenu.getItems().add(aboutItem);

        menuBar.getMenus().addAll(fileMenu, toolsMenu, helpMenu);
        return menuBar;
    }

    private VBox createLeftPanel() {
        VBox leftPanel = new VBox(10);
        leftPanel.setPadding(new Insets(10));
        leftPanel.setStyle("-fx-background-color: #f5f5f5;");

        // Header with logo
        try {
            Image logo = new Image(getClass().getResourceAsStream("/images/logo_laberit.png"));
            ImageView logoView = new ImageView(logo);
            logoView.setFitWidth(180);
            logoView.setPreserveRatio(true);
            leftPanel.getChildren().add(logoView);
        } catch (Exception e) {
            logger.error("Error loading logo", e);
        }

        Label titleLabel = new Label("LABERIT");
        titleLabel.setStyle("-fx-font-size: 22; -fx-font-weight: bold; -fx-text-fill: #2c3e50;");
        leftPanel.getChildren().add(titleLabel);

        // Network range section
        TitledPane networkPane = new TitledPane();
        networkPane.setText("Rango de Red");
        networkPane.setCollapsible(false);

        GridPane networkGrid = new GridPane();
        networkGrid.setHgap(5);
        networkGrid.setVgap(5);
        networkGrid.setPadding(new Insets(5));

        Label networkLabel = new Label("Rango de red:");
        networkRangeField = new TextField("192.168.1.0/24");
        Button detectButton = new Button("Autodetectar");
        detectButton.setOnAction(e -> autoDetectNetwork());

        networkGrid.add(networkLabel, 0, 0);
        networkGrid.add(networkRangeField, 1, 0);
        networkGrid.add(detectButton, 2, 0);

        networkPane.setContent(networkGrid);

        // Scan options section
        TitledPane optionsPane = new TitledPane();
        optionsPane.setText("Opciones de Escaneo");
        optionsPane.setCollapsible(false);

        VBox optionsBox = new VBox(5);
        optionsBox.setPadding(new Insets(5));

        saveCredentialsCheck = new CheckBox("Guardar credenciales");
        riskAnalysisCheck = new CheckBox("Realizar análisis de riesgo");

        optionsBox.getChildren().addAll(saveCredentialsCheck, riskAnalysisCheck);
        optionsPane.setContent(optionsBox);

        // Action buttons
        HBox buttonBox = new HBox(5);
        buttonBox.setAlignment(Pos.CENTER);

        scanButton = new Button("Iniciar Escaneo");
        scanButton.setStyle("-fx-base: #3498db;");
        scanButton.setOnAction(e -> startScan());

        stopButton = new Button("Detener Escaneo");
        stopButton.setStyle("-fx-base: #e74c3c;");
        stopButton.setDisable(true);
        stopButton.setOnAction(e -> stopScan());

        buttonBox.getChildren().addAll(scanButton, stopButton);

        // Data and filters section
        TitledPane dataPane = new TitledPane();
        dataPane.setText("Datos y Filtros");
        dataPane.setCollapsible(false);

        VBox dataBox = new VBox(5);
        dataBox.setPadding(new Insets(5));

        // Export/Import buttons
        HBox exportBox = new HBox(5);
        exportBox.setAlignment(Pos.CENTER);

        exportCsvButton = new Button("Exportar CSV");
        exportCsvButton.setOnAction(e -> exportToCsv());

        exportJsonButton = new Button("Exportar JSON");
        exportJsonButton.setOnAction(e -> exportToJson());

        importCsvButton = new Button("Importar CSV");
        importCsvButton.setOnAction(e -> importFromCsv());

        exportBox.getChildren().addAll(exportCsvButton, exportJsonButton, importCsvButton);

        // Quick filters
        HBox filterBox = new HBox(5);
        filterBox.setAlignment(Pos.CENTER);

        Button httpFilter = new Button("HTTP");
        httpFilter.setOnAction(e -> filterByService("http"));

        Button sshFilter = new Button("SSH");
        sshFilter.setOnAction(e -> filterByService("ssh"));

        Button rdpFilter = new Button("RDP");
        rdpFilter.setOnAction(e -> filterByService("rdp"));

        Button clearFilter = new Button("Limpiar");
        clearFilter.setOnAction(e -> clearFilters());

        filterBox.getChildren().addAll(httpFilter, sshFilter, rdpFilter, clearFilter);

        dataBox.getChildren().addAll(exportBox, filterBox);
        dataPane.setContent(dataBox);

        leftPanel.getChildren().addAll(networkPane, optionsPane, buttonBox, dataPane);
        return leftPanel;
    }

    private VBox createRightPanel() {
        VBox rightPanel = new VBox(10);
        rightPanel.setPadding(new Insets(10));

        // Results title
        Label resultsLabel = new Label("Resultados del Escaneo");
        resultsLabel.setStyle("-fx-font-size: 14; -fx-font-weight: bold;");
        rightPanel.getChildren().add(resultsLabel);

        // Search filter
        HBox filterBox = new HBox(5);
        filterBox.setAlignment(Pos.CENTER_LEFT);

        Label filterLabel = new Label("Filtrar:");
        searchFilterField = new TextField();
        searchFilterField.textProperty().addListener((obs, oldVal, newVal) -> applyFilter());

        filterBox.getChildren().addAll(filterLabel, searchFilterField);
        rightPanel.getChildren().add(filterBox);

        // Results table
        resultsTable = new TableView<>();
        resultsTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);

        // Create columns
        TableColumn<Device, String> ipCol = new TableColumn<>("IP");
        ipCol.setCellValueFactory(new PropertyValueFactory<>("ip"));

        TableColumn<Device, String> hostnameCol = new TableColumn<>("Hostname");
        hostnameCol.setCellValueFactory(new PropertyValueFactory<>("hostname"));

        TableColumn<Device, String> macCol = new TableColumn<>("MAC");
        macCol.setCellValueFactory(new PropertyValueFactory<>("mac"));

        TableColumn<Device, String> vendorCol = new TableColumn<>("Fabricante");
        vendorCol.setCellValueFactory(new PropertyValueFactory<>("vendor"));

        TableColumn<Device, String> osCol = new TableColumn<>("Sistema Operativo");
        osCol.setCellValueFactory(new PropertyValueFactory<>("os"));

        TableColumn<Device, String> portsCol = new TableColumn<>("Puertos");
        portsCol.setCellValueFactory(new PropertyValueFactory<>("ports"));

        resultsTable.getColumns().addAll(ipCol, hostnameCol, macCol, vendorCol, osCol, portsCol);
        resultsTable.setItems(filteredResults);

        // Set row factory for context menu
        resultsTable.setRowFactory(tv -> {
            TableRow<Device> row = new TableRow<>();
            row.setOnMouseClicked(event -> {
                if (event.getClickCount() == 2 && !row.isEmpty()) {
                    selectedDevice = row.getItem();
                    showDeviceDetails(selectedDevice);
                }
            });

            // Context menu
            ContextMenu contextMenu = new ContextMenu();
            MenuItem detailsItem = new MenuItem("Ver detalles");
            detailsItem.setOnAction(e -> {
                selectedDevice = row.getItem();
                showDeviceDetails(selectedDevice);
            });

            contextMenu.getItems().add(detailsItem);

            // Add service-specific items
            if (!row.isEmpty()) {
                Device device = row.getItem();
                if (device.hasService("http") || device.hasService("https")) {
                    MenuItem webItem = new MenuItem("Abrir en navegador");
                    webItem.setOnAction(e -> openWebInterface(device));
                    contextMenu.getItems().add(webItem);
                }

                if (device.hasService("ssh")) {
                    MenuItem sshItem = new MenuItem("Conectar por SSH");
                    sshItem.setOnAction(e -> connectSSH(device));
                    contextMenu.getItems().add(sshItem);
                }

                if (device.hasService("rdp")) {
                    MenuItem rdpItem = new MenuItem("Conectar por RDP");
                    rdpItem.setOnAction(e -> connectRDP(device));
                    contextMenu.getItems().add(rdpItem);
                }
            }

            row.contextMenuProperty().bind(
                    javafx.beans.binding.Bindings.when(row.emptyProperty())
                            .then((ContextMenu)null)
                            .otherwise(contextMenu)
            );

            return row;
        });

        rightPanel.getChildren().add(resultsTable);

        // Details tabs
        TabPane detailsTabs = new TabPane();

        // General tab
        Tab generalTab = new Tab("General");
        generalTextArea = new TextArea();
        generalTextArea.setEditable(false);
        generalTab.setContent(generalTextArea);

        // Hardware tab
        Tab hardwareTab = new Tab("Hardware");
        VBox hardwareBox = new VBox(10);

        // CPU section
        TitledPane cpuPane = new TitledPane("Procesador", new ScrollPane());
        cpuTextArea = new TextArea();
        cpuTextArea.setEditable(false);
        cpuPane.setContent(cpuTextArea);

        // RAM section
        TitledPane ramPane = new TitledPane("Memoria RAM", new ScrollPane());
        ramTextArea = new TextArea();
        ramTextArea.setEditable(false);
        ramPane.setContent(ramTextArea);

        // Storage section
        TitledPane storagePane = new TitledPane("Almacenamiento", new ScrollPane());
        storageTextArea = new TextArea();
        storageTextArea.setEditable(false);
        storagePane.setContent(storageTextArea);

        hardwareBox.getChildren().addAll(cpuPane, ramPane, storagePane);
        hardwareTab.setContent(hardwareBox);

        // Services tab
        Tab servicesTab = new Tab("Servicios");
        servicesTextArea = new TextArea();
        servicesTextArea.setEditable(false);
        servicesTab.setContent(new ScrollPane(servicesTextArea));

        // Security tab
        Tab securityTab = new Tab("Seguridad");
        VBox securityBox = new VBox(10);

        Label vulnsLabel = new Label("Vulnerabilidades detectadas:");
        vulnsLabel.setStyle("-fx-font-weight: bold;");
        vulnsTextArea = new TextArea();
        vulnsTextArea.setEditable(false);

        Label recsLabel = new Label("Recomendaciones de seguridad:");
        recsLabel.setStyle("-fx-font-weight: bold;");
        recsTextArea = new TextArea();
        recsTextArea.setEditable(false);

        securityBox.getChildren().addAll(vulnsLabel, vulnsTextArea, recsLabel, recsTextArea);
        securityTab.setContent(new ScrollPane(securityBox));

        // History tab
        Tab historyTab = new Tab("Historial");
        TableView<HistoryEntry> historyTable = new TableView<>();
        historyTab.setContent(new ScrollPane(historyTable));

        detailsTabs.getTabs().addAll(generalTab, hardwareTab, servicesTab, securityTab, historyTab);
        rightPanel.getChildren().add(detailsTabs);

        return rightPanel;
    }

    private HBox createStatusBar() {
        HBox statusBar = new HBox(10);
        statusBar.setPadding(new Insets(5));
        statusBar.setStyle("-fx-background-color: #e0e0e0;");

        progressBar = new ProgressBar(0);
        progressBar.setPrefWidth(400);

        progressLabel = new Label("Progreso: 0%");
        statusLabel = new Label("Listo para escanear");

        statusBar.getChildren().addAll(progressBar, progressLabel, statusLabel);
        return statusBar;
    }

    private void showCredentialsDialog() {
        Dialog<Map<String, String>> dialog = new Dialog<>();
        dialog.setTitle("Gestión de Credenciales");
        dialog.setHeaderText("Ingrese las credenciales de acceso");

        // Set the button types
        ButtonType saveButtonType = new ButtonType("Guardar", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(saveButtonType, ButtonType.CANCEL);

        // Create the credential fields
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

        sshUsernameField = new TextField();
        sshPasswordField = new PasswordField();
        sshKeyFileField = new TextField();
        snmpCommunityField = new TextField();
        wmiUsernameField = new TextField();
        wmiPasswordField = new PasswordField();

        grid.add(new Label("Usuario SSH:"), 0, 0);
        grid.add(sshUsernameField, 1, 0);
        grid.add(new Label("Contraseña SSH:"), 0, 1);
        grid.add(sshPasswordField, 1, 1);
        grid.add(new Label("Archivo clave SSH:"), 0, 2);
        grid.add(sshKeyFileField, 1, 2);
        grid.add(new Label("Comunidad SNMP:"), 0, 3);
        grid.add(snmpCommunityField, 1, 3);
        grid.add(new Label("Usuario WMI:"), 0, 4);
        grid.add(wmiUsernameField, 1, 4);
        grid.add(new Label("Contraseña WMI:"), 0, 5);
        grid.add(wmiPasswordField, 1, 5);

        dialog.getDialogPane().setContent(grid);

        // Convert the result to a credential map when the save button is clicked
        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == saveButtonType) {
                Map<String, String> credentials = new HashMap<>();
                credentials.put("ssh_username", sshUsernameField.getText());
                credentials.put("ssh_password", sshPasswordField.getText());
                credentials.put("ssh_key_file", sshKeyFileField.getText());
                credentials.put("snmp_community", snmpCommunityField.getText());
                credentials.put("wmi_username", wmiUsernameField.getText());
                credentials.put("wmi_password", wmiPasswordField.getText());
                return credentials;
            }
            return null;
        });

        Optional<Map<String, String>> result = dialog.showAndWait();
        result.ifPresent(credentials -> {
            // Save credentials logic here
            logger.info("Credentials saved");
        });
    }

    private void showAboutDialog() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Acerca de");
        alert.setHeaderText("Herramienta de Escaneo de Red - Laberit");
        alert.setContentText("Versión 1.0\n\n" +
                "Una herramienta para el análisis y monitoreo de redes.\n\n" +
                "Esta es la versión convertida de Python a Java.\n\n" +
                "Desarrollado por estudiantes en práctica:\n");
        alert.showAndWait();
    }


    private void autoDetectNetwork() {
        // Implement network auto-detection
        networkRangeField.setText("192.168.1.0/24"); // Placeholder
    }

    private void startScan() {
        String networkRange = networkRangeField.getText().trim();
        if (networkRange.isEmpty()) {
            showAlert("Error", "Please enter a valid network range");
            return;
        }

        scanButton.setDisable(true);
        stopButton.setDisable(false);
        statusLabel.setText("Scanning...");
        progressBar.setProgress(0);

        Task<Void> scanTask = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                NetworkScanner scanner = new NetworkScanner();
                scanner.registerDeviceCallback(deviceInfo -> {
                    Platform.runLater(() -> {
                        Map<String, Object> macInfo = (Map<String, Object>) deviceInfo.getOrDefault("mac_info", Map.of());
                        String mac = (String) macInfo.getOrDefault("mac", "Unknown");
                        String vendor = (String) macInfo.getOrDefault("vendor", "Unknown");

                        Device device = new Device(
                                (String) deviceInfo.get("ip"),
                                (String) deviceInfo.getOrDefault("hostname", "Unknown"),
                                mac,
                                vendor,
                                (String) deviceInfo.getOrDefault("os_info", "Unknown"),
                                String.join(", ", ((Map<String, Object>) deviceInfo.getOrDefault("services", Map.of())).keySet())
                        );
                        scanResults.add(device);
                    });

                });

                // Start scan in background thread
                Thread scanThread = new Thread(() -> {
                    List<Map<String, Object>> devices = scanner.scanNetwork(
                            networkRange,
                            "-T4",
                            riskAnalysisCheck.isSelected(),
                            snmpCommunityField.getText()
                    );

                    // Update progress
                    updateProgress(1, 1);
                    updateMessage("Scan completed. Found " + devices.size() + " devices");
                });

                scanThread.start();

                // Update progress while scanning
                while (scanThread.isAlive()) {
                    updateProgress(scanner.getScanProgress() / 100, 1);
                    updateMessage("Scanning... " + (int)scanner.getScanProgress() + "%");
                    Thread.sleep(500);
                }

                return null;
            }
        };

        scanTask.setOnSucceeded(e -> {
            scanButton.setDisable(false);
            stopButton.setDisable(true);
            filteredResults.setAll(scanResults);
        });

        scanTask.setOnCancelled(e -> {
            scanButton.setDisable(false);
            stopButton.setDisable(true);
            statusLabel.setText("Scan cancelled");
        });

        progressBar.progressProperty().bind(scanTask.progressProperty());
        statusLabel.textProperty().bind(scanTask.messageProperty());

        new Thread(scanTask).start();
    }

    private void stopScan() {
        // Implement scan stopping logic
        scanButton.setDisable(false);
        stopButton.setDisable(true);
        statusLabel.setText("Escaneo detenido");
    }

    private void exportToCsv() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Guardar como CSV");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files", "*.csv"));
        File file = fileChooser.showSaveDialog(primaryStage);

        if (file != null) {
            // Implement CSV export logic
            logger.info("Exporting to CSV: " + file.getAbsolutePath());
            showAlert("Éxito", "Datos exportados correctamente a CSV");
        }
    }

    private void exportToJson() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Guardar como JSON");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("JSON Files", "*.json"));
        File file = fileChooser.showSaveDialog(primaryStage);

        if (file != null) {
            // Implement JSON export logic
            logger.info("Exporting to JSON: " + file.getAbsolutePath());
            showAlert("Éxito", "Datos exportados correctamente a JSON");
        }
    }

    private void importFromCsv() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Abrir archivo CSV");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files", "*.csv"));
        File file = fileChooser.showOpenDialog(primaryStage);

        if (file != null) {
            // Implement CSV import logic
            logger.info("Importing from CSV: " + file.getAbsolutePath());

            // Sample imported data
            scanResults.clear();
            scanResults.add(new Device("192.168.1.3", "New-Device", "00:1A:2B:3C:4D:61", "Unknown", "Linux", "22, 80"));
            filteredResults.setAll(scanResults);

            showAlert("Éxito", "Datos importados correctamente desde CSV");
        }
    }

    private void filterByService(String service) {
        filteredResults.clear();
        for (Device device : scanResults) {
            if (device.hasService(service)) {
                filteredResults.add(device);
            }
        }
    }

    private void clearFilters() {
        filteredResults.setAll(scanResults);
        searchFilterField.clear();
    }

    private void applyFilter() {
        String filter = searchFilterField.getText().toLowerCase();
        if (filter.isEmpty()) {
            filteredResults.setAll(scanResults);
            return;
        }

        filteredResults.clear();
        for (Device device : scanResults) {
            if (device.matchesFilter(filter)) {
                filteredResults.add(device);
            }
        }
    }

    private void showDeviceDetails(Device device) {
        generalTextArea.setText(
                "IP: " + device.getIp() + "\n" +
                        "Hostname: " + device.getHostname() + "\n" +
                        "MAC: " + device.getMac() + "\n" +
                        "Fabricante: " + device.getVendor() + "\n" +
                        "Sistema Operativo: " + device.getOs() + "\n" +
                        "Puertos: " + device.getPorts()
        );

        // Sample hardware details
        cpuTextArea.setText("Modelo: Intel Core i7-9700K\nNúcleos: 8\nFrecuencia: 3.6 GHz");
        ramTextArea.setText("Total: 16 GB\nTipo: DDR4\nVelocidad: 3200 MHz");
        storageTextArea.setText("Disco 1: SSD 500 GB\nDisco 2: HDD 2 TB");

        // Sample services
        servicesTextArea.setText("80: HTTP (Apache)\n443: HTTPS (Apache)\n22: SSH (OpenSSH)");

        // Sample security info
        vulnsTextArea.setText("- Puerto 80: Vulnerabilidad XSS\n- Puerto 22: Versión antigua de OpenSSH");
        recsTextArea.setText("- Actualizar OpenSSH a la última versión\n- Configurar HTTPS correctamente");
    }

    private void openWebInterface(Device device) {
        String url = "http://" + device.getIp();
        getHostServices().showDocument(url);
    }

    private void connectSSH(Device device) {
        showAlert("Conectar SSH", "Iniciando conexión SSH a " + device.getIp());
    }

    private void connectRDP(Device device) {
        showAlert("Conectar RDP", "Iniciando conexión RDP a " + device.getIp());
    }

    private void showAlert(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    private void handleExit() {
        if (showConfirmation("Salir", "¿Está seguro que desea salir de la aplicación?")) {
            Platform.exit();
        }
    }

    private boolean showConfirmation(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        return alert.showAndWait().get() == ButtonType.OK;
    }

    // Device model class
    public class Device {
        private final String ip;
        private final String hostname;
        private final String mac;
        private final String vendor;
        private final String os;
        private final String ports;
        private final Map<String, Map<String, String>> services;

        public Device(String ip, String hostname, String mac, String vendor, String os, String ports) {
            this.ip = ip;
            this.hostname = hostname;
            this.mac = mac;
            this.vendor = vendor;
            this.os = os;
            this.ports = ports;
            this.services = parseServices(ports);
        }

        private Map<String, Map<String, String>> parseServices(String portsStr) {
            Map<String, Map<String, String>> services = new HashMap<>();
            if (portsStr != null && !portsStr.isEmpty()) {
                String[] portEntries = portsStr.split(",");
                for (String entry : portEntries) {
                    String[] parts = entry.trim().split("/");
                    if (parts.length >= 1) {
                        String port = parts[0].trim();
                        Map<String, String> serviceInfo = new HashMap<>();
                        serviceInfo.put("port", port);
                        if (parts.length >= 2) {
                            serviceInfo.put("protocol", parts[1].trim());
                        }
                        services.put(port, serviceInfo);
                    }
                }
            }
            return services;
        }

        // Getters
        public String getIp() { return ip; }
        public String getHostname() { return hostname; }
        public String getMac() { return mac; }
        public String getVendor() { return vendor; }
        public String getOs() { return os; }
        public String getPorts() { return ports; }
        public Map<String, Map<String, String>> getServices() { return services; }

        public boolean hasService(String serviceName) {
            return services.values().stream()
                    .anyMatch(service ->
                            service.getOrDefault("name", "").toLowerCase().contains(serviceName.toLowerCase()) ||
                                    (serviceName.equalsIgnoreCase("http") && service.get("port").equals("80")) ||
                                    (serviceName.equalsIgnoreCase("https") && service.get("port").equals("443"))
                    );
        }
        public boolean matchesFilter(String filter) {
            if (filter == null || filter.isEmpty()) return true;
            filter = filter.toLowerCase();

            // Buscar en todos los campos principales
            if ((ip != null && ip.toLowerCase().contains(filter)) ||
                    (hostname != null && hostname.toLowerCase().contains(filter)) ||
                    (mac != null && mac.toLowerCase().contains(filter)) ||
                    (vendor != null && vendor.toLowerCase().contains(filter)) ||
                    (os != null && os.toLowerCase().contains(filter)) ||
                    (ports != null && ports.toLowerCase().contains(filter))) {
                return true;
            }

            // Buscar en los servicios
            for (Map<String, String> service : services.values()) {
                for (String value : service.values()) {
                    if (value != null && value.toLowerCase().contains(filter)) {
                        return true;
                    }
                }
            }

            return false;
        }


    }

    // HistoryEntry model class
    class HistoryEntry {
        private final String timestamp;
        private final String eventType;
        private final String description;
        private final String status;

        public HistoryEntry(String timestamp, String eventType, String description, String status) {
            this.timestamp = timestamp;
            this.eventType = eventType;
            this.description = description;
            this.status = status;
        }

        // Getters
        public String getTimestamp() { return timestamp; }
        public String getEventType() { return eventType; }
        public String getDescription() { return description; }
        public String getStatus() { return status; }
    }

    // CredentialManager class
    class CredentialManager {
        private static final String CREDENTIALS_FILE = "credentials.json";
        private static final String ENCRYPTION_KEY = "secure_key_123"; // In production, use a proper key management system

        public void saveCredentials(Map<String, String> credentials, boolean encrypt) {
            try {
                String json = new Gson().toJson(credentials);

                if (encrypt) {
                    json = encrypt(json);
                }

                Files.write(Paths.get(CREDENTIALS_FILE), json.getBytes());
            } catch (Exception e) {
                throw new RuntimeException("Error saving credentials", e);
            }
        }

        public Map<String, String> loadCredentials() {
            try {
                if (!Files.exists(Paths.get(CREDENTIALS_FILE))) {
                    return new HashMap<>();
                }

                String json = new String(Files.readAllBytes(Paths.get(CREDENTIALS_FILE)));

                // Try to decrypt (it may be unencrypted)
                try {
                    json = decrypt(json);
                } catch (Exception e) {
                    // If decryption fails, assume it's unencrypted
                }

                return new Gson().fromJson(json, new TypeToken<Map<String, String>>(){}.getType());
            } catch (Exception e) {
                throw new RuntimeException("Error loading credentials", e);
            }
        }

        private String encrypt(String data) {
            // Implement encryption logic here
            // This is a placeholder - use proper encryption in production
            return Base64.getEncoder().encodeToString(data.getBytes());
        }

        private String decrypt(String data) {
            // Implement decryption logic here
            // This is a placeholder - use proper encryption in production
            return new String(Base64.getDecoder().decode(data));
        }
    }

    // DataExporter class
    class DataExporter {
        public boolean exportToCsv(List<Device> devices, String filename) {
            try (PrintWriter writer = new PrintWriter(new File(filename))) {
                // Write CSV header
                writer.println("IP,Hostname,MAC,Vendor,OS,Ports");

                // Write device data
                for (Device device : devices) {
                    writer.println(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"",
                            device.getIp(),
                            device.getHostname(),
                            device.getMac(),
                            device.getVendor(),
                            device.getOs(),
                            device.getPorts()));
                }

                return true;
            } catch (Exception e) {
                logger.error("Error exporting to CSV", e);
                return false;
            }
        }

        public boolean exportToJson(List<Device> devices, String filename) {
            try (PrintWriter writer = new PrintWriter(new File(filename))) {
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                writer.println(gson.toJson(devices));
                return true;
            } catch (Exception e) {
                logger.error("Error exporting to JSON", e);
                return false;
            }
        }

        public List<Device> importFromCsv(String filename) {
            List<Device> devices = new ArrayList<>();

            try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
                // Skip header
                br.readLine();

                String line;
                while ((line = br.readLine()) != null) {
                    String[] values = line.split(",");
                    if (values.length >= 6) {
                        Device device = new Device(
                                values[0].replace("\"", ""),
                                values[1].replace("\"", ""),
                                values[2].replace("\"", ""),
                                values[3].replace("\"", ""),
                                values[4].replace("\"", ""),
                                values[5].replace("\"", ""));
                        devices.add(device);
                    }
                }
            } catch (Exception e) {
                logger.error("Error importing from CSV", e);
                return null;
            }

            return devices;
        }
    }

    // NetworkVisualizer class
    class NetworkVisualizer {
        private final Map<String, Device> devices = new HashMap<>();
        private final Map<String, List<String>> connections = new HashMap<>();

        public void addDevice(Device device) {
            devices.put(device.getIp(), device);
        }

        public void addConnection(String sourceIp, String targetIp) {
            connections.computeIfAbsent(sourceIp, k -> new ArrayList<>()).add(targetIp);
        }

        public boolean generateHtml(String outputPath) {
            try {
                // Create HTML template
                String html = "<!DOCTYPE html>\n" +
                        "<html>\n" +
                        "<head>\n" +
                        "    <title>Network Topology</title>\n" +
                        "    <script src=\"https://unpkg.com/vis-network/standalone/umd/vis-network.min.js\"></script>\n" +
                        "    <style>\n" +
                        "        #network {\n" +
                        "            width: 100%;\n" +
                        "            height: 750px;\n" +
                        "            border: 1px solid #ccc;\n" +
                        "        }\n" +
                        "        body { font-family: Arial; margin: 20px; }\n" +
                        "    </style>\n" +
                        "</head>\n" +
                        "<body>\n" +
                        "    <h1>Network Topology Visualization</h1>\n" +
                        "    <div id=\"network\"></div>\n" +
                        "    <script>\n" +
                        "        var nodes = new vis.DataSet([\n" +
                        generateNodesJs() +
                        "        ]);\n" +
                        "        var edges = new vis.DataSet([\n" +
                        generateEdgesJs() +
                        "        ]);\n" +
                        "        var container = document.getElementById('network');\n" +
                        "        var data = {\n" +
                        "            nodes: nodes,\n" +
                        "            edges: edges\n" +
                        "        };\n" +
                        "        var options = {\n" +
                        "            nodes: {\n" +
                        "                font: {\n" +
                        "                    size: 12,\n" +
                        "                    face: 'Tahoma'\n" +
                        "                }\n" +
                        "            },\n" +
                        "            edges: {\n" +
                        "                color: {\n" +
                        "                    color: '#848484',\n" +
                        "                    highlight: '#1B4F72'\n" +
                        "                },\n" +
                        "                smooth: {\n" +
                        "                    type: 'continuous'\n" +
                        "                }\n" +
                        "            },\n" +
                        "            physics: {\n" +
                        "                forceAtlas2Based: {\n" +
                        "                    gravitationalConstant: -50,\n" +
                        "                    centralGravity: 0.01,\n" +
                        "                    springLength: 100,\n" +
                        "                    springConstant: 0.08\n" +
                        "                },\n" +
                        "                maxVelocity: 50,\n" +
                        "                minVelocity: 0.1,\n" +
                        "                           solver: 'forceAtlas2Based'\n" +
                        "            }\n" +
                        "        };\n" +
                        "        var network = new vis.Network(container, data, options);\n" +
                        "    </script>\n" +
                        "</body>\n" +
                        "</html>";

                // Write to file
                Files.write(Paths.get(outputPath), html.getBytes());
                return true;
            } catch (Exception e) {
                logger.error("Error generating network visualization", e);
                return false;
            }
        }

        private String generateNodesJs() {
            StringBuilder sb = new StringBuilder();
            for (Device device : devices.values()) {
                sb.append(String.format(
                        "            { id: '%s', label: '%s\\n%s', title: '%s', color: '%s', shape: '%s' },\n",
                        device.getIp(),
                        device.getHostname(),
                        device.getIp(),
                        generateTooltip(device),
                        getNodeColor(device),
                        getNodeShape(device)
                ));
            }
            return sb.toString();
        }

        private String generateEdgesJs() {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, List<String>> entry : connections.entrySet()) {
                String source = entry.getKey();
                for (String target : entry.getValue()) {
                    sb.append(String.format(
                            "            { from: '%s', to: '%s', title: 'network' },\n",
                            source, target
                    ));
                }
            }
            return sb.toString();
        }

        private String generateTooltip(Device device) {
            return String.format(
                    "IP: %s<br>Hostname: %s<br>MAC: %s<br>Vendor: %s<br>OS: %s<br>Ports: %s",
                    device.getIp(),
                    device.getHostname(),
                    device.getMac(),
                    device.getVendor(),
                    device.getOs(),
                    device.getPorts()
            );
        }

        private String getNodeColor(Device device) {
            if (device.hasService("http") || device.hasService("https")) return "#9999ff"; // blue
            if (device.hasService("ssh")) return "#ffff99"; // yellow
            if (device.hasService("rdp")) return "#99ff99"; // green
            return "#cccccc"; // gray
        }

        private String getNodeShape(Device device) {
            if (device.hasService("http") || device.hasService("https")) return "box";
            if (device.hasService("ssh")) return "diamond";
            if (device.hasService("rdp")) return "square";
            return "dot";
        }

        }
    }