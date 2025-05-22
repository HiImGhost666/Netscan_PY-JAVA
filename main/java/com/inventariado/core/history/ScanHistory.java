package com.inventariado.core.history;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import org.slf4j.*;
import com.fasterxml.jackson.databind.ObjectMapper;


/**

 Gestiona el historial de escaneos y comparación de cambios.
 */
public class ScanHistory {
    private static final Logger logger = LoggerFactory.getLogger(ScanHistory.class);

    private final String dbPath;
    private final ObjectMapper objectMapper;

    public ScanHistory() {
        this("network_history.db");
    }

    public ScanHistory(String dbPath) {
        this.dbPath = dbPath;
        this.objectMapper = new ObjectMapper();
        initDatabase();
    }

    private void initDatabase() {
        try (Connection conn = getConnection()) {
            // Create tables if they don't exist
            Statement stmt = conn.createStatement();
            stmt.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                description TEXT,
                network_version TEXT
            )""");

            stmt.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                device_data TEXT NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )""");

            logger.info("Database initialized successfully");
        } catch (SQLException e) {
            logger.error("Error initializing database: {}", e.getMessage());
            throw new RuntimeException("Failed to initialize database", e);
        }
    }

    public Integer saveScan(Map<String, Object> scanData, String description) {
        try (Connection conn = getConnection()) {
            conn.setAutoCommit(false);

            // Insert scan
            String sql = """
            INSERT INTO scans (timestamp, description, network_version) 
            VALUES (?, ?, ?)""";
            PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            pstmt.setString(1, LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            pstmt.setString(2, description);
            pstmt.setString(3, (String) scanData.getOrDefault("network_version", "1.0"));
            pstmt.executeUpdate();

            ResultSet rs = pstmt.getGeneratedKeys();
            int scanId = rs.next() ? rs.getInt(1) : 0;

            // Save devices
            List<Map<String, Object>> devices = (List<Map<String, Object>>)
                    scanData.getOrDefault("devices", new ArrayList<>());

            for (Map<String, Object> device : devices) {
                String ip = (String) device.get("ip");
                String status = getLastDeviceStatus(conn, ip);

                sql = """
                INSERT INTO devices (scan_id, ip, hostname, device_data, status)
                VALUES (?, ?, ?, ?, ?)""";
                pstmt = conn.prepareStatement(sql);
                pstmt.setInt(1, scanId);
                pstmt.setString(2, ip);
                pstmt.setString(3, (String) device.getOrDefault("hostname", ""));
                pstmt.setString(4, objectMapper.writeValueAsString(device));
                pstmt.setString(5, status);
                pstmt.executeUpdate();
            }

            conn.commit();
            return scanId;
        } catch (Exception e) {
            logger.error("Error saving scan: {}", e.getMessage());
            return null;
        }
    }

    private String getLastDeviceStatus(Connection conn, String ip) throws SQLException {
        String sql = """
SELECT status FROM devices
WHERE ip = ?
ORDER BY scan_id DESC
LIMIT 1
""";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, ip);
        ResultSet rs = pstmt.executeQuery();
        return rs.next() ? rs.getString("status") : "pending";
    }

    public Map<String, Object> compareScans(int scanId1, int scanId2) {
        try (Connection conn = getConnection()) {
// Validar que existen ambos escaneos
            if (!scanExists(conn, scanId1) || !scanExists(conn, scanId2)) {
                logger.error("Uno o ambos IDs de escaneo no existen");
                return null;
            }

            List<Map<String, Object>> devices1 = getScanDevices(conn, scanId1);
            List<Map<String, Object>> devices2 = getScanDevices(conn, scanId2);

            Map<String, Object> changes = new HashMap<>();
            changes.put("new_devices", new ArrayList<>());
            changes.put("removed_devices", new ArrayList<>());
            changes.put("modified_devices", new ArrayList<>());
            changes.put("port_changes", new ArrayList<>());
            changes.put("service_changes", new ArrayList<>());
            changes.put("status_changes", new ArrayList<>());

            // Detectar dispositivos nuevos y eliminados
            Set<String> ips1 = new HashSet<>();
            Set<String> ips2 = new HashSet<>();

            for (Map<String, Object> device : devices1) {
                ips1.add((String) device.get("ip"));
            }

            for (Map<String, Object> device : devices2) {
                ips2.add((String) device.get("ip"));
            }

            // Dispositivos nuevos
            Set<String> newIps = new HashSet<>(ips2);
            newIps.removeAll(ips1);
            ((List<String>) changes.get("new_devices")).addAll(newIps);

            // Dispositivos eliminados
            Set<String> removedIps = new HashSet<>(ips1);
            removedIps.removeAll(ips2);
            ((List<String>) changes.get("removed_devices")).addAll(removedIps);

            // Comparar dispositivos existentes
            for (Map<String, Object> device1 : devices1) {
                for (Map<String, Object> device2 : devices2) {
                    if (device1.get("ip").equals(device2.get("ip"))) {
                        List<Map<String, Object>> deviceChanges = compareDevices(device1, device2);
                        if (!deviceChanges.isEmpty()) {
                            Map<String, Object> modifiedDevice = new HashMap<>();
                            modifiedDevice.put("ip", device1.get("ip"));
                            modifiedDevice.put("changes", deviceChanges);
                            modifiedDevice.put("current_status", device2.getOrDefault("status", "pending"));
                            ((List<Map<String, Object>>) changes.get("modified_devices")).add(modifiedDevice);
                        }
                    }
                }
            }

            return changes;
        } catch (Exception e) {
            logger.error("Error al comparar escaneos: {}", e.getMessage());
            return null;
        }
    }

    private boolean scanExists(Connection conn, int scanId) throws SQLException {
        String sql = "SELECT id FROM scans WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setInt(1, scanId);
        ResultSet rs = pstmt.executeQuery();
        return rs.next();
    }

    private List<Map<String, Object>> getScanDevices(Connection conn, int scanId) throws Exception {
        String sql = "SELECT device_data FROM devices WHERE scan_id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setInt(1, scanId);
        ResultSet rs = pstmt.executeQuery();
        List<Map<String, Object>> devices = new ArrayList<>();
        while (rs.next()) {
            devices.add(objectMapper.readValue(rs.getString("device_data"), Map.class));
        }
        return devices;
    }

    private List<Map<String, Object>> compareDevices(Map<String, Object> device1, Map<String, Object> device2) {
        List<Map<String, Object>> changes = new ArrayList<>();
        // Comparar servicios
        Map<String, Map<String, Object>> services1 = (Map<String, Map<String, Object>>)
                device1.getOrDefault("services", new HashMap<>());
        Map<String, Map<String, Object>> services2 = (Map<String, Map<String, Object>>)
                device2.getOrDefault("services", new HashMap<>());

        // Nuevos servicios
        for (String port : services2.keySet()) {
            if (!services1.containsKey(port)) {
                Map<String, Object> change = new HashMap<>();
                change.put("type", "new_service");
                change.put("port", port);
                change.put("service", services2.get(port));
                changes.add(change);
            }
        }

        // Servicios eliminados
        for (String port : services1.keySet()) {
            if (!services2.containsKey(port)) {
                Map<String, Object> change = new HashMap<>();
                change.put("type", "removed_service");
                change.put("port", port);
                change.put("service", services1.get(port));
                changes.add(change);
            }
        }

        // Cambios en sistema operativo
        if (!Objects.equals(device1.get("os"), device2.get("os"))) {
            Map<String, Object> change = new HashMap<>();
            change.put("type", "os_change");
            change.put("old", device1.get("os"));
            change.put("new", device2.get("os"));
            changes.add(change);
        }

        // Cambios en hostname
        if (!Objects.equals(device1.get("hostname"), device2.get("hostname"))) {
            Map<String, Object> change = new HashMap<>();
            change.put("type", "hostname_change");
            change.put("old", device1.get("hostname"));
            change.put("new", device2.get("hostname"));
            changes.add(change);
        }

        return changes;
    }

    public boolean updateDeviceStatus(String ip, String status) {
        if (!List.of("approved", "pending", "review", "inactive").contains(status)) {
            logger.error("Estado inválido: {}", status);
            return false;
        }

        try (Connection conn = getConnection()) {
            String sql = """
                UPDATE devices 
                SET status = ? 
                WHERE ip = ? 
                AND scan_id = (SELECT MAX(scan_id) FROM devices WHERE ip = ?)
            """;
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, status);
            pstmt.setString(2, ip);
            pstmt.setString(3, ip);
            int affectedRows = pstmt.executeUpdate();
            return affectedRows > 0;
        } catch (SQLException e) {
            logger.error("Error al actualizar estado del dispositivo: {}", e.getMessage());
            return false;
        }
    }

    public List<Map<String, Object>> getDeviceHistory(String ip) {
        try (Connection conn = getConnection()) {
            String sql = """
                SELECT s.timestamp, d.device_data
                FROM devices d
                JOIN scans s ON d.scan_id = s.id
                WHERE d.ip = ?
                ORDER BY s.timestamp DESC
            """;
            PreparedStatement pstmt = conn.prepareStatement(sql);
            pstmt.setString(1, ip);
            ResultSet rs = pstmt.executeQuery();

            List<Map<String, Object>> history = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> entry = new HashMap<>();
                entry.put("timestamp", rs.getString("timestamp"));
                entry.put("device_data", objectMapper.readValue(rs.getString("device_data"), Map.class));
                history.add(entry);
            }
            return history;
        } catch (Exception e) {
            logger.error("Error al obtener historial de dispositivo: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + dbPath);
    }
}

