package com.inventariado.core.inventory;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.logging.Logger;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

/**
 * Clase para gestionar el inventario de activos IT.
 * Equivalente Java de inventory.py
 */
public class InventoryManager {
    private static final Logger logger = Logger.getLogger(InventoryManager.class.getName());
    private static final Gson gson = new Gson();

    private final String dbPath;

    public InventoryManager() {
        this("inventory.db");
    }

    public InventoryManager(String dbPath) {
        this.dbPath = dbPath;
        initDatabase();
    }

    private void initDatabase() {
        try (Connection conn = getConnection()) {
            // Tabla de escaneos
            conn.createStatement().execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TIMESTAMP,
                    network_range TEXT,
                    total_devices INTEGER
                )
            """);

            // Tabla de dispositivos
            conn.createStatement().execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    ip TEXT,
                    hostname TEXT,
                    mac TEXT,
                    vendor TEXT,
                    os TEXT,
                    device_type TEXT,
                    location TEXT,
                    responsible TEXT,
                    tags TEXT,
                    services TEXT,
                    last_seen TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """);

            // Tabla de cambios
            conn.createStatement().execute("""
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    change_date TIMESTAMP,
                    change_type TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            """);

            logger.info("Base de datos inicializada correctamente");
        } catch (SQLException e) {
            logger.severe("Error al inicializar la base de datos: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public int storeScanResults(String networkRange, List<Map<String, Object>> devices) {
        try (Connection conn = getConnection()) {
            conn.setAutoCommit(false);

            // Insertar registro de escaneo
            try (PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO scans (scan_date, network_range, total_devices) VALUES (?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS)) {
                stmt.setTimestamp(1, Timestamp.valueOf(LocalDateTime.now()));
                stmt.setString(2, networkRange);
                stmt.setInt(3, devices.size());
                stmt.executeUpdate();

                ResultSet rs = stmt.getGeneratedKeys();
                int scanId = rs.next() ? rs.getInt(1) : -1;

                // Insertar dispositivos
                for (Map<String, Object> device : devices) {
                    storeDevice(conn, scanId, device);
                }

                conn.commit();
                logger.info("Resultados del escaneo almacenados. ID: " + scanId);
                return scanId;
            }
        } catch (SQLException e) {
            logger.severe("Error al almacenar resultados del escaneo: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void storeDevice(Connection conn, int scanId, Map<String, Object> device) throws SQLException {
        // Buscar dispositivo existente por MAC o IP
        String mac = (String) device.get("mac");
        String ip = (String) device.get("ip");

        try (PreparedStatement stmt = conn.prepareStatement(
                "SELECT id, hostname, os, services FROM devices WHERE mac = ? OR (mac IS NULL AND ip = ?)")) {
            stmt.setString(1, mac);
            stmt.setString(2, ip);

            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                int deviceId = rs.getInt("id");
                String oldHostname = rs.getString("hostname");
                String oldOs = rs.getString("os");
                String oldServices = rs.getString("services");

                // Registrar cambios
                registerChanges(conn, deviceId, oldHostname, oldOs, oldServices, device);

                // Actualizar dispositivo
                try (PreparedStatement updateStmt = conn.prepareStatement(
                        "UPDATE devices SET scan_id = ?, hostname = ?, os = ?, vendor = ?, services = ?, last_seen = ? WHERE id = ?")) {
                    updateStmt.setInt(1, scanId);
                    updateStmt.setString(2, (String) device.get("hostname"));
                    updateStmt.setString(3, (String) device.get("os"));
                    updateStmt.setString(4, (String) device.get("vendor"));
                    updateStmt.setString(5, gson.toJson(device.get("services")));
                    updateStmt.setTimestamp(6, Timestamp.valueOf(LocalDateTime.now()));
                    updateStmt.setInt(7, deviceId);
                    updateStmt.executeUpdate();
                }
            } else {
                // Insertar nuevo dispositivo
                try (PreparedStatement insertStmt = conn.prepareStatement(
                        "INSERT INTO devices (scan_id, ip, hostname, mac, vendor, os, services, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {
                    insertStmt.setInt(1, scanId);
                    insertStmt.setString(2, ip);
                    insertStmt.setString(3, (String) device.get("hostname"));
                    insertStmt.setString(4, mac);
                    insertStmt.setString(5, (String) device.get("vendor"));
                    insertStmt.setString(6, (String) device.get("os"));
                    insertStmt.setString(7, gson.toJson(device.get("services")));
                    insertStmt.setTimestamp(8, Timestamp.valueOf(LocalDateTime.now()));
                    insertStmt.executeUpdate();
                }
            }
        }
    }

    private void registerChanges(Connection conn, int deviceId, String oldHostname, String oldOs,
                                 String oldServices, Map<String, Object> newDevice) throws SQLException {
        String newHostname = (String) newDevice.get("hostname");
        String newOs = (String) newDevice.get("os");
        String newServices = gson.toJson(newDevice.get("services"));

        // Comparar y registrar cambios
        if (!Objects.equals(oldHostname, newHostname)) {
            addChange(conn, deviceId, "hostname", oldHostname, newHostname);
        }

        if (!Objects.equals(oldOs, newOs)) {
            addChange(conn, deviceId, "os", oldOs, newOs);
        }

        // Comparar servicios
        if (!Objects.equals(oldServices, newServices)) {
            addChange(conn, deviceId, "services", oldServices, newServices);
        }
    }

    private void addChange(Connection conn, int deviceId, String changeType,
                           String oldValue, String newValue) throws SQLException {
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO changes (device_id, change_date, change_type, old_value, new_value) VALUES (?, ?, ?, ?, ?)")) {
            stmt.setInt(1, deviceId);
            stmt.setTimestamp(2, Timestamp.valueOf(LocalDateTime.now()));
            stmt.setString(3, changeType);
            stmt.setString(4, oldValue);
            stmt.setString(5, newValue);
            stmt.executeUpdate();
        }
    }

    public List<Map<String, Object>> getDeviceHistory(int deviceId) {
        List<Map<String, Object>> changes = new ArrayList<>();

        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                     "SELECT change_date, change_type, old_value, new_value FROM changes " +
                             "WHERE device_id = ? ORDER BY change_date DESC")) {
            stmt.setInt(1, deviceId);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Map<String, Object> change = new HashMap<>();
                change.put("date", rs.getTimestamp("change_date").toLocalDateTime());
                change.put("type", rs.getString("change_type"));
                change.put("old_value", rs.getString("old_value"));
                change.put("new_value", rs.getString("new_value"));
                changes.add(change);
            }
        } catch (SQLException e) {
            logger.severe("Error al obtener historial del dispositivo: " + e.getMessage());
        }

        return changes;
    }

    public boolean updateDeviceInfo(int deviceId, Map<String, Object> info) {
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                     "UPDATE devices SET device_type = ?, location = ?, responsible = ?, tags = ? WHERE id = ?")) {

            stmt.setString(1, (String) info.get("device_type"));
            stmt.setString(2, (String) info.get("location"));
            stmt.setString(3, (String) info.get("responsible"));
            stmt.setString(4, gson.toJson(info.get("tags")));
            stmt.setInt(5, deviceId);

            int rowsUpdated = stmt.executeUpdate();
            return rowsUpdated > 0;
        } catch (SQLException e) {
            logger.severe("Error al actualizar información del dispositivo: " + e.getMessage());
            return false;
        }
    }

    public Map<String, Object> getScanComparison(int scanId1, int scanId2) {
        Map<String, Object> result = new HashMap<>();

        try (Connection conn = getConnection()) {
            // Obtener dispositivos de ambos escaneos
            Map<String, Map<String, Object>> devices1 = getScanDevices(conn, scanId1);
            Map<String, Map<String, Object>> devices2 = getScanDevices(conn, scanId2);

            // Analizar diferencias
            Set<String> newDevices = new HashSet<>(devices2.keySet());
            newDevices.removeAll(devices1.keySet());

            Set<String> removedDevices = new HashSet<>(devices1.keySet());
            removedDevices.removeAll(devices2.keySet());

            Map<String, Map<String, Map<String, Object>>> changedDevices = new HashMap<>();

            // Detectar cambios en dispositivos existentes
            for (String ip : devices1.keySet()) {
                if (devices2.containsKey(ip)) {
                    Map<String, Map<String, Object>> changes = new HashMap<>();

                    compareField("hostname", devices1.get(ip), devices2.get(ip), changes);
                    compareField("os", devices1.get(ip), devices2.get(ip), changes);
                    compareField("services", devices1.get(ip), devices2.get(ip), changes);

                    if (!changes.isEmpty()) {
                        changedDevices.put(ip, changes);
                    }
                }
            }

            result.put("new_devices", new ArrayList<>(newDevices));
            result.put("removed_devices", new ArrayList<>(removedDevices));
            result.put("changed_devices", changedDevices);

        } catch (SQLException e) {
            logger.severe("Error al comparar escaneos: " + e.getMessage());
            result.put("error", e.getMessage());
        }

        return result;
    }

    private Map<String, Map<String, Object>> getScanDevices(Connection conn, int scanId) throws SQLException {
        Map<String, Map<String, Object>> devices = new HashMap<>();

        try (PreparedStatement stmt = conn.prepareStatement(
                "SELECT ip, mac, hostname, os, services FROM devices WHERE scan_id = ?")) {
            stmt.setInt(1, scanId);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Map<String, Object> device = new HashMap<>();
                String ip = rs.getString("ip");

                device.put("mac", rs.getString("mac"));
                device.put("hostname", rs.getString("hostname"));
                device.put("os", rs.getString("os"));
                device.put("services", gson.fromJson(rs.getString("services"),
                        new TypeToken<Map<String, Object>>(){}.getType()));

                devices.put(ip, device);
            }
        }

        return devices;
    }

    private void compareField(String field, Map<String, Object> oldDevice,
                              Map<String, Object> newDevice, Map<String, Map<String, Object>> changes) {
        Object oldValue = oldDevice.get(field);
        Object newValue = newDevice.get(field);

        if (!Objects.equals(oldValue, newValue)) {
            Map<String, Object> change = new HashMap<>();
            change.put("old", oldValue);
            change.put("new", newValue);
            changes.put(field, change);
        }
    }

    public List<Map<String, Object>> getRecentScans(int limit) {
        List<Map<String, Object>> scans = new ArrayList<>();

        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                     "SELECT id, scan_date, network_range, total_devices FROM scans " +
                             "ORDER BY scan_date DESC LIMIT ?")) {
            stmt.setInt(1, limit);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Map<String, Object> scan = new HashMap<>();
                scan.put("id", rs.getInt("id"));
                scan.put("date", rs.getTimestamp("scan_date").toLocalDateTime());
                scan.put("network_range", rs.getString("network_range"));
                scan.put("total_devices", rs.getInt("total_devices"));
                scans.add(scan);
            }
        } catch (SQLException e) {
            logger.severe("Error al obtener escaneos recientes: " + e.getMessage());
        }

        return scans;
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + dbPath);
    }
}
