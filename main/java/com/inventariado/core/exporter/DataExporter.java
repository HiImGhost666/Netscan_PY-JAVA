package com.inventariado.core.exporter;

import org.json.*;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class DataExporter {

    // Método para exportar a CSV
    public static boolean exportToCSV(List<Map<String, Object>> devices, String filename) {
        try {
            // Asegurarse de que el directorio exista
            Path filePath = Paths.get(filename);
            Files.createDirectories(filePath.getParent());

            try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
                // Definir las columnas
                List<String> fieldnames = Arrays.asList(
                        "ip", "hostname", "mac", "vendor", "os", "ports", "serial", "model",
                        "services_details", "users", "cpu_info", "memory_info", "storage_info",
                        "geolocation", "ttl");

                // Escribir la cabecera
                writer.write(String.join(",", fieldnames));
                writer.newLine();

                // Escribir los datos de los dispositivos
                for (Map<String, Object> device : devices) {
                    String servicesStr = new JSONObject(device.get("services")).toString();
                    String usersStr = new JSONArray((List<?>) device.get("users")).toString();

                    Map<String, Object> hardware = (Map<String, Object>) device.get("hardware");
                    String cpuInfo = new JSONObject(hardware.get("cpu")).toString();
                    String memoryInfo = new JSONObject(hardware.get("memory")).toString();
                    String storageInfo = new JSONArray((List<?>) hardware.get("storage")).toString();

                    StringBuilder portsStr = new StringBuilder();
                    Map<String, Object> services = (Map<String, Object>) device.get("services");
                    for (String port : services.keySet()) {
                        if (portsStr.length() > 0) portsStr.append(", ");
                        portsStr.append(port);
                    }

                    String geoStr = new JSONObject(device.get("geolocation")).toString();

                    // Escribir los valores
                    writer.write(String.join(",", Arrays.asList(
                            String.valueOf(device.get("ip")),
                            String.valueOf(device.get("hostname")),
                            String.valueOf(device.get("mac")),
                            String.valueOf(device.get("vendor")),
                            String.valueOf(device.get("os")),
                            portsStr.toString(),
                            String.valueOf(device.get("serial")),
                            String.valueOf(device.get("model")),
                            servicesStr,
                            usersStr,
                            cpuInfo,
                            memoryInfo,
                            storageInfo,
                            geoStr,
                            String.valueOf(device.get("ttl"))
                    )));
                    writer.newLine();
                }
            }

            System.out.println("Datos exportados exitosamente a " + filename);
            return true;
        } catch (IOException | JSONException e) {
            System.err.println("Error al exportar a CSV: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // Método para exportar a JSON
    public static boolean exportToJSON(List<Map<String, Object>> devices, String filename) {
        try {
            // Asegurarse de que el directorio exista
            Path filePath = Paths.get(filename);
            Files.createDirectories(filePath.getParent());

            try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
                writer.write(new JSONArray(devices).toString(4));
            }

            System.out.println("Datos exportados exitosamente a " + filename);
            return true;
        } catch (IOException | JSONException e) {
            System.err.println("Error al exportar a JSON: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // Método para importar desde CSV
    public static List<Map<String, Object>> importFromCSV(String filename) {
        List<Map<String, Object>> devices = new ArrayList<>();
        try {
            List<String> lines = Files.readAllLines(Paths.get(filename));
            String header = lines.get(0);
            List<String> fieldnames = Arrays.asList(header.split(","));

            for (int i = 1; i < lines.size(); i++) {
                String line = lines.get(i);
                String[] values = line.split(",");

                Map<String, Object> device = new HashMap<>();
                device.put("ip", values[0]);
                device.put("hostname", values[1]);
                device.put("mac", values[2]);
                device.put("vendor", values[3]);
                device.put("os", values[4]);

                // Convertir los puertos
                Map<String, Object> services = new HashMap<>();
                String[] ports = values[5].split(",");
                for (String port : ports) {
                    if (port.trim().matches("\\d+")) {
                        services.put(port.trim(), new JSONObject()
                                .put("name", "unknown")
                                .put("product", "")
                                .put("version", ""));
                    }
                }
                device.put("services", services);

                // Rellenar el resto de campos
                device.put("serial", values[6]);
                device.put("model", values[7]);
                device.put("users", new ArrayList<>());
                device.put("hardware", new JSONObject()
                        .put("cpu", new JSONObject()
                                .put("model", "")
                                .put("cores", 0)
                                .put("threads", 0)
                                .put("speed", ""))
                        .put("memory", new JSONObject()
                                .put("total", "")
                                .put("type", "")
                                .put("slots", new JSONArray()))
                        .put("storage", new JSONArray()));

                devices.add(device);
            }

            System.out.println("Se importaron " + devices.size() + " dispositivos desde " + filename);
            return devices;
        } catch (IOException | JSONException e) {
            System.err.println("Error al importar desde CSV: " + e.getMessage());
            e.printStackTrace();
            return devices;
        }
    }

    // Método para importar desde JSON
    public static List<Map<String, Object>> importFromJSON(String filename) {
        List<Map<String, Object>> devices = new ArrayList<>();
        try {
            String content = new String(Files.readAllBytes(Paths.get(filename)));
            JSONArray jsonArray = new JSONArray(content);
            devices.clear();  // si ya existe y quieres reemplazar contenido anterior

            for (Object obj : jsonArray) {
                if (obj instanceof Map<?, ?>) {
                    devices.add((Map<String, Object>) obj);
                }
            }


            System.out.println("Se importaron " + devices.size() + " dispositivos desde " + filename);
            return devices;
        } catch (IOException | JSONException e) {
            System.err.println("Error al importar desde JSON: " + e.getMessage());
            e.printStackTrace();
            return devices;
        }
    }
}
