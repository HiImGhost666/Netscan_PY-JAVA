package com.inventariado.core.topology;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import org.json.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**

 Clase para manejar y visualizar la topología de red
 */
public class TopologyManager {
    private static final Logger logger = LoggerFactory.getLogger(TopologyManager.class);

    private Map<String, Map<String, Object>> graph = new HashMap<>();
    private Map<String, Map<String, String>> deviceTypes = new HashMap<>();

    public TopologyManager() {
// Inicializar tipos de dispositivos con sus estilos
        deviceTypes.put("router", Map.of(
                "color", "#ff9999",
                "shape", "diamond"
        ));
        deviceTypes.put("switch", Map.of(
                "color", "#99ff99",
                "shape", "square"
        ));
        deviceTypes.put("server", Map.of(
                "color", "#9999ff",
                "shape", "box"
        ));
        deviceTypes.put("workstation", Map.of(
                "color", "#ffff99",
                "shape", "dot"
        ));
        deviceTypes.put("printer", Map.of(
                "color", "#ff99ff",
                "shape", "triangle"
        ));
        deviceTypes.put("camera", Map.of(
                "color", "#99ffff",
                "shape", "star"
        ));
        deviceTypes.put("unknown", Map.of(
                "color", "#cccccc",
                "shape", "dot"
        ));
    }

    /**

     Añade un dispositivo al grafo
     */
    public void addDevice(Map<String, Object> deviceData) {
        try {
            String deviceType = determineDeviceType(deviceData);
            Map<String, String> style = deviceTypes.getOrDefault(deviceType, deviceTypes.get("unknown"));
            // Crear etiqueta con información relevante
            String label = deviceData.getOrDefault("hostname", "") + "\n" +
                    deviceData.getOrDefault("ip", "");

            // Añadir nodo al grafo
            Map<String, Object> node = new HashMap<>();
            node.put("title", createNodeTooltip(deviceData));
            node.put("label", label);
            node.put("color", style.get("color"));
            node.put("shape", style.get("shape"));

            graph.put((String) deviceData.get("ip"), node);
        } catch (Exception e) {
            logger.error("Error al añadir dispositivo a la topología: {}", e.getMessage());
        }
    }

    /**

     Añade una conexión entre dos dispositivos
     */
    public void addConnection(String source, String target, String connectionType) {
        try {
            if (!graph.containsKey(source)) {
                graph.put(source, new HashMap<>());
            }
            if (!graph.containsKey(target)) {
                graph.put(target, new HashMap<>());
            }

            Map<String, Object> sourceNode = graph.get(source);
            Map<String, Object> connections = (Map<String, Object>) sourceNode.getOrDefault("connections", new HashMap<>());
            connections.put(target, Map.of("type", connectionType));
            sourceNode.put("connections", connections);
        } catch (Exception e) {
            logger.error("Error al añadir conexión a la topología: {}", e.getMessage());
        }
    }

    private String determineDeviceType(Map<String, Object> deviceData) {
        Map<String, Object> services = (Map<String, Object>) deviceData.getOrDefault("services", new HashMap<>());
        String osInfo = ((String) deviceData.getOrDefault("os", "")).toLowerCase();
        // Detectar router
        if (services.keySet().stream().anyMatch(port ->
                port.equals("23") || port.equals("53") || port.equals("67") || port.equals("68") || port.equals("161"))) {
            return "router";
        }

        // Detectar switch
        if (services.containsKey("161") || osInfo.contains("switch")) {
            return "switch";
        }

        // Detectar servidor
        if (services.keySet().stream().anyMatch(port ->
                port.equals("21") || port.equals("22") || port.equals("80") ||
                        port.equals("443") || port.equals("3306") || port.equals("1433"))) {
            return "server";
        }

        // Detectar impresora
        if (services.keySet().stream().anyMatch(port ->
                port.equals("515") || port.equals("631") || port.equals("9100"))) {
            return "printer";
        }

        // Detectar cámara
        if (services.keySet().stream().anyMatch(port ->
                port.equals("554") || port.equals("8000") || port.equals("8080") || port.equals("8081"))) {
            return "camera";
        }

        // Detectar estación de trabajo
        if (osInfo.contains("windows") || osInfo.contains("linux") || osInfo.contains("mac")) {
            return "workstation";
        }

        return "unknown";
    }

    private String createNodeTooltip(Map<String, Object> deviceData) {
        StringBuilder tooltip = new StringBuilder();
        tooltip.append("<b>IP:</b> ").append(deviceData.getOrDefault("ip", "N/A")).append("<br>");
        tooltip.append("<b>Hostname:</b> ").append(deviceData.getOrDefault("hostname", "N/A")).append("<br>");
        tooltip.append("<b>MAC:</b> ").append(deviceData.getOrDefault("mac", "N/A")).append("<br>");
        tooltip.append("<b>OS:</b> ").append(deviceData.getOrDefault("os", "N/A")).append("<br>");
        tooltip.append("<b>Vendor:</b> ").append(deviceData.getOrDefault("vendor", "N/A")).append("<br>");
        // Añadir servicios
        Map<String, Object> services = (Map<String, Object>) deviceData.getOrDefault("services", new HashMap<>());
        if (!services.isEmpty()) {
            tooltip.append("<b>Servicios:</b><br>");
            for (Map.Entry<String, Object> entry : services.entrySet()) {
                Map<String, Object> service = (Map<String, Object>) entry.getValue();
                tooltip.append("- Puerto ").append(entry.getKey()).append(": ")
                        .append(service.getOrDefault("name", "unknown")).append("<br>");
            }
        }

        return tooltip.toString();
    }

    /**

     Exporta la topología a un archivo JSON
     */
    public boolean exportTopology(String outputPath) {
        try (FileWriter file = new FileWriter(outputPath)) {
            JSONObject topologyData = new JSONObject();
            JSONArray nodes = new JSONArray();
            JSONArray edges = new JSONArray();
            for (Map.Entry<String, Map<String, Object>> entry : graph.entrySet()) {
                JSONObject node = new JSONObject(entry.getValue());
                node.put("id", entry.getKey());
                nodes.put(node);

                if (entry.getValue().containsKey("connections")) {
                    Map<String, Object> connections = (Map<String, Object>) entry.getValue().get("connections");
                    for (String target : connections.keySet()) {
                        JSONObject edge = new JSONObject();
                        edge.put("from", entry.getKey());
                        edge.put("to", target);
                        edge.put("type", ((Map<?, ?>) connections.get(target)).get("type"));
                        edges.put(edge);
                    }
                }
            }

            topologyData.put("nodes", nodes);
            topologyData.put("edges", edges);

            file.write(topologyData.toString(4));
            logger.info("Topología exportada a {}", outputPath);
            return true;
        } catch (Exception e) {
            logger.error("Error al exportar la topología: {}", e.getMessage());
            return false;
        }
    }

    /**

     Importa la topología desde un archivo JSON
     */
    public boolean importTopology(String inputPath) {
        try {
            String jsonData = new String(Files.readAllBytes(Paths.get(inputPath)));
            JSONObject topologyData = new JSONObject(jsonData);
            graph.clear();

            JSONArray nodes = topologyData.getJSONArray("nodes");
            for (int i = 0; i < nodes.length(); i++) {
                JSONObject node = nodes.getJSONObject(i);
                String id = node.getString("id");
                Map<String, Object> nodeData = new HashMap<>();

                Iterator<String> keys = node.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    if (!key.equals("id")) {
                        nodeData.put(key, node.get(key));
                    }
                }

                graph.put(id, nodeData);
            }

            JSONArray edges = topologyData.getJSONArray("edges");
            for (int i = 0; i < edges.length(); i++) {
                JSONObject edge = edges.getJSONObject(i);
                String from = edge.getString("from");
                String to = edge.getString("to");
                String type = edge.getString("type");

                addConnection(from, to, type);
            }

            logger.info("Topología importada desde {}", inputPath);
            return true;
        } catch (Exception e) {
            logger.error("Error al importar la topología: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Genera la visualización HTML de la topología
     * Nota: Esta implementación básica crea un esqueleto HTML que luego puede ser
     *       completado con JavaScript para visualizar el grafo
     */
    public boolean generateHtml(String outputPath) {
        try {
            String jsonData = convertGraphToJson();
            String htmlContent = "<!DOCTYPE html>\n" +
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
                    "        var topologyData = " + jsonData + ";\n" +
                    "        \n" +
                    "        var nodes = new vis.DataSet(topologyData.nodes);\n" +
                    "        var edges = new vis.DataSet(topologyData.edges);\n" +
                    "        \n" +
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
                    "                solver: 'forceAtlas2Based'\n" +
                    "            }\n" +
                    "        };\n" +
                    "        \n" +
                    "        var network = new vis.Network(container, data, options);\n" +
                    "    </script>\n" +
                    "</body>\n" +
                    "</html>";

            Files.write(Paths.get(outputPath), htmlContent.getBytes());
            logger.info("Visualización HTML generada en {}", outputPath);
            return true;
        } catch (Exception e) {
            logger.error("Error al generar la visualización HTML: {}", e.getMessage());
            return false;
        }
    }

    private String convertGraphToJson() {
        try {
            JSONObject json = new JSONObject();
            JSONArray nodes = new JSONArray();
            JSONArray edges = new JSONArray();

            for (Map.Entry<String, Map<String, Object>> entry : graph.entrySet()) {
                JSONObject node = new JSONObject(entry.getValue());
                node.put("id", entry.getKey());
                nodes.put(node);

                if (entry.getValue().containsKey("connections")) {
                    Map<String, Object> connections = (Map<String, Object>) entry.getValue().get("connections");
                    for (Map.Entry<String, Object> conn : connections.entrySet()) {
                        JSONObject edge = new JSONObject();
                        edge.put("from", entry.getKey());
                        edge.put("to", conn.getKey());
                        edge.put("type", ((Map<?, ?>) conn.getValue()).get("type"));
                        edges.put(edge);
                    }
                }
            }

            json.put("nodes", nodes);
            json.put("edges", edges);
            return json.toString();
        } catch (Exception e) {
            logger.error("Error al convertir grafo a JSON: {}", e.getMessage());
            return "{\"nodes\":[], \"edges\":[]}";
        }
    }
}
