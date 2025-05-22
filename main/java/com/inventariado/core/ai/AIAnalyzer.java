package com.inventariado.core.ai;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.Logger;

/**
 * Clase para análisis inteligente de dispositivos y red.
 * Equivalente Java de ai_analyzer.py
 */
public class AIAnalyzer {
    private static final Logger logger = Logger.getLogger(AIAnalyzer.class.getName());

    // Reglas para clasificación de dispositivos
    private final Map<String, Map<String, Object>> deviceRules;

    // Pesos para la puntuación de seguridad
    private final Map<String, Integer> securityWeights;

    // Patrones de versiones conocidas como seguras/inseguras
    private final Map<String, Map<String, List<String>>> versionPatterns;

    public AIAnalyzer() {
        // Inicializar reglas para clasificación de dispositivos
        this.deviceRules = new HashMap<>();

        Map<String, Object> routerRules = new HashMap<>();
        routerRules.put("ports", Arrays.asList(53, 67, 68, 161)); // DNS, DHCP, SNMP
        routerRules.put("keywords", Arrays.asList("router", "gateway", "mikrotik", "cisco"));

        Map<String, Object> switchRules = new HashMap<>();
        switchRules.put("ports", Arrays.asList(161, 162)); // SNMP
        switchRules.put("keywords", Arrays.asList("switch", "catalyst", "procurve"));

        Map<String, Object> serverRules = new HashMap<>();
        serverRules.put("ports", Arrays.asList(21, 22, 80, 443, 3306, 1433)); // FTP, SSH, HTTP(S), MySQL, MSSQL
        serverRules.put("keywords", Arrays.asList("server", "windows server", "ubuntu server", "centos"));

        Map<String, Object> workstationRules = new HashMap<>();
        workstationRules.put("ports", Arrays.asList(135, 139, 445)); // NetBIOS, SMB
        workstationRules.put("keywords", Arrays.asList("windows", "desktop", "workstation"));

        Map<String, Object> printerRules = new HashMap<>();
        printerRules.put("ports", Arrays.asList(515, 631, 9100)); // LPD, IPP, Raw Print
        printerRules.put("keywords", Arrays.asList("printer", "hp", "epson", "canon"));

        Map<String, Object> cameraRules = new HashMap<>();
        cameraRules.put("ports", Arrays.asList(554, 8000, 8080)); // RTSP, HTTP Stream
        cameraRules.put("keywords", Arrays.asList("camera", "ipcam", "axis", "hikvision"));

        this.deviceRules.put("router", routerRules);
        this.deviceRules.put("switch", switchRules);
        this.deviceRules.put("server", serverRules);
        this.deviceRules.put("workstation", workstationRules);
        this.deviceRules.put("printer", printerRules);
        this.deviceRules.put("camera", cameraRules);

        // Inicializar pesos de seguridad
        this.securityWeights = new HashMap<>();
        this.securityWeights.put("open_ports", -2);
        this.securityWeights.put("secure_services", 5);
        this.securityWeights.put("insecure_services", -5);
        this.securityWeights.put("updated_software", 3);
        this.securityWeights.put("outdated_software", -3);

        // Inicializar patrones de versiones
        this.versionPatterns = new HashMap<>();

        Map<String, List<String>> opensshPatterns = new HashMap<>();
        opensshPatterns.put("safe", Arrays.asList("8.", "7.9"));
        opensshPatterns.put("unsafe", Arrays.asList("6.", "5."));

        Map<String, List<String>> apachePatterns = new HashMap<>();
        apachePatterns.put("safe", Arrays.asList("2.4."));
        apachePatterns.put("unsafe", Arrays.asList("2.2.", "2.0."));

        Map<String, List<String>> nginxPatterns = new HashMap<>();
        nginxPatterns.put("safe", Arrays.asList("1.20.", "1.18."));
        nginxPatterns.put("unsafe", Arrays.asList("1.16.", "1.14."));

        Map<String, List<String>> windowsPatterns = new HashMap<>();
        windowsPatterns.put("safe", Arrays.asList("10.", "2019"));
        windowsPatterns.put("unsafe", Arrays.asList("7", "xp", "2003"));

        this.versionPatterns.put("openssh", opensshPatterns);
        this.versionPatterns.put("apache", apachePatterns);
        this.versionPatterns.put("nginx", nginxPatterns);
        this.versionPatterns.put("windows", windowsPatterns);
    }

    /**
     * Analiza un dispositivo y genera recomendaciones.
     * @param deviceData Mapa con los datos del dispositivo
     * @return Mapa con los resultados del análisis
     */
    public Map<String, Object> analyzeDevice(Map<String, Object> deviceData) {
        try {
            // Detectar tipo de dispositivo
            String deviceType = detectDeviceType(deviceData);

            // Calcular puntuación de seguridad
            int securityScore = calculateSecurityScore(deviceData);

            // Generar recomendaciones
            List<String> recommendations = generateRecommendations(deviceData, deviceType, securityScore);

            Map<String, Object> result = new HashMap<>();
            result.put("device_type", deviceType);
            result.put("security_score", securityScore);
            result.put("recommendations", recommendations);
            result.put("analysis_date", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));

            return result;
        } catch (Exception e) {
            logger.severe("Error al analizar dispositivo: " + e.getMessage());
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("error", e.getMessage());
            return errorResult;
        }
    }

    private String detectDeviceType(Map<String, Object> deviceData) {
        Map<String, Integer> scores = new HashMap<>();
        for (String dtype : deviceRules.keySet()) {
            scores.put(dtype, 0);
        }

        // Analizar puertos abiertos
        Map<String, Map<String, String>> services = (Map<String, Map<String, String>>) deviceData.getOrDefault("services", new HashMap<>());
        List<Integer> openPorts = new ArrayList<>();
        for (String portStr : services.keySet()) {
            try {
                openPorts.add(Integer.parseInt(portStr));
            } catch (NumberFormatException e) {
                logger.warning("Puerto no válido: " + portStr);
            }
        }

        // Analizar información del sistema
        String osInfo = ((String) deviceData.getOrDefault("os", "")).toLowerCase();
        String hostname = ((String) deviceData.getOrDefault("hostname", "")).toLowerCase();

        for (Map.Entry<String, Map<String, Object>> entry : deviceRules.entrySet()) {
            String deviceType = entry.getKey();
            Map<String, Object> rules = entry.getValue();

            // Puntos por puertos coincidentes
            List<Integer> ports = (List<Integer>) rules.get("ports");
            for (Integer port : ports) {
                if (openPorts.contains(port)) {
                    scores.put(deviceType, scores.get(deviceType) + 2);
                }
            }

            // Puntos por palabras clave
            List<String> keywords = (List<String>) rules.get("keywords");
            for (String keyword : keywords) {
                if (osInfo.contains(keyword)) {
                    scores.put(deviceType, scores.get(deviceType) + 3);
                }
                if (hostname.contains(keyword)) {
                    scores.put(deviceType, scores.get(deviceType) + 2);
                }
            }
        }

        // Determinar el tipo con mayor puntuación
        String bestType = "unknown";
        int maxScore = 0;

        for (Map.Entry<String, Integer> entry : scores.entrySet()) {
            if (entry.getValue() > maxScore) {
                maxScore = entry.getValue();
                bestType = entry.getKey();
            }
        }

        return maxScore > 0 ? bestType : "unknown";
    }

    private int calculateSecurityScore(Map<String, Object> deviceData) {
        int score = 100; // Puntuación inicial
        Map<String, Map<String, String>> services = (Map<String, Map<String, String>>) deviceData.getOrDefault("services", new HashMap<>());

        // Penalización por puertos abiertos
        score += services.size() * securityWeights.get("open_ports");

        for (Map.Entry<String, Map<String, String>> entry : services.entrySet()) {
            String port = entry.getKey();
            Map<String, String> service = entry.getValue();

            String serviceName = service.getOrDefault("name", "").toLowerCase();
            String serviceVersion = service.getOrDefault("version", "");

            // Bonificación por servicios seguros
            if (serviceName.contains("ssh") || serviceName.contains("https")) {
                score += securityWeights.get("secure_services");
            }

            // Penalización por servicios inseguros
            if (serviceName.contains("telnet") || serviceName.contains("ftp")) {
                score += securityWeights.get("insecure_services");
            }

            // Análisis de versiones
            for (Map.Entry<String, Map<String, List<String>>> patternEntry : versionPatterns.entrySet()) {
                String app = patternEntry.getKey();
                if (serviceName.contains(app)) {
                    Map<String, List<String>> patterns = patternEntry.getValue();

                    // Verificar versiones seguras
                    for (String safePattern : patterns.get("safe")) {
                        if (serviceVersion.contains(safePattern)) {
                            score += securityWeights.get("updated_software");
                            break;
                        }
                    }

                    // Verificar versiones inseguras
                    for (String unsafePattern : patterns.get("unsafe")) {
                        if (serviceVersion.contains(unsafePattern)) {
                            score += securityWeights.get("outdated_software");
                            break;
                        }
                    }
                }
            }
        }

        // Asegurar que la puntuación esté entre 0 y 100
        return Math.max(0, Math.min(100, score));
    }

    private List<String> generateRecommendations(Map<String, Object> deviceData, String deviceType, int securityScore) {
        Set<String> recommendations = new HashSet<>();
        Map<String, Map<String, String>> services = (Map<String, Map<String, String>>) deviceData.getOrDefault("services", new HashMap<>());

        // Recomendaciones basadas en servicios inseguros
        for (Map.Entry<String, Map<String, String>> entry : services.entrySet()) {
            String port = entry.getKey();
            Map<String, String> service = entry.getValue();
            String serviceName = service.getOrDefault("name", "").toLowerCase();

            if (serviceName.contains("telnet")) {
                recommendations.add("Reemplazar Telnet con SSH para acceso remoto seguro");
            } else if (serviceName.contains("ftp")) {
                recommendations.add("Migrar de FTP a SFTP o FTPS para transferencia segura de archivos");
            } else if (port.equals("80") && !services.containsKey("443")) {
                recommendations.add("Implementar HTTPS para cifrar el tráfico web");
            }
        }

        // Recomendaciones basadas en el tipo de dispositivo
        switch (deviceType) {
            case "router":
                recommendations.addAll(Arrays.asList(
                        "Configurar ACLs para filtrar tráfico no autorizado",
                        "Implementar autenticación de dos factores para acceso administrativo",
                        "Actualizar el firmware regularmente"
                ));
                break;
            case "server":
                recommendations.addAll(Arrays.asList(
                        "Implementar política de contraseñas fuertes",
                        "Configurar copias de seguridad automáticas",
                        "Monitorear logs de seguridad"
                ));
                break;
            case "workstation":
                recommendations.addAll(Arrays.asList(
                        "Instalar y mantener actualizado el antivirus",
                        "Activar el firewall del sistema operativo",
                        "Implementar políticas de actualización automática"
                ));
                break;
        }

        // Recomendaciones basadas en la puntuación de seguridad
        if (securityScore < 50) {
            recommendations.addAll(Arrays.asList(
                    "Realizar una auditoría de seguridad completa",
                    "Revisar y actualizar todas las configuraciones de seguridad",
                    "Considerar la implementación de un IDS/IPS"
            ));
        } else if (securityScore < 80) {
            recommendations.addAll(Arrays.asList(
                    "Revisar y actualizar las políticas de seguridad",
                    "Programar auditorías de seguridad periódicas"
            ));
        }

        return new ArrayList<>(recommendations);
    }

    /**
     * Analiza toda la red y genera un informe global.
     * @param devices Lista de dispositivos a analizar
     * @return Mapa con los resultados del análisis de red
     */
    public Map<String, Object> analyzeNetwork(List<Map<String, Object>> devices) {
        try {
            Map<String, Object> networkAnalysis = new HashMap<>();
            Map<String, Integer> deviceTypesCount = new HashMap<>();
            List<Map<String, Object>> criticalDevices = new ArrayList<>();
            Set<String> globalRecommendations = new HashSet<>();

            int totalScore = 0;

            for (Map<String, Object> device : devices) {
                Map<String, Object> analysis = analyzeDevice(device);

                // Contabilizar tipos de dispositivos
                String deviceType = (String) analysis.get("device_type");
                deviceTypesCount.put(deviceType, deviceTypesCount.getOrDefault(deviceType, 0) + 1);

                // Acumular puntuación
                int score = (int) analysis.get("security_score");
                totalScore += score;

                // Identificar dispositivos críticos
                if (score < 50) {
                    Map<String, Object> criticalDevice = new HashMap<>();
                    criticalDevice.put("ip", device.get("ip"));
                    criticalDevice.put("hostname", device.get("hostname"));
                    criticalDevice.put("score", score);
                    criticalDevice.put("type", deviceType);
                    criticalDevices.add(criticalDevice);
                }

                // Agregar recomendaciones globales
                List<String> recommendations = (List<String>) analysis.get("recommendations");
                globalRecommendations.addAll(recommendations);
            }

            // Calcular promedio
            double averageScore = devices.isEmpty() ? 0 : (double) totalScore / devices.size();

            // Construir resultado final
            networkAnalysis.put("device_types", deviceTypesCount);
            networkAnalysis.put("average_security_score", averageScore);
            networkAnalysis.put("critical_devices", criticalDevices);
            networkAnalysis.put("global_recommendations", new ArrayList<>(globalRecommendations));
            networkAnalysis.put("analysis_date", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));

            return networkAnalysis;
        } catch (Exception e) {
            logger.severe("Error al analizar la red: " + e.getMessage());
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("error", e.getMessage());
            return errorResult;
        }
    }
}
