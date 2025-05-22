package com.inventariado.core.security;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.Logger;

/**
 * Clase para realizar auditorías de seguridad en la red.
 * Equivalente Java de security.py
 */
public class SecurityAuditor {
    private static final Logger logger = Logger.getLogger(SecurityAuditor.class.getName());

    // Definir puertos y servicios inseguros conocidos
    private final Map<Integer, Map<String, Object>> insecureServices;

    // Definir niveles de riesgo y sus puntajes
    private final Map<String, Integer> riskScores;

    public Map<Integer, Map<String, Object>> getInsecureServices() {
        return insecureServices;
    }

    public SecurityAuditor() {
        this.insecureServices = new HashMap<>();
        initializeInsecureServices();

        this.riskScores = new HashMap<>();
        initializeRiskScores();
    }

    private void initializeInsecureServices() {
        insecureServices.put(21, createServiceInfo("FTP", "high",
                "Protocolo de transferencia de archivos sin cifrar"));
        insecureServices.put(23, createServiceInfo("Telnet", "critical",
                "Acceso remoto sin cifrar"));
        insecureServices.put(53, createServiceInfo("DNS", "medium",
                "Servidor DNS potencialmente vulnerable"));
        insecureServices.put(139, createServiceInfo("NetBIOS", "high",
                "Protocolo SMB v1 inseguro"));
        insecureServices.put(445, createServiceInfo("SMB", "high",
                "Protocolo de compartición de archivos potencialmente vulnerable"));
        insecureServices.put(1433, createServiceInfo("MSSQL", "medium",
                "Base de datos SQL Server expuesta"));
        insecureServices.put(3306, createServiceInfo("MySQL", "medium",
                "Base de datos MySQL expuesta"));
        insecureServices.put(3389, createServiceInfo("RDP", "high",
                "Acceso remoto Windows expuesto"));
        insecureServices.put(5432, createServiceInfo("PostgreSQL", "medium",
                "Base de datos PostgreSQL expuesta"));
        insecureServices.put(8080, createServiceInfo("HTTP Alternate", "medium",
                "Servidor web alternativo sin SSL"));
    }

    private Map<String, Object> createServiceInfo(String name, String riskLevel, String description) {
        Map<String, Object> info = new HashMap<>();
        info.put("name", name);
        info.put("risk_level", riskLevel);
        info.put("description", description);
        return info;
    }

    private void initializeRiskScores() {
        riskScores.put("critical", 10);
        riskScores.put("high", 8);
        riskScores.put("medium", 5);
        riskScores.put("low", 2);
        riskScores.put("info", 0);
    }

    /**
     * Analiza la seguridad de un dispositivo.
     * @param deviceData Mapa con los datos del dispositivo
     * @return Mapa con los resultados del análisis
     */
    public Map<String, Object> analyzeDevice(Map<String, Object> deviceData) {
        try {
            List<Map<String, Object>> vulnerabilities = new ArrayList<>();
            int totalScore = 0;

            @SuppressWarnings("unchecked")
            Map<Integer, Map<String, Object>> services = (Map<Integer, Map<String, Object>>)
                    deviceData.getOrDefault("services", new HashMap<>());

            // Analizar servicios inseguros
            for (Map.Entry<Integer, Map<String, Object>> entry : services.entrySet()) {
                int port = entry.getKey();
                Map<String, Object> serviceInfo = entry.getValue();

                if (insecureServices.containsKey(port)) {
                    Map<String, Object> vulnInfo = new HashMap<>(insecureServices.get(port));
                    vulnInfo.put("port", port);
                    vulnInfo.put("service_version", serviceInfo.getOrDefault("version", "Unknown"));
                    vulnInfo.put("service_product", serviceInfo.getOrDefault("product", "Unknown"));

                    vulnerabilities.add(vulnInfo);
                    totalScore += riskScores.get(vulnInfo.get("risk_level").toString());
                }
                // Verificar servicios HTTP sin SSL
                else if ("http".equalsIgnoreCase(serviceInfo.get("name").toString()) && port != 443) {
                    Map<String, Object> httpVuln = new HashMap<>();
                    httpVuln.put("name", "HTTP sin SSL");
                    httpVuln.put("port", port);
                    httpVuln.put("risk_level", "medium");
                    httpVuln.put("description", "Servicio web sin cifrado SSL/TLS");
                    httpVuln.put("service_version", serviceInfo.getOrDefault("version", "Unknown"));
                    httpVuln.put("service_product", serviceInfo.getOrDefault("product", "Unknown"));

                    vulnerabilities.add(httpVuln);
                    totalScore += riskScores.get("medium");
                }
            }

            // Calcular nivel de riesgo general
            String riskLevel = calculateRiskLevel(totalScore);

            Map<String, Object> result = new HashMap<>();
            result.put("device_ip", deviceData.get("ip"));
            result.put("device_hostname", deviceData.get("hostname"));
            result.put("scan_date", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            result.put("risk_level", riskLevel);
            result.put("risk_score", totalScore);
            result.put("vulnerabilities", vulnerabilities);
            result.put("recommendations", generateRecommendations(vulnerabilities));

            return result;

        } catch (Exception e) {
            logger.severe("Error al analizar dispositivo: " + e.getMessage());
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("error", e.getMessage());
            return errorResult;
        }
    }

    private String calculateRiskLevel(int score) {
        if (score >= 30) {
            return "critical";
        } else if (score >= 20) {
            return "high";
        } else if (score >= 10) {
            return "medium";
        } else if (score > 0) {
            return "low";
        }
        return "info";
    }

    private List<String> generateRecommendations(List<Map<String, Object>> vulnerabilities) {
        Set<String> recommendations = new HashSet<>();

        for (Map<String, Object> vuln : vulnerabilities) {
            String name = vuln.get("name").toString();

            switch (name) {
                case "Telnet":
                    recommendations.add("Deshabilitar Telnet y usar SSH para acceso remoto seguro");
                    break;
                case "FTP":
                    recommendations.add("Migrar a SFTP o FTPS para transferencia segura de archivos");
                    break;
                case "SMB":
                    recommendations.add("Actualizar a SMB v3 y deshabilitar versiones antiguas");
                    break;
                case "HTTP sin SSL":
                    recommendations.add("Implementar SSL/TLS para todo el tráfico web");
                    break;
                case "RDP":
                    recommendations.add("Limitar acceso RDP a VPN o direcciones IP específicas");
                    break;
                default:
                    if (name.contains("SQL")) {
                        recommendations.add("Restringir acceso a " + name + " solo a direcciones IP autorizadas");
                    }
                    break;
            }
        }

        // Recomendaciones generales
        if (!vulnerabilities.isEmpty()) {
            recommendations.addAll(Arrays.asList(
                    "Implementar un firewall para filtrar tráfico no autorizado",
                    "Mantener todos los servicios actualizados con los últimos parches de seguridad",
                    "Realizar auditorías de seguridad periódicas"
            ));
        }

        return new ArrayList<>(recommendations);
    }

    /**
     * Genera un informe de seguridad completo para todos los dispositivos.
     * @param devices Lista de dispositivos a analizar
     * @return Mapa con el informe de seguridad
     */
    public Map<String, Object> generateSecurityReport(List<Map<String, Object>> devices) {
        try {
            Map<String, Object> report = new HashMap<>();
            report.put("scan_date", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            report.put("total_devices", devices.size());

            // Inicializar resumen de riesgos
            Map<String, Integer> riskSummary = new HashMap<>();
            riskSummary.put("critical", 0);
            riskSummary.put("high", 0);
            riskSummary.put("medium", 0);
            riskSummary.put("low", 0);
            riskSummary.put("info", 0);
            report.put("risk_summary", riskSummary);

            List<Map<String, Object>> deviceReports = new ArrayList<>();
            Set<String> globalRecommendations = new HashSet<>();

            // Analizar cada dispositivo
            for (Map<String, Object> device : devices) {
                Map<String, Object> deviceReport = analyzeDevice(device);
                deviceReports.add(deviceReport);

                // Actualizar resumen de riesgos
                String riskLevel = deviceReport.get("risk_level").toString();
                riskSummary.put(riskLevel, riskSummary.get(riskLevel) + 1);

                // Agregar recomendaciones globales
                @SuppressWarnings("unchecked")
                List<String> recs = (List<String>) deviceReport.get("recommendations");
                globalRecommendations.addAll(recs);
            }

            report.put("device_reports", deviceReports);
            report.put("global_recommendations", new ArrayList<>(globalRecommendations));

            // Calcular estadísticas
            Map<String, Object> statistics = new HashMap<>();
            int totalVulnerabilities = 0;
            double totalRiskScore = 0;

            for (Map<String, Object> dr : deviceReports) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> vulns = (List<Map<String, Object>>) dr.get("vulnerabilities");
                totalVulnerabilities += vulns.size();
                totalRiskScore += (int) dr.get("risk_score");
            }

            statistics.put("total_vulnerabilities", totalVulnerabilities);
            statistics.put("average_risk_score",
                    devices.isEmpty() ? 0 : totalRiskScore / devices.size());

            report.put("statistics", statistics);

            return report;

        } catch (Exception e) {
            logger.severe("Error al generar informe de seguridad: " + e.getMessage());
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("error", e.getMessage());
            return errorResult;
        }
    }
}