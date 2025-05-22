package com.inventariado.core.risk;

import com.inventariado.core.ai.AIAnalyzer;
import com.inventariado.core.security.SecurityAuditor;
import org.slf4j.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**

 Analizador de riesgos con sistema de puntuación tipo semáforo.
 */
public class RiskAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(RiskAnalyzer.class);

    private final SecurityAuditor securityAuditor;
    private final AIAnalyzer aiAnalyzer;

    // Umbrales para clasificación de riesgos
    private final Map<String, Map<String, Integer>> riskThresholds = Map.of(
            "green", Map.of("min", 0, "max", 3),   // Riesgo bajo
            "orange", Map.of("min", 4, "max", 7),  // Riesgo medio
            "red", Map.of("min", 8, "max", 10)     // Riesgo alto
    );

    // Plantillas de recomendaciones
    private final Map<String, String> recommendationTemplates = Map.of(
            "update_firmware", "Actualizar el firmware del dispositivo a la versión más reciente",
            "close_port", "Cerrar el puerto {port} ({service}) si no es necesario",
            "enable_ssl", "Habilitar SSL/TLS para el servicio {service}",
            "update_service", "Actualizar el servicio {service} a una versión segura",
            "disable_service", "Deshabilitar el servicio {service} si no es necesario",
            "change_default", "Cambiar las credenciales por defecto del servicio {service}",
            "enable_firewall", "Habilitar y configurar correctamente el firewall",
            "monitor_traffic", "Implementar monitorización de tráfico para el puerto {port}"
    );

    public RiskAnalyzer() {
        this.securityAuditor = new SecurityAuditor();
        this.aiAnalyzer = new AIAnalyzer();
    }

    /**

     Analiza el riesgo de un dispositivo y genera recomendaciones.
     @param deviceData Datos del dispositivo
     @return Mapa con resultados del análisis
     */
    public Map<String, Object> analyzeDeviceRisk(Map<String, Object> deviceData) {
        try {
            Map<String, Object> securityAnalysis = securityAuditor.analyzeDevice(deviceData);
            Map<String, Object> aiAnalysis = aiAnalyzer.analyzeDevice(deviceData);

            double riskScore = calculateRiskScore(securityAnalysis, aiAnalysis);
            String riskLevel = determineRiskLevel(riskScore);
            List<String> recommendations = generateRecommendations(deviceData, securityAnalysis);

            return Map.of(
                    "risk_score", riskScore,
                    "risk_level", riskLevel,
                    "risk_color", getRiskColor(riskLevel),
                    "recommendations", recommendations,
                    "analysis_date", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME),
                    "details", Map.of(
                            "security_analysis", securityAnalysis,
                            "ai_analysis", aiAnalysis
                    )
            );
        } catch (Exception e) {
            logger.error("Error in risk analysis: {}", e.getMessage());
            return Map.of("error", e.getMessage());
        }
    }

    private double calculateRiskScore(Map<String, Object> securityAnalysis, Map<String, Object> aiAnalysis) {
        double securityScore = (double) securityAnalysis.getOrDefault("total_score", 0);
        double aiScore = (double) aiAnalysis.getOrDefault("security_score", 0);
        // Normalizar puntuaciones a escala 0-10
        double normalizedScore = (securityScore + aiScore) / 2;
        return Math.min(Math.max(normalizedScore, 0), 10);
    }

    private String determineRiskLevel(double riskScore) {
        for (Map.Entry<String, Map<String, Integer>> entry : riskThresholds.entrySet()) {
            int min = entry.getValue().get("min");
            int max = entry.getValue().get("max");
            if (riskScore >= min && riskScore <= max) {
                return entry.getKey();
            }
        }
        return "red"; // Por defecto, si algo sale mal
    }

    private String getRiskColor(String riskLevel) {
        return switch (riskLevel) {
            case "green" -> "#4CAF50";   // Verde
            case "orange" -> "#FF9800";  // Naranja
            case "red" -> "#F44336";     // Rojo
            default -> "#F44336";        // Rojo por defecto
        };
    }

    private List<String> generateRecommendations(Map<String, Object> deviceData, Map<String, Object> securityAnalysis) {
        List<String> recommendations = new ArrayList<>();
        Map<String, Map<String, Object>> services = (Map<String, Map<String, Object>>)
                deviceData.getOrDefault("services", new HashMap<>());
        // Analizar servicios y generar recomendaciones
        for (Map.Entry<String, Map<String, Object>> entry : services.entrySet()) {
            String port = entry.getKey();
            Map<String, Object> serviceInfo = entry.getValue();
            String serviceName = (String) serviceInfo.getOrDefault("name", "desconocido");

            // Verificar servicios inseguros
            int portNumber = Integer.parseInt(port);
            if (securityAuditor.getInsecureServices().containsKey(portNumber)) {
                recommendations.add(
                        recommendationTemplates.get("close_port")
                                .replace("{port}", port)
                                .replace("{service}", serviceName)
                );
            }


            // Verificar servicios sin SSL
            if (List.of("http", "ftp", "telnet").contains(serviceName.toLowerCase())) {
                recommendations.add(
                        recommendationTemplates.get("enable_ssl")
                                .replace("{service}", serviceName)
                );
            }
        }

        // Recomendaciones generales basadas en el análisis de seguridad
        if ((double) securityAnalysis.getOrDefault("total_score", 0) > 5) {
            recommendations.add(recommendationTemplates.get("enable_firewall"));
        }

        return recommendations;
    }
}