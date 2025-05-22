package com.inventariado.core.alert;

import java.time.LocalDateTime;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AlertSystem {
    private static final Logger logger = Logger.getLogger(AlertSystem.class.getName());

    private List<Map<String, Object>> alertRules = new ArrayList<>();
    private Map<String, NotificationHandler> notificationChannels = new HashMap<>();

    public AlertSystem() {
        notificationChannels.put("app", this::sendAppNotification);
        notificationChannels.put("log", this::logAlert);
        notificationChannels.put("custom", null); // For custom integrations
    }

    public void addRule(Map<String, Object> rule) {
        try {
            if (validateRule(rule)) {
                alertRules.add(rule);
                logger.info("Nueva regla de alerta añadida: " + rule.get("name"));
            } else {
                throw new IllegalArgumentException("Regla de alerta inválida");
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error al añadir regla de alerta", e);
        }
    }

    public void removeRule(String ruleId) {
        try {
            alertRules.removeIf(rule -> rule.get("id").equals(ruleId));
            logger.info("Regla de alerta eliminada: " + ruleId);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error al eliminar regla de alerta", e);
        }
    }

    public void checkDevice(Map<String, Object> deviceData) {
        try {
            for (Map<String, Object> rule : alertRules) {
                if (evaluateRule(rule, deviceData)) {
                    triggerAlert(rule, deviceData);
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error al verificar dispositivo", e);
        }
    }

    public void setNotificationChannel(String channel, NotificationHandler handler) {
        if (notificationChannels.containsKey(channel)) {
            notificationChannels.put("custom", handler);
            logger.info("Canal de notificación configurado: " + channel);
        } else {
            logger.severe("Canal de notificación no soportado: " + channel);
        }
    }

    private boolean validateRule(Map<String, Object> rule) {
        return rule.containsKey("id") && rule.containsKey("name") && rule.containsKey("condition") && rule.containsKey("notification_type");
    }

    private boolean evaluateRule(Map<String, Object> rule, Map<String, Object> deviceData) {
        Map<String, Object> condition = (Map<String, Object>) rule.get("condition");
        String type = (String) condition.get("type");

        switch (type) {
            case "new_device":
                return checkNewDevice(deviceData);
            case "port_open":
                return checkPortOpen(deviceData, (int) condition.get("port"));
            case "service_down":
                return !checkServiceStatus(deviceData, (String) condition.get("service"));
            case "snmp_public":
                return checkSnmpPublic(deviceData);
            default:
                return false;
        }
    }

    private void triggerAlert(Map<String, Object> rule, Map<String, Object> deviceData) {
        Map<String, Object> alertData = new HashMap<>();
        alertData.put("timestamp", LocalDateTime.now().toString());
        alertData.put("rule_name", rule.get("name"));
        alertData.put("device_ip", deviceData.get("ip"));
        alertData.put("device_name", deviceData.getOrDefault("hostname", "Desconocido"));
        alertData.put("message", generateAlertMessage(rule, deviceData));

        String type = (String) rule.get("notification_type");
        NotificationHandler handler = notificationChannels.get(type);
        if (handler != null) {
            handler.send(alertData);
        }
    }

    private void sendAppNotification(Map<String, Object> alertData) {
        // Placeholder for desktop/mobile app notification
        System.out.println("NOTIFICACIÓN: " + alertData.get("message"));
    }

    private void logAlert(Map<String, Object> alertData) {
        logger.warning("ALERTA: " + alertData.get("rule_name") +
                " - Dispositivo: " + alertData.get("device_name") +
                " (" + alertData.get("device_ip") + ") - " +
                alertData.get("message"));
    }

    private boolean checkNewDevice(Map<String, Object> deviceData) {
        // Placeholder
        return false;
    }

    private boolean checkPortOpen(Map<String, Object> deviceData, int port) {
        Map<String, Map<String, Object>> services = (Map<String, Map<String, Object>>) deviceData.get("services");
        return services != null && services.containsKey(String.valueOf(port));
    }

    private boolean checkServiceStatus(Map<String, Object> deviceData, String service) {
        Map<String, Map<String, Object>> services = (Map<String, Map<String, Object>>) deviceData.get("services");
        if (services == null) return false;
        for (Map<String, Object> s : services.values()) {
            String name = (String) s.get("name");
            if (name != null && name.toLowerCase().contains(service.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private boolean checkSnmpPublic(Map<String, Object> deviceData) {
        Map<String, Map<String, Object>> services = (Map<String, Map<String, Object>>) deviceData.get("services");
        return services != null && services.containsKey("161");
    }

    private String generateAlertMessage(Map<String, Object> rule, Map<String, Object> deviceData) {
        Map<String, Object> condition = (Map<String, Object>) rule.get("condition");
        String type = (String) condition.get("type");
        String hostname = (String) deviceData.getOrDefault("hostname", "Desconocido");
        String ip = (String) deviceData.get("ip");

        switch (type) {
            case "new_device":
                return "Nuevo dispositivo detectado: " + hostname + " (" + ip + ")";
            case "port_open":
                return "Puerto " + condition.get("port") + " abierto en " + hostname + " (" + ip + ")";
            case "service_down":
                return "Servicio " + condition.get("service") + " caído en " + hostname + " (" + ip + ")";
            case "snmp_public":
                return "SNMP público detectado en " + hostname + " (" + ip + ")";
            default:
                return "Alerta en dispositivo " + hostname + " (" + ip + ")";
        }
    }

    // Interface funcional para manejar notificaciones
    @FunctionalInterface
    interface NotificationHandler {
        void send(Map<String, Object> alertData);
    }
}