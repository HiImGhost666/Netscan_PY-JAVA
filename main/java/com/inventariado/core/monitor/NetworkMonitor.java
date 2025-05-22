package com.inventariado.core.monitor;

import java.io.EOFException;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**

 Clase para monitorear la red en tiempo real.
 Implementa la detección de nuevos dispositivos y el sistema de alertas.
 */
public class NetworkMonitor {
    private static final Logger logger = LoggerFactory.getLogger(NetworkMonitor.class);

    private final Set<String> knownDevices = ConcurrentHashMap.newKeySet();
    private final List<Consumer<Map<String, String>>> alertCallbacks = new CopyOnWriteArrayList<>();
    private volatile boolean isMonitoring = false;
    private Thread monitorThread;
    private final Map<String, Long> lastAlertTime = new ConcurrentHashMap<>();
    private static final long MIN_ALERT_INTERVAL = 300; // 5 minutos en segundos

    private PcapHandle handle;
    private String interfaceName;

    public NetworkMonitor() {
// Constructor vacío
    }

    /**

     Inicia el monitoreo de red.
     @param interfaceName Nombre de la interfaz de red
     @return true si el monitoreo se inició correctamente
     */
    public boolean startMonitoring(String interfaceName) {
        if (isMonitoring) {
            logger.warn("El monitoreo ya está activo");
            return false;
        }

        try {
            this.interfaceName = interfaceName;
            this.isMonitoring = true;
            this.monitorThread = new Thread(this::monitorNetwork);
            this.monitorThread.setDaemon(true);
            this.monitorThread.start();

            logger.info("Monitoreo de red iniciado");
            return true;
        } catch (Exception e) {
            logger.error("Error al iniciar el monitoreo: {}", e.getMessage());
            this.isMonitoring = false;
            return false;
        }
    }

    /**

     Detiene el monitoreo de red.
     */
    public void stopMonitoring() {
        this.isMonitoring = false;

        if (handle != null && handle.isOpen()) {
            handle.close();
        }

        if (monitorThread != null) {
            try {
                monitorThread.join(1000);
            } catch (InterruptedException e) {
                logger.warn("Interrupción al detener el hilo de monitoreo");
                Thread.currentThread().interrupt();
            }
        }

        logger.info("Monitoreo de red detenido");
    }

    /**

     Añade un dispositivo conocido.
     @param mac Dirección MAC del dispositivo
     */
    public void addKnownDevice(String mac) {
        if (mac != null) {
            knownDevices.add(mac.toLowerCase());
        }
    }
    /**

     Añade una lista de dispositivos conocidos.
     @param devices Lista de dispositivos (mapas con clave "mac")
     */
    public void addKnownDevices(List<Map<String, String>> devices) {
        if (devices != null) {
            devices.stream()
                    .filter(device -> device.containsKey("mac") && device.get("mac") != null)
                    .forEach(device -> addKnownDevice(device.get("mac")));
        }
    }
    /**

     Registra una función de callback para alertas.
     @param callback Función a ejecutar cuando se detecte un nuevo dispositivo
     */
    public void registerAlertCallback(Consumer<Map<String, String>> callback) {
        if (callback != null) {
            alertCallbacks.add(callback);
        }
    }
    private void monitorNetwork() {
        try {
// Configurar el manejador de captura
            PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
            int snapshotLength = 65536;
            int timeout = 50;
            handle = nif.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
            // Filtro para capturar solo paquetes ARP
            String filter = "arp";
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

            // Capturar paquetes mientras isMonitoring sea true
            while (isMonitoring) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    processPacket(packet);
                } catch (PcapNativeException | NotOpenException e) {
                    if (isMonitoring) {
                        logger.error("Error al capturar paquete: {}", e.getMessage());
                    }
                    break;
                } catch (TimeoutException e) {
                    // Timeout esperado, continuar
                    continue;
                } catch (EOFException e) {
                    throw new RuntimeException(e);
                }
            }
        } catch (PcapNativeException | NotOpenException e) {
            logger.error("Error en el monitoreo de red: {}", e.getMessage());
            isMonitoring = false;
        } finally {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        }
    }

    private void processPacket(Packet packet) {
        if (packet == null) return;
        try {
            ArpPacket arpPacket = packet.get(ArpPacket.class);
            if (arpPacket == null) return;

            ArpOperation operation = arpPacket.getHeader().getOperation();
            if (operation.equals(ArpOperation.REQUEST) || operation.equals(ArpOperation.REPLY)) {
                MacAddress macAddress = arpPacket.getHeader().getSrcHardwareAddr();
                String mac = macAddress.toString().toLowerCase();
                String ip = arpPacket.getHeader().getSrcProtocolAddr().toString();

                // Verificar si es un dispositivo nuevo
                if (mac != null && !knownDevices.contains(mac) && shouldAlert(mac)) {
                    Map<String, String> deviceInfo = new HashMap<>();
                    deviceInfo.put("mac", mac);
                    deviceInfo.put("ip", ip);
                    deviceInfo.put("first_seen", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
                    deviceInfo.put("detection_type", "arp");

                    // Generar alerta
                    generateAlert(deviceInfo);

                    // Actualizar tiempo de última alerta
                    lastAlertTime.put(mac, System.currentTimeMillis() / 1000);

                    // Añadir a dispositivos conocidos
                    knownDevices.add(mac);
                }
            }
        } catch (Exception e) {
            logger.error("Error al procesar paquete ARP: {}", e.getMessage());
        }
    }

    private boolean shouldAlert(String mac) {
        long currentTime = System.currentTimeMillis() / 1000;
        long lastAlert = lastAlertTime.getOrDefault(mac, 0L);
        return (currentTime - lastAlert) >= MIN_ALERT_INTERVAL;
    }

    private void generateAlert(Map<String, String> deviceInfo) {
        try {
// Crear mensaje de alerta
            String title = "¡Nuevo dispositivo detectado!";
            String message = String.format("IP: %s\nMAC: %s",
                    deviceInfo.get("ip"), deviceInfo.get("mac"));

            // Mostrar notificación del sistema (requiere integración con sistema de notificaciones)
            // Notificaciones del sistema podrían implementarse con:
            // - JavaFX Notifications
            // - TrayIcon (Swing)
            // - Librerías específicas del sistema operativo

            // Registrar en el log
            logger.info("Nuevo dispositivo detectado: {}", deviceInfo);

            // Ejecutar callbacks registrados
            for (Consumer<Map<String, String>> callback : alertCallbacks) {
                try {
                    callback.accept(deviceInfo);
                } catch (Exception e) {
                    logger.error("Error en callback de alerta: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            logger.error("Error al generar alerta: {}", e.getMessage());
        }
    }

    /**

     Obtiene el estado actual del monitoreo.
     @return Mapa con el estado del monitoreo
     */
    public Map<String, Object> getMonitoringStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("active", isMonitoring);
        status.put("known_devices", knownDevices.size());

        if (isMonitoring && !lastAlertTime.isEmpty()) {
            long startTime = lastAlertTime.values().stream().min(Long::compare).orElse(0L);
            status.put("uptime", (System.currentTimeMillis() / 1000) - startTime);
        } else {
            status.put("uptime", 0);
        }

        return status;
    }
}