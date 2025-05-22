package com.inventariado.core.scanner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.inventariado.core.security.SecurityAuditor;
import com.google.gson.Gson;

/**
 * Clase para escaneo de red ejecutando Nmap directamente como proceso externo
 */
public class NetworkScanner {
    private static final Logger logger = Logger.getLogger(NetworkScanner.class.getName());
    private static final Gson gson = new Gson();

    private final List<Map<String, Object>> devices;
    private final BlockingQueue<Map<String, Object>> scanQueue;
    private final BlockingQueue<Map<String, Object>> resultQueue;
    private volatile boolean isScanning;
    private volatile double scanProgress;
    private volatile int totalHosts;
    private volatile int scannedHosts;
    private final List<DeviceFoundCallback> deviceCallbacks;
    private volatile boolean stopScan;
    private final SecurityAuditor securityAuditor;

    // Patrones regex para parsear salida de Nmap
    private static final Pattern HOST_PATTERN = Pattern.compile("Nmap scan report for (.*?) \\[(.*?)\\]");
    private static final Pattern PORT_PATTERN = Pattern.compile("(\\d+)/(\\w+)\\s+(\\w+)\\s+(.*)");
    private static final Pattern SERVICE_PATTERN = Pattern.compile("(\\d+)/(\\w+)\\s+(\\w+)\\s+(.*?)\\s+(.*)");
    private static final Pattern OS_PATTERN = Pattern.compile("OS details?: (.*)");
    private static final Pattern MAC_PATTERN = Pattern.compile("MAC Address: (.*?) \\((.*?)\\)");

    public interface DeviceFoundCallback {
        void onDeviceFound(Map<String, Object> deviceInfo);
    }

    public NetworkScanner() {
        this.devices = new ArrayList<>();
        this.scanQueue = new LinkedBlockingQueue<>();
        this.resultQueue = new LinkedBlockingQueue<>();
        this.isScanning = false;
        this.scanProgress = 0;
        this.totalHosts = 0;
        this.scannedHosts = 0;
        this.deviceCallbacks = new ArrayList<>();
        this.stopScan = false;
        this.securityAuditor = new SecurityAuditor();
    }

    public void registerDeviceCallback(DeviceFoundCallback callback) {
        if (callback != null) {
            this.deviceCallbacks.add(callback);
        }
    }

    private void notifyDeviceFound(Map<String, Object> deviceInfo) {
        for (DeviceFoundCallback callback : deviceCallbacks) {
            try {
                callback.onDeviceFound(deviceInfo);
            } catch (Exception e) {
                logger.severe("Error en callback: " + e.getMessage());
            }
        }
    }

    public List<Map<String, Object>> scanNetwork(String networkRange, String intensity,
                                                 boolean performRiskAnalysis, String snmpCommunity) {
        this.devices.clear();
        this.isScanning = true;
        this.scanProgress = 0;
        this.stopScan = false;
        long startTime = System.currentTimeMillis();

        try {
            // Validar el rango de red
            List<String> hosts = expandHosts(networkRange);
            if (hosts.isEmpty()) {
                logger.severe("Rango de red inválido: " + networkRange);
                return Collections.emptyList();
            }

            logger.info("Escaneando " + hosts.size() + " hosts en la red " + networkRange);
            this.totalHosts = hosts.size();

            // Configurar cola de trabajo
            for (String host : hosts) {
                Map<String, Object> task = new HashMap<>();
                task.put("host", host);
                task.put("snmpCommunity", snmpCommunity);
                scanQueue.put(task);
            }

            // Crear y ejecutar hilos de trabajo
            int threadCount = Math.min(32, hosts.size());
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);

            for (int i = 0; i < threadCount; i++) {
                executor.execute(() -> scanWorker(intensity));
            }

            // Esperar a que terminen todos los escaneos
            executor.shutdown();
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);

            // Recolectar resultados
            while (!resultQueue.isEmpty()) {
                Map<String, Object> device = resultQueue.poll();
                if (device != null) {
                    devices.add(device);
                }
            }

            // Ordenar dispositivos por IP
            devices.sort((d1, d2) -> {
                String ip1 = (String) d1.get("ip");
                String ip2 = (String) d2.get("ip");
                return compareIps(ip1, ip2);
            });

            double scanDuration = (System.currentTimeMillis() - startTime) / 1000.0;
            logger.info(String.format("Escaneo completado en %.2f segundos. Encontrados %d dispositivos.",
                    scanDuration, devices.size()));

            return new ArrayList<>(devices);

        } catch (Exception e) {
            logger.severe("Error durante escaneo de red: " + e.getMessage());
            return Collections.emptyList();
        } finally {
            this.isScanning = false;
            this.stopScan = true;
        }
    }

    public void stopScan() {
        try {
            logger.info("Deteniendo escaneo...");
            this.stopScan = true;
            this.isScanning = false;

            // Limpiar las colas
            scanQueue.clear();
            resultQueue.clear();

            // Resetear contadores
            this.scanProgress = 0;
            this.scannedHosts = 0;
            this.totalHosts = 0;

            logger.info("Escaneo detenido correctamente");
        } catch (Exception e) {
            logger.severe("Error al detener el escaneo: " + e.getMessage());
        }
    }

    private void scanWorker(String intensity) {
        while (!stopScan) {
            Map<String, Object> task = null;
            try {
                // Intentar obtener un host de la cola con timeout
                task = scanQueue.poll(1, TimeUnit.SECONDS);
                if (task == null) {
                    if (stopScan) break;
                    continue;
                }

                String host = (String) task.get("host");
                String snmpCommunity = (String) task.get("snmpCommunity");

                logger.info("Escaneando " + host + "...");
                Map<String, Object> device = scanHostFullPorts(host, intensity, snmpCommunity);

                if (device != null) {
                    resultQueue.put(device);
                    notifyDeviceFound(device);
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warning("Hilo de escaneo interrumpido");
                break;
            } catch (Exception e) {
                logger.severe("Error en worker de escaneo: " + e.getMessage());
            } finally {
                if (task != null && !stopScan) {
                    scannedHosts++;
                    if (totalHosts > 0) {
                        scanProgress = (scannedHosts / (double) totalHosts) * 100;
                    }
                }
            }
        }
    }

    private Map<String, Object> scanHostFullPorts(String host, String intensity, String snmpCommunity) {
        long scanStart = System.currentTimeMillis();
        Map<String, Object> device = new HashMap<>();
        Map<Integer, Map<String, Object>> services = new HashMap<>();

        try {
            // Construir comando Nmap
            String[] command = buildNmapCommand(host, intensity);

            // Ejecutar proceso
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            String currentIp = host;
            String hostname = host;
            Map<String, Object> macInfo = new HashMap<>();
            macInfo.put("mac", "Desconocida");
            macInfo.put("vendor", "Desconocido");
            String osInfo = "Desconocido";

            // Parsear salida de Nmap
            while ((line = reader.readLine()) != null) {
                if (stopScan) {
                    process.destroy();
                    return null;
                }

                // Parsear información del host
                Matcher hostMatcher = HOST_PATTERN.matcher(line);
                if (hostMatcher.find()) {
                    hostname = hostMatcher.group(1);
                    currentIp = hostMatcher.group(2);
                    continue;
                }

                // Parsear información MAC
                Matcher macMatcher = MAC_PATTERN.matcher(line);
                if (macMatcher.find()) {
                    macInfo.put("mac", macMatcher.group(1));
                    macInfo.put("vendor", macMatcher.group(2));
                    continue;
                }

                // Parsear información del SO
                Matcher osMatcher = OS_PATTERN.matcher(line);
                if (osMatcher.find()) {
                    osInfo = osMatcher.group(1);
                    continue;
                }

                // Parsear puertos y servicios
                Matcher serviceMatcher = SERVICE_PATTERN.matcher(line);
                if (serviceMatcher.find()) {
                    int port = Integer.parseInt(serviceMatcher.group(1));
                    String protocol = serviceMatcher.group(2);
                    String state = serviceMatcher.group(3);
                    String serviceName = serviceMatcher.group(4);
                    String serviceInfo = serviceMatcher.groupCount() > 4 ? serviceMatcher.group(5) : "";

                    if ("open".equalsIgnoreCase(state)) {
                        Map<String, Object> service = new HashMap<>();
                        service.put("port", port);
                        service.put("protocol", protocol);
                        service.put("state", state);
                        service.put("name", serviceName);

                        // Parse version if available
                        if (serviceInfo != null && !serviceInfo.isEmpty()) {
                            String[] versionParts = serviceInfo.split(" ");
                            if (versionParts.length > 0) {
                                service.put("product", versionParts[0]);
                                if (versionParts.length > 1) {
                                    service.put("version", versionParts[1]);
                                }
                            }
                        }

                        services.put(port, service);
                    }
                }
            }

            // Esperar a que termine el proceso
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                logger.warning("Nmap terminó con código de salida: " + exitCode + " para host: " + host);
            }

            // Obtener información de hardware (simplificado)
            Map<String, Object> hardwareInfo = getHardwareInfo(host, snmpCommunity);

            // Construir objeto dispositivo
            device.put("ip", currentIp);
            device.put("hostname", hostname);
            device.put("mac_info", macInfo);
            device.put("os_info", osInfo);
            device.put("services", services);
            device.put("hardware", hardwareInfo);
            device.put("detection_method", "nmap");
            device.put("status", "up");
            device.put("last_seen", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            device.put("scan_duration", (System.currentTimeMillis() - scanStart) / 1000.0);
            device.put("open_ports", services.size());

            // Análisis de seguridad
            Map<String, Object> riskReport = securityAuditor.analyzeDevice(device);
            device.put("risk_level", riskReport.getOrDefault("risk_level", "No evaluado"));
            device.put("risk_score", riskReport.getOrDefault("risk_score", 0));
            device.put("vulnerabilities", riskReport.getOrDefault("vulnerabilities", Collections.emptyList()));
            device.put("recommendations", riskReport.getOrDefault("recommendations", Collections.emptyList()));

            logger.info(String.format(
                    "Escaneo de %s completado en %.2fs - Puertos abiertos: %d - Nivel de riesgo: %s",
                    host, (System.currentTimeMillis() - scanStart) / 1000.0,
                    services.size(), device.get("risk_level")
            ));

            return device;

        } catch (IOException | InterruptedException e) {
            logger.severe("Error al escanear " + host + ": " + e.getMessage());
            return null;
        }
    }


    private String[] buildNmapCommand(String host, String intensity) {
        return new String[] {
                "nmap",
                "-p", "1-65535",
                "-sS",
                "-sV",
                "-O",
                "-A",
                "--osscan-guess",
                "--max-os-tries", "2",
                intensity,
                "--host-timeout", "60s",
                "--version-intensity", "7",
                "--script=banner,http-title,ssl-cert,ssh-hostkey,snmp-info,smb-os-discovery",
                host
        };
    }

    private Map<String, Object> getHardwareInfo(String host, String snmpCommunity) {
        // Implementación simplificada
        Map<String, Object> hardwareInfo = new HashMap<>();
        hardwareInfo.put("cpu", Collections.emptyMap());
        hardwareInfo.put("memory", Collections.emptyMap());
        hardwareInfo.put("storage", Collections.emptyList());
        hardwareInfo.put("network_interfaces", Collections.emptyList());
        return hardwareInfo;
    }

    private List<String> expandHosts(String networkRange) {
        try {
            // Implementación simplificada - en una implementación real se expandiría el rango CIDR
            return Collections.singletonList(networkRange);
        } catch (Exception e) {
            logger.severe("Rango de red inválido: " + networkRange);
            return Collections.emptyList();
        }
    }

    private int compareIps(String ip1, String ip2) {
        String[] parts1 = ip1.split("\\.");
        String[] parts2 = ip2.split("\\.");

        for (int i = 0; i < 4; i++) {
            int part1 = Integer.parseInt(parts1[i]);
            int part2 = Integer.parseInt(parts2[i]);

            if (part1 != part2) {
                return Integer.compare(part1, part2);
            }
        }

        return 0;
    }

    public double getScanProgress() {
        return scanProgress;
    }

    public boolean isScanInProgress() {
        return isScanning;
    }
}