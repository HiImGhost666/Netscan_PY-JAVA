package com.inventariado;

import com.inventariado.ui.NetworkScannerGUI;
import javafx.application.Application;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Clase principal que inicia la aplicación de escaneo de red
 */
public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    private static final String LOG_FILE = "application.log";

    public static void main(String[] args) {
        configureLogging();

        try {
            checkJavaVersion();

            // Check if JavaFX is available
            try {
                Class.forName("javafx.application.Application");
            } catch (ClassNotFoundException e) {
                throw new RuntimeException("JavaFX not found. Please add JavaFX to your module path.", e);
            }

            logger.info("Starting network scanner application");
            Application.launch(NetworkScannerGUI.class, args);

        } catch (Exception e) {
            handleCriticalError(e);
        }
    }

    // ... rest of the methods remain the same ...


    private static void configureLogging() {
        try {
            // Configuración básica del logging (en producción usar logback.xml)
            System.setProperty("logback.configurationFile", "logback.xml");

            // Crear archivo de log si no existe
            if (!Files.exists(Paths.get(LOG_FILE))) {
                Files.createFile(Paths.get(LOG_FILE));
            }

            logger.info("Configuración de logging inicializada");
        } catch (IOException e) {
            System.err.println("Error al configurar el sistema de logging: " + e.getMessage());
        }
    }

    private static void checkJavaVersion() throws UnsupportedOperationException {
        // Requerimos al menos Java 11
        final int requiredVersion = 11;
        String version = System.getProperty("java.version");
        int majorVersion = Integer.parseInt(version.split("\\.")[0]);

        if (majorVersion < requiredVersion) {
            String errorMsg = String.format(
                    "Se requiere Java %d o superior. Versión actual: %s",
                    requiredVersion, version
            );
            logger.error(errorMsg);
            throw new UnsupportedOperationException(errorMsg);
        }

        logger.info("Versión de Java compatible: {}", version);
    }

    private static void handleCriticalError(Throwable e) {
        logger.error("Error crítico en la aplicación", e);

        String errorMessage = String.format(
                "Se ha producido un error inesperado en la aplicación.\n\n" +
                        "Consulte el archivo '%s' para más detalles.\n\n" +
                        "Error: %s",
                LOG_FILE, e.getMessage()
        );

        // Mostrar mensaje de error en consola si no se puede mostrar la GUI
        System.err.println(errorMessage);

        // Salir con código de error
        System.exit(1);
    }
}
