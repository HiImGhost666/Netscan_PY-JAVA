package com.inventariado.core.reporter;

import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import org.slf4j.*;
import freemarker.template.*;
import org.xhtmlrenderer.pdf.ITextRenderer;
import com.lowagie.text.DocumentException;

/**

 Clase para generar informes de red y seguridad en formato PDF y HTML.
 */
public class ReportGenerator {
    private static final Logger logger = LoggerFactory.getLogger(ReportGenerator.class);

    private final Configuration templateConfig;
    private final Path templateDir;

    public ReportGenerator(String templateDir) throws IOException {
        this.templateDir = Paths.get(templateDir);
        Files.createDirectories(this.templateDir);
        // Configurar FreeMarker
        this.templateConfig = new Configuration(Configuration.VERSION_2_3_31);
        this.templateConfig.setDirectoryForTemplateLoading(this.templateDir.toFile());
        this.templateConfig.setDefaultEncoding("UTF-8");

        // Crear plantillas por defecto si no existen
        createDefaultTemplates();
    }

    private void createDefaultTemplates() throws IOException {
// Plantilla principal
        String mainTemplate = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>${title}</title>
<style>
body {
font-family: Arial, sans-serif;
line-height: 1.6;
margin: 0;
padding: 20px;
}
.header {
text-align: center;
margin-bottom: 30px;
}
.header img {
max-width: 200px;
}
.section {
margin-bottom: 30px;
}
table {
width: 100%;
border-collapse: collapse;
margin-bottom: 20px;
}
th, td {
border: 1px solid #ddd;
padding: 8px;
text-align: left;
}
th {
background-color: #f5f5f5;
}
.risk-critical { color: #d32f2f; }
.risk-high { color: #f57c00; }
.risk-medium { color: #fbc02d; }
.risk-low { color: #388e3c; }
.risk-info { color: #1976d2; }
.chart-container {
width: 100%;
max-width: 600px;
margin: 20px auto;
}
</style>
</head>
<body>
<div class="header">
<h1>${title}</h1>
<p>Fecha: ${date}</p>
</div>
     <#-- Contenido principal -->
     <#nested>

     <div class="footer">
         <p>Generado por Network Scanner v1.0</p>
     </div>
 </body>
 </html>
 """;

 // Plantilla para informe de red
 String networkTemplate = """
 <#import "main.ftl" as layout>
 <@layout.main title="Informe de Escaneo de Red">
     <div class="section">
         <h2>Resumen de Red</h2>
         <p>Rango escaneado: ${networkRange}</p>
         <p>Dispositivos encontrados: ${devices?size}</p>
     </div>

     <div class="section">
         <h2>Dispositivos Detectados</h2>
         <table>
             <tr>
                 <th>IP</th>
                 <th>Hostname</th>
                 <th>MAC</th>
                 <th>Sistema Operativo</th>
                 <th>Servicios</th>
             </tr>
             <#list devices as device>
             <tr>
                 <td>${device.ip}</td>
                 <td>${device.hostname!""}</td>
                 <td>${device.mac!""}</td>
                 <td>${device.os!""}</td>
                 <td>
                     <#if device.services??>
                         <#list device.services as port, service>
                             ${port}/${service.name}<#sep>, </#sep>
                         </#list>
                     </#if>
                 </td>
             </tr>
             </#list>
         </table>
     </div>

     <div class="section">
         <h2>Topología de Red</h2>
         <div class="chart-container">
             ${topologyChart}
         </div>
     </div>
 </@layout.main>
 """;

 // Plantilla para informe de seguridad
 String securityTemplate = """
 <#import "main.ftl" as layout>
 <@layout.main title="Informe de Seguridad de Red">
     <div class="section">
         <h2>Resumen de Seguridad</h2>
         <table>
             <tr>
                 <th>Nivel de Riesgo</th>
                 <th>Cantidad</th>
             </tr>
             <#list riskSummary?keys as level>
             <tr>
                 <td class="risk-${level}">${level?capitalize}</td>
                 <td>${riskSummary[level]}</td>
             </tr>
             </#list>
         </table>
     </div>

     <div class="section">
         <h2>Vulnerabilidades por Dispositivo</h2>
         <#list deviceReports as device>
         <div class="device-report">
             <h3>${device.deviceHostname} (${device.deviceIp})</h3>
             <p>Nivel de riesgo: <span class="risk-${device.riskLevel}">${device.riskLevel?capitalize}</span></p>

             <table>
                 <tr>
                     <th>Puerto</th>
                     <th>Servicio</th>
                     <th>Riesgo</th>
                     <th>Descripción</th>
                 </tr>
                 <#list device.vulnerabilities as vuln>
                 <tr>
                     <td>${vuln.port}</td>
                     <td>${vuln.name}</td>
                     <td class="risk-${vuln.riskLevel}">${vuln.riskLevel?capitalize}</td>
                     <td>${vuln.description}</td>
                 </tr>
                 </#list>
             </table>

             <h4>Recomendaciones:</h4>
             <ul>
                 <#list device.recommendations as rec>
                 <li>${rec}</li>
                 </#list>
             </ul>
         </div>
         </#list>
     </div>

     <div class="section">
         <h2>Recomendaciones Globales</h2>
         <ul>
             <#list globalRecommendations as rec>
             <li>${rec}</li>
             </#list>
         </ul>
     </div>
 </@layout.main>
 """;

 // Guardar plantillas
 Map<String, String> templates = Map.of(
     "main.ftl", mainTemplate,
     "network_report.ftl", networkTemplate,
     "security_report.ftl", securityTemplate
 );

 for (Map.Entry<String, String> entry : templates.entrySet()) {
     Path templatePath = templateDir.resolve(entry.getKey());
     if (!Files.exists(templatePath)) {
         Files.writeString(templatePath, entry.getValue());
     }
 }
}

/**

Genera un informe de red en el formato especificado.
@param scanData Datos del escaneo
@param outputPath Ruta de salida
@param format Formato (pdf o html)
@return true si se generó correctamente
*/
public boolean generateNetworkReport(Map<String, Object> scanData,
String outputPath,
String format) {
try {
// Preparar datos para la plantilla
Map<String, Object> templateData = new HashMap<>();
templateData.put("title", "Informe de Escaneo de Red");
templateData.put("date", DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
.format(LocalDateTime.now()));
templateData.put("networkRange", scanData.getOrDefault("networkRange", "N/A"));
templateData.put("devices", scanData.getOrDefault("devices", new ArrayList<>()));
templateData.put("topologyChart", scanData.getOrDefault("topologyChart", ""));

 // Procesar plantilla
 Template template = templateConfig.getTemplate("network_report.ftl");
 StringWriter writer = new StringWriter();
 template.process(templateData, writer);
 String htmlContent = writer.toString();

 // Generar salida
 if ("html".equalsIgnoreCase(format)) {
     Files.writeString(Paths.get(outputPath), htmlContent);
 } else { // PDF
     try (OutputStream os = new FileOutputStream(outputPath)) {
         ITextRenderer renderer = new ITextRenderer();
         renderer.setDocumentFromString(htmlContent);
         renderer.layout();
         renderer.createPDF(os);
     }
 }

            logger.info("Informe de red generado: {}", outputPath);
            return true;
        } catch (IOException | TemplateException e) {
            logger.error("Error al generar informe de red: {}", e.getMessage());
            return false;
        } catch (DocumentException e) {
            logger.error("Error al generar PDF: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Genera un informe de seguridad en el formato especificado.
     * @param securityData Datos de seguridad
     * @param outputPath Ruta de salida
     * @param format Formato (pdf o html)
     * @return true si se generó correctamente
     */
    public boolean generateSecurityReport(Map<String, Object> securityData,
                                        String outputPath,
                                        String format) {
        try {
            // Preparar datos para la plantilla
            Map<String, Object> templateData = new HashMap<>();
            templateData.put("title", "Informe de Seguridad de Red");
            templateData.put("date", DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                                  .format(LocalDateTime.now()));
            templateData.put("riskSummary", securityData.getOrDefault("riskSummary", new HashMap<>()));
            templateData.put("deviceReports", securityData.getOrDefault("deviceReports", new ArrayList<>()));
            templateData.put("globalRecommendations", securityData.getOrDefault("globalRecommendations", new ArrayList<>()));

            // Procesar plantilla
            Template template = templateConfig.getTemplate("security_report.ftl");
            StringWriter writer = new StringWriter();
            template.process(templateData, writer);
            String htmlContent = writer.toString();

            // Generar salida
            if ("html".equalsIgnoreCase(format)) {
                Files.writeString(Paths.get(outputPath), htmlContent);
            } else { // PDF
                try (OutputStream os = new FileOutputStream(outputPath)) {
                    ITextRenderer renderer = new ITextRenderer();
                    renderer.setDocumentFromString(htmlContent);
                    renderer.layout();
                    renderer.createPDF(os);
                }
            }

            logger.info("Informe de seguridad generado: {}", outputPath);
            return true;
        } catch (IOException | TemplateException e) {
            logger.error("Error al generar informe de seguridad: {}", e.getMessage());
            return false;
        } catch (DocumentException e) {
            logger.error("Error al generar PDF: {}", e.getMessage());
            return false;
        }
    }
}


