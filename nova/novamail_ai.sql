CREATE DATABASE IF NOT EXISTS `novamail_ai`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `novamail_ai`;

-- 1. Tabla de Configuración de Servidores e Inteligencia Artificial
DROP TABLE IF EXISTS `configuracion_novamail`;
CREATE TABLE IF NOT EXISTS `configuracion_novamail` (
  `id` int NOT NULL AUTO_INCREMENT,
  `usuario_id` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `correo_electronico` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password_token_cifrado` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `protocolo_entrante` enum('IMAP','POP3') COLLATE utf8mb4_unicode_ci DEFAULT 'IMAP',
  `imap_host` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `imap_puerto` int NOT NULL DEFAULT '993',
  `imap_cifrado` enum('SSL/TLS','STARTTLS','NINGUNO') COLLATE utf8mb4_unicode_ci DEFAULT 'SSL/TLS',
  `smtp_host` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `smtp_puerto` int NOT NULL DEFAULT '465',
  `smtp_cifrado` enum('SSL/TLS','STARTTLS','NINGUNO') COLLATE utf8mb4_unicode_ci DEFAULT 'SSL/TLS',
  `modelo_ia` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'gemini-2.5-flash',
  `api_key_ia_cifrada` text COLLATE utf8mb4_unicode_ci,
  `temperatura` decimal(3,2) DEFAULT '0.30',
  `tono_redaccion` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT 'Profesional',
  `escaneo_preventivo_activo` tinyint(1) DEFAULT '1',
  `fecha_actualizacion` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `usuario_id` (`usuario_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Tabla Remota de Auditoría Forense de Phishing
DROP TABLE IF EXISTS `registros_phishing_remoto`;
CREATE TABLE IF NOT EXISTS `registros_phishing_remoto` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `uuid_incidente` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `fecha_deteccion` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `remitente_nombre` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `remitente_correo` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `destinatario_correo` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `asunto` varchar(500) COLLATE utf8mb4_unicode_ci NOT NULL,
  `cuerpo_resumen` text COLLATE utf8mb4_unicode_ci,
  `direccion_ip_origen` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Soporta IPv4 e IPv6',
  `proveedor_hosting` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Hosting / ASN desde donde se envió el correo',
  `asn_numero` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pais_origen` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cabeceras_raw` longtext COLLATE utf8mb4_unicode_ci,
  `es_phishing` tinyint(1) NOT NULL DEFAULT '1',
  `nivel_riesgo` enum('BAJO','MEDIO','ALTO','CRITICO') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ALTO',
  `puntuacion_confianza` decimal(5,2) NOT NULL COMMENT 'Porcentaje de certeza IA (0.00 - 100.00)',
  `modelo_ia_utilizado` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `indicadores_detectados` json NOT NULL COMMENT 'Lista de URLs maliciosas, spoofing, urgencia, etc.',
  `estado_accion` enum('CUARENTENA','BLOQUEADO','FALSO_POSITIVO') COLLATE utf8mb4_unicode_ci DEFAULT 'CUARENTENA',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid_incidente` (`uuid_incidente`),
  KEY `idx_ip_origen` (`direccion_ip_origen`),
  KEY `idx_hosting` (`proveedor_hosting`),
  KEY `idx_remitente` (`remitente_correo`),
  KEY `idx_fecha` (`fecha_deteccion`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
