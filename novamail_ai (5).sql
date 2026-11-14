-- phpMyAdmin SQL Dump
-- version 5.2.3
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1:3306
-- Tiempo de generación: 14-11-2026 a las 11:31:17
-- Versión del servidor: 8.4.7
-- Versión de PHP: 8.3.28

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `novamail_ai`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `configuracion_novamail`
--

DROP TABLE IF EXISTS `configuracion_novamail`;
CREATE TABLE IF NOT EXISTS `configuracion_novamail` (
  `id` int NOT NULL AUTO_INCREMENT,
  `usuario_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `correo_electronico` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `password_token_cifrado` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `protocolo_entrante` enum('IMAP','POP3') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'IMAP',
  `imap_host` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `imap_puerto` int NOT NULL DEFAULT '993',
  `imap_cifrado` enum('SSL/TLS','STARTTLS','NINGUNO') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'SSL/TLS',
  `smtp_host` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `smtp_puerto` int NOT NULL DEFAULT '465',
  `smtp_cifrado` enum('SSL/TLS','STARTTLS','NINGUNO') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'SSL/TLS',
  `modelo_ia` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'gemini-3.8-flash',
  `api_key_ia_cifrada` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `temperatura` decimal(3,2) DEFAULT '0.30',
  `tono_redaccion` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'Profesional',
  `escaneo_preventivo_activo` tinyint(1) DEFAULT '1',
  `fecha_actualizacion` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `usuario_id` (`usuario_id`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Volcado de datos para la tabla `configuracion_novamail`
--

INSERT INTO `configuracion_novamail` (`id`, `usuario_id`, `correo_electronico`, `password_token_cifrado`, `protocolo_entrante`, `imap_host`, `imap_puerto`, `imap_cifrado`, `smtp_host`, `smtp_puerto`, `smtp_cifrado`, `modelo_ia`, `api_key_ia_cifrada`, `temperatura`, `tono_redaccion`, `escaneo_preventivo_activo`, `fecha_actualizacion`) VALUES
(1, 'user_admin_01', 'novamail.cicpc2026@gmail.com', '62kF0H2pPVFXsw5CpqtwTym6b9Rhdk4x4aF6MdSVBf+fg0wnikHovD9IDMg=', 'IMAP', 'imap.gmail.com', 993, 'SSL/TLS', 'smtp.gmail.com', 465, 'SSL/TLS', 'gemini-3.5-flash-lite', 'vycUP+W6i93vYVYiWCoQ85eIeLUkBaGwmw+JYES3daRexcSwuTr3gH7rKizHFEhmWHE6CGzSJ/qqNrZc59Vk07Pc8p5eEZXQkuPMoHoiepDJ', 0.30, 'Profesional', 1, '2026-11-14 05:30:59');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `registros_phishing_remoto`
--

DROP TABLE IF EXISTS `registros_phishing_remoto`;
CREATE TABLE IF NOT EXISTS `registros_phishing_remoto` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `uuid_incidente` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `fecha_deteccion` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `remitente_nombre` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `remitente_correo` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `destinatario_correo` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `asunto` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `cuerpo_resumen` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `direccion_ip_origen` varchar(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Soporta IPv4 e IPv6',
  `proveedor_hosting` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT 'Hosting / ASN desde donde se envió el correo',
  `asn_numero` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pais_origen` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `cabeceras_raw` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
  `es_phishing` tinyint(1) NOT NULL DEFAULT '1',
  `nivel_riesgo` enum('BAJO','MEDIO','ALTO','CRITICO') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'ALTO',
  `puntuacion_confianza` decimal(5,2) NOT NULL COMMENT 'Porcentaje de certeza IA (0.00 - 100.00)',
  `modelo_ia_utilizado` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `indicadores_detectados` json NOT NULL COMMENT 'Lista de URLs maliciosas, spoofing, urgencia, etc.',
  `estado_accion` enum('CUARENTENA','BLOQUEADO','FALSO_POSITIVO') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'CUARENTENA',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid_incidente` (`uuid_incidente`),
  KEY `idx_ip_origen` (`direccion_ip_origen`),
  KEY `idx_hosting` (`proveedor_hosting`),
  KEY `idx_remitente` (`remitente_correo`),
  KEY `idx_fecha` (`fecha_deteccion`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Volcado de datos para la tabla `registros_phishing_remoto`
--

INSERT INTO `registros_phishing_remoto` (`id`, `uuid_incidente`, `fecha_deteccion`, `remitente_nombre`, `remitente_correo`, `destinatario_correo`, `asunto`, `cuerpo_resumen`, `direccion_ip_origen`, `proveedor_hosting`, `asn_numero`, `pais_origen`, `cabeceras_raw`, `es_phishing`, `nivel_riesgo`, `puntuacion_confianza`, `modelo_ia_utilizado`, `indicadores_detectados`, `estado_accion`) VALUES
(1, 'PHISH-C7B9663A', '2026-11-14 00:08:37', 'Departamento de Facturación', 'cobros@factura-pendiente-portal.xyz', 'admin@novamail.ai', 'Aviso de Embargo Judicial - Factura Vencida #99412', 'Estimado cliente, descargue el comprobante fiscal adjunto en http://factura-pendiente-portal.xyz/descarga.exe antes de las 18:00 hrs.', '91.214.124.88', 'Hostinger International', 'AS47583 / CY', 'Desconocido', 'Received-SPF: softfail; DKIM-Signature: missing; DMARC: fail', 1, 'CRITICO', 99.95, 'gemini-3.5-flash-lite', '[\"Dominio del remitente sospechoso y no oficial (.xyz)\", \"Fallo en autenticación SPF (softfail)\", \"Firma DKIM ausente\", \"Fallo en política DMARC\", \"Uso de ingeniería social con temática de coacción legal y embargo judicial\", \"Urgencia artificial con límite de tiempo\", \"Enlace malicioso que descarga un archivo ejecutable (.exe)\"]', 'CUARENTENA'),
(2, 'PHISH-67D81F34', '2026-11-14 00:34:51', 'Departamento de Facturación', 'cobros@factura-pendiente-portal.xyz', 'admin@novamail.ai', 'Aviso de Embargo Judicial - Factura Vencida #99412', 'Estimado cliente, descargue el comprobante fiscal adjunto en http://factura-pendiente-portal.xyz/descarga.exe antes de las 18:00 hrs.', '91.214.124.88', 'Hostinger International', 'AS47583 / CY', 'Desconocido', 'Received-SPF: softfail; DKIM-Signature: missing; DMARC: fail', 1, 'CRITICO', 99.95, 'gemini-3.5-flash-lite', '[\"Dominio del remitente sospechoso y no oficial (.xyz)\", \"Falla en la validación DMARC y SPF (softfail)\", \"Firma DKIM faltante\", \"Uso de tácticas de urgencia artificial y coacción (aviso de embargo judicial, plazo estricto)\", \"Ingeniería social orientada a la descarga de un archivo ejecutable (.exe)\", \"Infraestructura de hosting asociada a proveedor de alto riesgo para campañas de malware\", \"Discrepancia entre el nombre del remitente (Departamento de Facturación) y la dirección de correo\"]', 'CUARENTENA');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuarios_soc`
--

DROP TABLE IF EXISTS `usuarios_soc`;
CREATE TABLE IF NOT EXISTS `usuarios_soc` (
  `id` int NOT NULL AUTO_INCREMENT,
  `usuario_id` varchar(100) NOT NULL,
  `nombre_completo` varchar(150) NOT NULL,
  `correo_login` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `rol` enum('ANALISTA_SOC','ADMIN') NOT NULL DEFAULT 'ADMIN',
  `intentos_fallidos` int NOT NULL DEFAULT '0',
  `bloqueado_hasta` datetime DEFAULT NULL,
  `ultimo_acceso` datetime DEFAULT NULL,
  `fecha_creacion` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `usuario_id` (`usuario_id`),
  UNIQUE KEY `correo_login` (`correo_login`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Volcado de datos para la tabla `usuarios_soc`
--

INSERT INTO `usuarios_soc` (`id`, `usuario_id`, `nombre_completo`, `correo_login`, `password_hash`, `rol`, `intentos_fallidos`, `bloqueado_hasta`, `ultimo_acceso`, `fecha_creacion`) VALUES
(1, 'user_admin_01', 'Administrador SOC', 'admin@novamail.ai', '$2y$10$IXLej3Y3CrJ7I3NLwb9gR.nsPhhygggu/pEIV29rxQvjt9ScPpcPa', 'ADMIN', 0, NULL, '2026-11-14 00:52:50', '2026-11-14 04:50:26');
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
