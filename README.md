# ESCUDO-ANTI-PHISHING---NOVAMAIL
NovaMail AI v2.0, una plataforma que redefinela seguridad del correo electrónico corporativo al fusionar un cliente IMAP/SMTP nativo con un Centro de Operaciones de Seguridad (SOC) autónomo.
ENTREGABLE TÉCNICO — FASE 0 (HORAS 0–3)
NovaMail AI (v2.0) — Esquema DDL, Criptografía &
Auth SOC
Arquitectura: PHP 8.x Nativo + PDO + OpenSSL + MySQL 8.x | Seguridad: AES-256-GCM & CAPTCHA SVG
Resumen de Implementación: Este documento contiene los tres componentes fundacionales del
backend requeridos en el PRD: (1) el modelo relacional schema.sql para configuración cifrada,
auditoría forense de phishing y analistas SOC; (2) el módulo criptográfico crypto.php bajo estándar
AES-256-GCM con IV de 12 bytes, Tag de 16 bytes y enmascaramiento de secretos; y (3) el controlador
auth_captcha.php con generación SVG en memoria y bloqueo temporal anti-fuerza bruta.
1. Esquema Relacional MySQL ( database/schema.sql )
Define la base de datos novamail_ai con codificación utf8mb4 , restricciones de integridad y
claves únicas para el seguimiento de incidentes ( uuid_incidente ).
NovaMail AI v2.0 — Fase 0: Arquitectura Core, DDL & Seguridad Page 1 of 6
-- ============================================================================
-- NovaMail AI (v2.0) - Esquema DDL MySQL 8.x (Fase 0: Horas 0-3)
-- ============================================================================
CREATE DATABASE IF NOT EXISTS `novamail_ai`
DEFAULT CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;
USE `novamail_ai`;
-- 1. Tabla de Configuración de Servidores (IMAP/SMTP) y Motor Google Gemini
CREATE TABLE IF NOT EXISTS `configuracion_novamail` (
`id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
`usuario_id` VARCHAR(64) NOT NULL,
`correo_electronico` VARCHAR(255) NOT NULL,
`password_token_cifrado` TEXT NOT NULL COMMENT 'Cifrado AES-256-GCM (Base64:
IV12 + Tag16 + Cipher)',
`protocolo_entrante` ENUM('IMAP','POP3') NOT NULL DEFAULT 'IMAP',
`imap_host` VARCHAR(255) NOT NULL,
`imap_puerto` SMALLINT UNSIGNED NOT NULL DEFAULT 993,
`imap_cifrado` ENUM('SSL/TLS','STARTTLS','NINGUNO') NOT NULL DEFAULT 'SSL/TLS',
`smtp_host` VARCHAR(255) NOT NULL,
`smtp_puerto` SMALLINT UNSIGNED NOT NULL DEFAULT 465,
`smtp_cifrado` ENUM('SSL/TLS','STARTTLS','NINGUNO') NOT NULL DEFAULT 'SSL/TLS',
`modelo_ia` VARCHAR(80) NOT NULL DEFAULT 'gemini-3.8-flash',
`api_key_ia_cifrada` TEXT NOT NULL COMMENT 'API Key Gemini cifrada con AES-256-
GCM',
`temperatura` DECIMAL(3,2) NOT NULL DEFAULT 0.30,
`tono_redaccion` VARCHAR(50) NOT NULL DEFAULT 'Profesional',
`escaneo_preventivo_activo` TINYINT(1) NOT NULL DEFAULT 1,
`fecha_actualizacion` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE
CURRENT_TIMESTAMP,
PRIMARY KEY (`id`),
UNIQUE KEY `uk_usuario_config` (`usuario_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- 2. Tabla de Trazabilidad Forense y Cuarentena Automatizada
CREATE TABLE IF NOT EXISTS `registros_phishing_remoto` (
`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
`uuid_incidente` VARCHAR(36) NOT NULL COMMENT 'Identificador forense único (ej.
PHISH-XXXXXXXX)',
`remitente_nombre` VARCHAR(255) DEFAULT NULL,
`remitente_correo` VARCHAR(255) NOT NULL,
`asunto` VARCHAR(500) NOT NULL,
`direccion_ip_origen` VARCHAR(45) DEFAULT '0.0.0.0',
`proveedor_hosting` VARCHAR(255) DEFAULT 'Desconocido',
`asn_numero` VARCHAR(64) DEFAULT NULL,
`nivel_riesgo` ENUM('BAJO','MEDIO','ALTO','CRITICO') NOT NULL DEFAULT 'ALTO',
`puntuacion_confianza` DECIMAL(5,2) NOT NULL DEFAULT 0.00,
`indicadores_json` JSON DEFAULT NULL COMMENT 'Evidencia técnica SPF/DKIM/DMARC y
URLs',
`cabeceras_raw` MEDIUMTEXT DEFAULT NULL,
`estado_accion` ENUM('CUARENTENA_IA','LIBERADO','ELIMINADO') NOT NULL DEFAULT
'CUARENTENA_IA',
`fecha_deteccion` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
PRIMARY KEY (`id`),
NovaMail AI v2.0 — Fase 0: Arquitectura Core, DDL & Seguridad Page 2 of 6
2. Bóveda Criptográfica AES-256-GCM ( backend/crypto.php )
Implementa cifrado autenticado AEAD nativo mediante openssl_encrypt / openssl_decrypt
exigiendo un vector de inicialización (IV) criptográficamente aleatorio de 12 bytes y etiqueta de
integridad (Tag) de 16 bytes, más la función mask_secret() para respuestas GET .
NovaMail AI v2.0 — Fase 0: Arquitectura Core, DDL & Seguridad Page 3 of 6
<?php
declare(strict_types=1);
/**
* NovaMail AI (v2.0) - Módulo Criptográfico AES-256-GCM (PHP 8.x)
* Estándar AEAD: IV de 12 bytes (96 bits) + Tag de autenticación de 16 bytes (128
bits).
*/
const NOVAMAIL_CIPHER_ALGO = 'aes-256-gcm';
const NOVAMAIL_IV_LENGTH = 12;
const NOVAMAIL_TAG_LENGTH = 16;
/**
* Obtiene una llave maestra binaria exacta de 32 bytes (256 bits) mediante SHA-
256.
* En producción/hackatón leer desde variable de entorno NOVAMAIL_MASTER_KEY.
*/
function get_master_key(): string
{
$secretSeed = getenv('NOVAMAIL_MASTER_KEY') ?:
'NovaMail_AI_v2_Hackathon_MasterSeed_2026!#';
return hash('sha256', $secretSeed, true); // 32 bytes crudos
}
/**
* Cifra un secreto en texto plano usando AES-256-GCM.
* Estructura del payload codificado en Base64: [IV (12B)] + [TAG (16B)] +
[CIPHERTEXT].
*/
function encrypt_secret(string $plainText): string
{
if ($plainText === '') {
return '';
}
$key = get_master_key();
$iv = random_bytes(NOVAMAIL_IV_LENGTH);
$tag = '';
$cipherText = openssl_encrypt(
$plainText,
NOVAMAIL_CIPHER_ALGO,
$key,
OPENSSL_RAW_DATA,
$iv,
$tag,
'',
NOVAMAIL_TAG_LENGTH
);
if ($cipherText === false || strlen($tag) !== NOVAMAIL_TAG_LENGTH) {
throw new RuntimeException('Fallo crítico al cifrar credencial con AES-
256-GCM.');
}
NovaMail AI v2.0 — Fase 0: Arquitectura Core, DDL & Seguridad Page 4 of 6
3. Autenticación SOC & CAPTCHA SVG ( backend/auth_captcha.php )
Genera retos visuales SVG ligeros en memoria vinculados a sesión HttpOnly (TTL de 5 minutos,
un solo uso) y aplica bloqueo progresivo anti-fuerza bruta en MySQL mediante consultas preparadas
PDO .
NovaMail AI v2.0 — Fase 0: Arquitectura Core, DDL & Seguridad Page 5 of 6
<?php
declare(strict_types=1);
/**
* NovaMail AI (v2.0) - Controlador de Autenticación SOC y CAPTCHA SVG
* Endpoints:
* GET -> ?action=captcha (Genera reto SVG) | ?action=status (Verifica
sesión)
* POST -> Autentica analista validando CAPTCHA + Hash + Bloqueo Anti-
BruteForce
* DELETE -> Cierra y destruye la sesión de forma segura
*/
ob_start();
ini_set('display_errors', '0');
if (session_status() === PHP_SESSION_NONE) {
session_start([
'cookie_httponly' => true,
'cookie_samesite' => 'Strict'
]);
}
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
function json_response(array $data, int $status = 200): never
{
while (ob_get_level() > 0) {
ob_end_clean();
}
http_response_code($status);
echo json_encode($data, JSON_UNESCAPED_UNICODE);
exit;
}
/**
* Genera un CAPTCHA SVG ligero de 6 caracteres sin dependencias externas
(GD/Imagick).
*/
function generate_svg_captcha(): string
{
$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
$code = '';
for ($i = 0; $i < 6; $i++) {
$code .= $alphabet[random_int(0, strlen($alphabet) - 1)];
}
$_SESSION['soc_captcha'] = [
'code' => $code,
'expires' => time() + 300 // Validez de 5 minutos
];
$w = 180;
