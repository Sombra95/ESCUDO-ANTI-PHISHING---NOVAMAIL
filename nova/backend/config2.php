<?php
require_once 'conexion.php';
require_once 'crypto.php';

header('Content-Type: application/json; charset=utf-8');
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    try {
        $stmt = $pdo->query("SELECT * FROM configuracion_novamail LIMIT 1");
        $config = $stmt->fetch();

        if ($config) {
            $config['password_token_cifrado'] = !empty($config['password_token_cifrado']) ? '••••••••••••' : '';
            $config['api_key_ia_cifrada']     = !empty($config['api_key_ia_cifrada']) ? 'AIzaSy••••••••••••••••••••' : '';
        }

        echo json_encode(['success' => true, 'config' => $config ?: null]);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
} 
else if ($method === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    if (!$data) {
        echo json_encode(['success' => false, 'error' => 'Datos JSON inválidos']);
        exit;
    }

    $modelo = trim($data['modeloIa'] ?? 'gemini-3.8-flash');
    $apiKey = trim($data['apiKeyIa'] ?? '');
    $passwordToken = $data['passwordToken'] ?? '';

    $stmtPrev = $pdo->query("SELECT password_token_cifrado, api_key_ia_cifrada FROM configuracion_novamail LIMIT 1");
    $prevConfig = $stmtPrev->fetch();

    if (strpos($apiKey, '••••') !== false && $prevConfig) {
        $apiKey = descifrarDato($prevConfig['api_key_ia_cifrada']);
    }
    if (strpos($passwordToken, '••••') !== false && $prevConfig) {
        $passwordToken = descifrarDato($prevConfig['password_token_cifrado']);
    }

    $avisoSaturacion = '';

    if (!empty($apiKey) && $apiKey !== 'AIzaSy_MockKey' && strpos($modelo, 'gemini') !== false) {
        $url = "https://generativelanguage.googleapis.com/v1beta/models/" . urlencode($modelo) . ":generateContent?key=" . urlencode($apiKey);
        $payload = json_encode([
            "contents" => [["parts" => [["text" => "OK"]]]]
        ]);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr  = curl_error($ch);
        curl_close($ch);

        if ($curlErr) {
            echo json_encode(['success' => false, 'error' => 'Error de conexión cURL: ' . $curlErr]);
            exit;
        }

        // Si es 503 (alta demanda), la clave API es válida pero el modelo está congestionado temporalmente
        if ($httpCode === 503) {
            $avisoSaturacion = ' (Nota: El modelo reportó alta demanda temporal, pero tu API Key es válida)';
        } elseif ($httpCode !== 200) {
            $errorData = json_decode($response, true);
            $errorMsg = $errorData['error']['message'] ?? "HTTP $httpCode - Respuesta: " . substr($response, 0, 200);
            echo json_encode(['success' => false, 'error' => 'Validación de IA fallida: ' . $errorMsg]);
            exit;
        }
    }

    $passwordCifrado = cifrarDato($passwordToken);
    $apiKeyCifrada   = cifrarDato($apiKey);

    try {
        $sql = "INSERT INTO configuracion_novamail 
                (usuario_id, correo_electronico, password_token_cifrado, protocolo_entrante, 
                 imap_host, imap_puerto, imap_cifrado, smtp_host, smtp_puerto, smtp_cifrado, 
                 modelo_ia, api_key_ia_cifrada, temperatura, tono_redaccion, escaneo_preventivo_activo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                correo_electronico = VALUES(correo_electronico),
                password_token_cifrado = VALUES(password_token_cifrado),
                protocolo_entrante = VALUES(protocolo_entrante),
                imap_host = VALUES(imap_host),
                imap_puerto = VALUES(imap_puerto),
                imap_cifrado = VALUES(imap_cifrado),
                smtp_host = VALUES(smtp_host),
                smtp_puerto = VALUES(smtp_puerto),
                smtp_cifrado = VALUES(smtp_cifrado),
                modelo_ia = VALUES(modelo_ia),
                api_key_ia_cifrada = VALUES(api_key_ia_cifrada),
                temperatura = VALUES(temperatura),
                tono_redaccion = VALUES(tono_redaccion),
                escaneo_preventivo_activo = VALUES(escaneo_preventivo_activo)";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            $data['usuarioId'] ?? 'user_admin_01',
            $data['correo'] ?? '',
            $passwordCifrado,
            $data['protocoloEntrante'] ?? 'IMAP',
            $data['imapHost'] ?? '',
            $data['imapPuerto'] ?? 993,
            $data['imapCifrado'] ?? 'SSL/TLS',
            $data['smtpHost'] ?? '',
            $data['smtpPuerto'] ?? 465,
            $data['smtpCifrado'] ?? 'SSL/TLS',
            $modelo,
            $apiKeyCifrada,
            $data['temperatura'] ?? 0.30,
            $data['tono'] ?? 'Profesional',
            isset($data['escaneoActivo']) ? (int)$data['escaneoActivo'] : 1
        ]);

        echo json_encode([
            'success' => true, 
            'message' => '¡Credenciales cifradas (AES-256-GCM) y configuración guardada en MySQL!' . $avisoSaturacion
        ]);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
}
?>