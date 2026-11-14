<?php
require_once 'conexion.php';

header('Content-Type: application/json; charset=utf-8');

try {
    $stmt = $pdo->query("SELECT * FROM registros_phishing_remoto ORDER BY fecha_deteccion DESC");
    $logs = $stmt->fetchAll();
    echo json_encode(['success' => true, 'data' => $logs]);
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
?>
