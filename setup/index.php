<?php
if (!file_exists('config/config.php')) {
    http_response_code(500);
    die("<h1>Config file missing</h1><p>Please ensure you have created your config file (<code>config/config.php</code>).</p>");
}
include('config/config.php');
$zoom = !empty($_GET['zoom']) ? $_GET['zoom'] : null;
$encounterId = !empty($_GET['encId']) ? $_GET['encId'] : null;
if (!empty($_GET['lat']) && !empty($_GET['lon'])) {
    $startingLat = $_GET['lat'];
    $startingLng = $_GET['lon'];
    $locationSet = 1;
} else {
    $locationSet = 0;
}
if ($blockIframe) {
    header('X-Frame-Options: DENY');
}

if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
} elseif (isset($_SERVER['REMOTE_ADDR'])) {
    $ip = $_SERVER['REMOTE_ADDR'];
}
$db = new SQLite3('Discord-OAuth2/oauth2.db');
$query = "SELECT user FROM authorized WHERE ip = :ip";
$stmt = $db->prepare($query);
$stmt->bindValue(':ip', $ip);
$result = $stmt->execute();
$_SESSION['user'] = $result->fetchArray()[0];

$query = "DELETE FROM authorized WHERE ip = :ip";
$stmt = $db->prepare($query);
$stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
$stmt->execute();
if ($db->changes() == 0) {
    $db->close();
    header("Location: /subscribe?origin=map&lat=".$startingLat."&lon=".$startingLng);
} else {
    $db->close();
}

?>