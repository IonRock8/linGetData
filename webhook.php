<?php
// ตั้งค่าการเชื่อมต่อฐานข้อมูล
$servername = "localhost";
$username = "root"; 
$password = ""; 
$dbname = "Sline_db";

// สร้างการเชื่อมต่อ
$conn = new mysqli($servername, $username, $password, $dbname);

// ตรวจสอบการเชื่อมต่อ
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
 
// X-Line-Signature ใช้ในการนกันบุคคลที่สามปลอมแปลงข้อมูล
$signature = $_SERVER['HTTP_X_LINE_SIGNATURE'];
$channelSecret = 'Your Channel Secret'; // แทนที่ด้วย Channel Secret ของคุณ

// รับข้อมูลจาก LINE
$content = file_get_contents('php://input');

// ตรวจสอบ Signature
$hash = base64_encode(hash_hmac('sha256', $content, $channelSecret, true));

if ($hash !== $signature) {
    http_response_code(400);
    exit();
}

$events = json_decode($content, true);
// ตรวจสอบว่ามีเหตุการณ์
if (!is_null($events['events'])) {
    foreach ($events['events'] as $event) {
        // ตรวจสอบว่าเป็นข้อความประเภทข้อความ
        if ($event['type'] == 'message' && $event['message']['type'] == 'text') {
            $userId = $event['source']['userId'];
            // ตรวจสอบว่าผู้ใช้งานมีอยู่ในฐานข้อมูลแล้วหรือไม่
            $stmt = $conn->prepare("SELECT id FROM users WHERE user_id = ?");
            $stmt->bind_param("s", $userId);
            $stmt->execute();
            $stmt->store_result();
            if ($stmt->num_rows == 0) {
                // ถ้ายังไม่มีผู้ใช้งานนี้ในฐานข้อมูล ให้ดึงข้อมูลผู้ใช้จาก LINE API
                $channelAccessToken = 'Your Channel Access Token '; // แทนที่ด้วย Channel Access Token ของคุณ
                $url = 'https://api.line.me/v2/bot/profile/' . $userId;

                $headers = [
                    'Authorization: Bearer ' . $channelAccessToken,
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
                $result = curl_exec($ch);
                curl_close($ch);

                $userProfile = json_decode($result, true);
                $displayName = $userProfile['displayName'];

                // เก็บข้อมูลลงฐานข้อมูล
                $insertStmt = $conn->prepare("INSERT INTO users (user_id, display_name) VALUES (?, ?)");
                $insertStmt->bind_param("ss", $userId, $displayName);
                $insertStmt->execute();
                $insertStmt->close();
            }

            $stmt->close();
        }
    }
}

$conn->close();

// ตอบกลับ LINE ว่ารับข้อมูลเรียบร้อย
echo "OK";
?>
