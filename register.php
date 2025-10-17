<?php

// ⚠️ แก้ไข: รวมไฟล์ config_mysqli.php เพื่อตั้งค่าฐานข้อมูลและ Session
require_once 'config_mysqli.php'; 

// ⚠️ โค้ด session_start() เดิมถูกลบออก เพราะถูกย้ายไปอยู่ใน config_mysqli.php แล้ว

$errors = [];
$success = "";

// ⚠️ แก้ไข: ลบโค้ดเชื่อมต่อฐานข้อมูลเดิมทิ้ง เพราะ config_mysqli.php จัดการให้แล้ว
// และใช้ $mysqli ที่ถูกสร้างจาก config ไฟล์

// ⚠️ แก้ไข: ลบโค้ดจัดการ Error การเชื่อมต่อเดิมทิ้ง เพราะ config_mysqli.php ใช้ try-catch จัดการแล้ว

// ฟังก์ชันเล็ก ๆ กัน XSS เวลา echo ค่าเดิมกลับฟอร์ม
function e($str){ return htmlspecialchars($str ?? "", ENT_QUOTES, "UTF-8"); }

// สร้าง CSRF token ครั้งแรก (หาก config_mysqli.php ยังไม่ได้ทำ)
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  
  // รับ CSRF token ก่อน
  $csrf_token = $_POST['csrf_token'] ?? "";

  // ⚠️ ปรับปรุง: ตรวจ CSRF token และหยุดการประมวลผลทันทีหากไม่ถูกต้อง
  if (empty($csrf_token) || !hash_equals($_SESSION['csrf_token'], $csrf_token)) {
    // Regenerate token เพื่อป้องกันการลองซ้ำ
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    // การใช้ die/exit ดีกว่าการเพิ่ม error เข้า array เพื่อหยุดการโจมตีทันที
    die("CSRF token ไม่ถูกต้อง กรุณารีเฟรชหน้าแล้วลองอีกครั้ง");
  }

  // รับค่าจากฟอร์ม
  $username  = trim($_POST['username'] ?? "");
  $password  = $_POST['password'] ?? "";
  $email     = trim($_POST['email'] ?? "");
  $full_name = trim($_POST['name'] ?? "");

  // ⚠️ ปรับปรุง: Sanitization สำหรับชื่อ-นามสกุล ก่อนใช้งาน
  $full_name = htmlspecialchars($full_name, ENT_QUOTES, 'UTF-8');

  // ตรวจความถูกต้องเบื้องต้น
  if ($username === "" || !preg_match('/^[A-Za-z0-9_\.]{3,30}$/', $username)) {
    $errors[] = "กรุณากรอก username 3–30 ตัวอักษร (a-z, A-Z, 0-9, _, .)";
  }
  if (strlen($password) < 8) {
    $errors[] = "รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร";
  }
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "อีเมลไม่ถูกต้อง";
  }
  if ($full_name === "" || mb_strlen($full_name) > 100) {
    $errors[] = "กรุณากรอกชื่อ–นามสกุล (ไม่เกิน 100 ตัวอักษร)";
  }

  // ตรวจซ้ำ username/email
  if (!$errors) {
    try {
      $sql = "SELECT 1 FROM users WHERE username = ? OR email = ? LIMIT 1";
      $stmt = $mysqli->prepare($sql);
      $stmt->bind_param("ss", $username, $email);
      $stmt->execute();
      $stmt->store_result();
      if ($stmt->num_rows > 0) {
        $errors[] = "Username หรือ Email นี้ถูกใช้แล้ว";
      }
      $stmt->close();
    } catch (mysqli_sql_exception $e) {
      // ⚠️ การจัดการ Error: ใช้ try-catch เนื่องจาก config_mysqli.php ตั้งค่าให้โยน Exception
      error_log("Database error (duplicate check): " . $e->getMessage());
      $errors[] = "เกิดข้อผิดพลาดภายในระบบ โปรดลองอีกครั้ง (ERR_DUP_CHK)";
    }
  }

  // บันทึกลงฐานข้อมูล
  if (!$errors) {
    // ⚠️ ปรับปรุง: ใช้ PASSWORD_BCRYPT แทน PASSWORD_DEFAULT เพื่อความชัดเจนและเสถียร
    $password_hash = password_hash($password, PASSWORD_BCRYPT); 

    try {
      $sql = "INSERT INTO users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)";
      $stmt = $mysqli->prepare($sql);
      $stmt->bind_param("ssss", $username, $email, $password_hash, $full_name);
      $stmt->execute();
      
      $success = "สมัครสมาชิกสำเร็จ! คุณสามารถล็อกอินได้แล้วค่ะ";
      // regenerate CSRF token หลังสำเร็จ
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
      // เคลียร์ฟอร์ม
      $username = $email = $full_name = "";
      
    } catch (mysqli_sql_exception $e) {
        // ⚠️ การจัดการ Error: ตรวจจับ duplicate (1062) และ Error อื่น ๆ
        if ($e->getCode() === 1062) {
             $errors[] = "Username หรือ Email ซ้ำ กรุณาใช้ค่าอื่น";
        } else {
             error_log("Database error (insert): " . $e->getMessage());
             $errors[] = "บันทึกข้อมูลไม่สำเร็จ: เกิดข้อผิดพลาดภายในระบบ โปรดลองอีกครั้ง";
        }
    }
  }
}
?>
<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Register</title>
  <style>
    /* ... (CSS ส่วนนี้คงเดิม) ... */
    body{font-family:system-ui, sans-serif; background:#f7f7fb; margin:0; padding:0;}
    .container{max-width:480px; margin:40px auto; background:#fff; border-radius:16px; padding:24px; box-shadow:0 10px 30px rgba(0,0,0,.06);}
    h1{margin:0 0 16px;}
    .alert{padding:12px 14px; border-radius:12px; margin-bottom:12px; font-size:14px;}
    .alert.error{background:#ffecec; color:#a40000; border:1px solid #ffc9c9;}
    .alert.success{background:#efffed; color:#0a7a28; border:1px solid #c9f5cf;}
    label{display:block; font-size:14px; margin:10px 0 6px;}
    input{width:100%; padding:12px; border-radius:12px; border:1px solid #ddd;}
    button{width:100%; padding:12px; border:none; border-radius:12px; margin-top:14px; background:#3b82f6; color:#fff; font-weight:600; cursor:pointer;}
    button:hover{filter:brightness(.95);}
    .hint{font-size:12px; color:#666;}
  </style>
</head>
<body>
  <div class="container">
    <h1>สมัครสมาชิก</h1>

    <?php if ($errors): ?>
      <div class="alert error">
        <?php foreach ($errors as $m) echo "<div>".e($m)."</div>"; ?>
      </div>
    <?php endif; ?>

    <?php if ($success): ?>
      <div class="alert success"><?= e($success) ?></div>
    <?php endif; ?>

    <form method="post" action="">
      <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']) ?>">
      <label>Username</label>
      <input type="text" name="username" value="<?= e($username ?? "") ?>" required>
      <div class="hint">อนุญาต a-z, A-Z, 0-9, _ และ . (3–30 ตัว)</div>

      <label>Password</label>
      <input type="password" name="password" required>
      <div class="hint">อย่างน้อย 8 ตัวอักษร</div>

      <label>Email</label>
      <input type="email" name="email" value="<?= e($email ?? "") ?>" required>

      <label>ชื่อ–นามสกุล</label>
      <input type="text" name="name" value="<?= e($full_name ?? "") ?>" required>

      <button type="submit">สมัครสมาชิก</button>
    </form>
  </div>
</body>
</html>