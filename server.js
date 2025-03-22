const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = 3000;

// MySQL 연결 설정
const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "oldplace0312@",
  database: "codeit",
});

// 미들웨어 설정
app.use(bodyParser.json());
app.use(cookieParser());

app.use(express.static(path.join(__dirname, "public")));

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// 회원가입 API (비밀번호 암호화 후 저장)
app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
  
    try {
      const [result] = await db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashedPassword]
      );
      res.json({ message: "회원가입 성공", userId: result.insertId });
    } catch (err) {
      res.status(500).json({ message: "회원가입 실패", error: err.message });
    }
  });

// 로그인 API (세션 생성)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // 유저 정보 가져오기
    const [users] = await db.execute("SELECT * FROM users WHERE username = ?", [username]);
    if (users.length === 0) return res.status(401).json({ message: "Invalid" });

    const user = users[0];

    // 비밀번호 검증
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid username or password" });

    // 기존 활성 세션 확인
    const [activeSessions] = await db.execute(
        "SELECT * FROM sessions WHERE userId = ? AND isSimultaneousLogin = FALSE AND expiresAt > NOW()",
        [user.id]
    );

    let isSimultaneous = false;
    if (activeSessions.length > 0) {
        // 이미 로그인된 세션이 있음 -> 중복 로그인 처리
        isSimultaneous = true;
    }

    // 새 세션 생성 (중복 로그인 여부 반영)
    const sessionId = crypto.randomBytes(64).toString("hex");
    const expiresAt = new Date(Date.now() + 3600000);
    await db.execute(
        "INSERT INTO sessions (sessionId, userId, isSimultaneousLogin, expiresAt) VALUES (?, ?, ?, ?)",
        [sessionId, user.id, isSimultaneous, expiresAt]
    );

    res.cookie("sessionId", sessionId, {
        httpOnly: true,  // 클라이언트 측에서 자바스크립트로 접근할 수 없도록 설정
        secure: true,    // https에서만 쿠키를 보내도록 설정 (http에서 테스트할 때는 false로 설정)
        maxAge: 3600000  // 쿠키의 만료 시간 (1시간)
    });

    if (isSimultaneous) {
        res.json({ sessionId, isSimultaneous, message: "동시 접속이 확인돼서 더 이상 사용할 수 없습니다" }); // 제한 세션
    } else {
        res.json({ sessionId, isSimultaneous }); // 정상 세션
    }

  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ message: "Server error" });
  }  
});

// 로그아웃 API (세션 삭제)
app.post("/logout", async (req, res) => {
  const { sessionId } = req.cookies;  // 쿠키에서 sessionId 가져오기

  try {
    await db.execute("DELETE FROM sessions WHERE sessionId = ?", [sessionId]);
    res.json({ message: "로그아웃 성공" });
  } catch (err) {
    res.status(500).json({ message: "로그아웃 실패", error: err.message });
  }
});

// 서비스 API(정상 세션에게만 보호된 리소스 제공)
app.get("/protected", async (req, res) => {
  const { sessionId } = req.cookies;  // 쿠키에서 sessionId 가져오기

  if (!sessionId) {
      return res.status(401).json({ message: "로그인이 필요한 서비스입니다." });
  }

  // 세션 ID로 세션 확인
  const [sessions] = await db.execute("SELECT * FROM sessions WHERE sessionId = ? AND expiresAt > NOW()", [sessionId]);

  if (sessions.length === 0) {
      return res.status(401).json({ message: "로그인이 필요한 서비스입니다(Invalid session)." });
  }

  const session = sessions[0];

  if (session.isSimultaneousLogin) {
      return res.status(403).json({ message: "동시 접속이 확인 돼서 더 이상 사용할 수 없습니다", data: "리소스 제공 불허" });
  }

  res.json({ message: "접근 허용", data: "정상 세션일 때 반환되는 보호된 리소스" });
});


// 서버 실행
app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});
