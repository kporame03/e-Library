# 🏛️ DGA Citizen Auth Service (C++ Version)

ระบบยืนยันตัวตน (Authentication Service) ที่เชื่อมต่อกับแพลตฟอร์ม **"ทางรัฐ" (DGA)** พัฒนาด้วยภาษา **C++17** เพื่อประสิทธิภาพสูงสุด (High Performance) และใช้ทรัพยากรน้อย (Lightweight) ทำงานบน Docker Container และเก็บข้อมูลลงฐานข้อมูล **PostgreSQL**

![C++](https://img.shields.io/badge/Language-C++17-blue.svg)
![Docker](https://img.shields.io/badge/Container-Docker-2496ED.svg)
![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-336791.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

---

## ✨ ฟีเจอร์หลัก (Features)

- **DGA Integration:** เชื่อมต่อ API ของสำนักงานพัฒนารัฐบาลดิจิทัล (สพร.) เพื่อยืนยันตัวตนผ่าน `mToken`
- **Auto Login/Register Flow:**
  - ตรวจสอบผู้ใช้ในระบบอัตโนมัติ
  - หากมีข้อมูลแล้ว → **Login สำเร็จ**
  - หากยังไม่มีข้อมูล → **ดึงข้อมูลจาก DGA มา Pre-fill ลงฟอร์มลงทะเบียน**
- **High Performance:** ใช้ Library `cpp-httplib` และ `libcurl` ทำงานได้รวดเร็ว
- **Secure Database:** บันทึกข้อมูลสมาชิก (Citizen ID, ชื่อ, นามสกุล, เบอร์โทร) ลง PostgreSQL
- **Dockerized:** พร้อม Deploy ใช้งานได้ทันทีด้วย Docker Compose
- **RESTful API:** ดำเนินการผ่าน HTTP Request ได้สะดวก

---

## 📂 โครงสร้างโปรเจกต์ (Project Structure)

```
my-dga-project/
├── public/                 # ไฟล์ Frontend (HTML/JS/CSS)
│   ├── index.html          # หน้า Login (รับ mToken และ Auto-check)
│   └── register.html       # หน้าลงทะเบียน (Pre-fill จากข้อมูล DGA)
├── .env                    # ไฟล์ Config (ต้องสร้างเอง - ดูตัวอย่างด้านล่าง)
├── docker-compose.yml      # การตั้งค่า Docker Services (App + Database)
├── Dockerfile              # คำสั่งสร้าง Docker Image ของ C++ Server
├── init.sql                # สคริปต์สร้างตาราง Database ครั้งแรก
├── server.cpp              # โค้ดหลัก (Core Logic) ภาษา C++
└── README.md               # ไฟล์นี้
```

---

## 🚀 วิธีติดตั้งและใช้งาน (Installation & Setup)

### 1️⃣ ข้อกำหนดเบื้องต้น (Prerequisites)

- **Docker** และ **Docker Compose** ติดตั้งบนเซิร์ฟเวอร์
- **Git** (สำหรับ Clone Repository)
- **SSH Access** (สำหรับ Upload ไฟล์ไปยังเซิร์ฟเวอร์)

### 2️⃣ ขั้นตอนการติดตั้ง

#### ขั้นตอน A: Upload ไฟล์ไปยังเซิร์ฟเวอร์

```bash
# ตัวอย่างการ Upload โปรเจกต์ทั้งหมด
scp -r . root@128.199.121.125:~/czp/test1

# หรือเข้าไปในโฟลเดอร์เซิร์ฟเวอร์
ssh root@128.199.121.125
cd ~/czp/test1
```

#### ขั้นตอน B: ตั้งค่า Environment Variables

สร้างไฟล์ `.env` ในโฟลเดอร์โปรเจกต์:

```bash
cat > .env << 'EOF'
# ===== DATABASE CONFIG =====
DB_HOST=db
DB_PORT=5432
DB_NAME=citizen_db
DB_USER=postgres
DB_PASSWORD=SecurePassword123!

# ===== DGA / ทางรัฐ CONFIG =====
AGENT_ID=YOUR_AGENT_ID
CONSUMER_KEY=YOUR_CONSUMER_KEY
CONSUMER_SECRET=YOUR_CONSUMER_SECRET

# ===== API ENDPOINTS =====
DGA_AUTH_URL=https://api.egov.go.th/ws/auth/validate
DGA_DEPROC_URL=https://api.egov.go.th/ws/dga/czp/uat/v1/core/shield/data/deproc

# ===== SERVER CONFIG =====
APP_PORT=8080
APP_HOST=0.0.0.0
LOG_LEVEL=INFO
EOF
```

#### ขั้นตอน C: สร้างและเรียกใช้ Docker Container

```bash
# สร้าง Image และ Start Services
docker-compose up -d

# ตรวจสอบสถานะ Container
docker-compose ps

# ดูข้อมูล Log
docker-compose logs -f server
```

#### ขั้นตอน D: ตรวจสอบว่ามันใช้งานได้

```bash
# ทดสอบ Endpoint
curl -X GET http://localhost:8080/health

# ตรวจสอบ Database
docker-compose exec db psql -U postgres -d citizen_db -c "SELECT * FROM citizens;"
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | ตรวจสอบสถานะเซิร์ฟเวอร์ |
| `POST` | `/auth/login` | Login ด้วย mToken จาก DGA |
| `POST` | `/auth/register` | ลงทะเบียนผู้ใช้ใหม่ |
| `GET` | `/auth/user/:id` | ดึงข้อมูลผู้ใช้ |
| `GET` | `/auth/validate` | ยืนยันตัวตน |

---

## 📊 Database Schema

### ตาราง: `citizens`

```sql
CREATE TABLE citizens (
    id SERIAL PRIMARY KEY,
    citizen_id VARCHAR(20) UNIQUE NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    phone_number VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 🔧 การแก้ไขปัญหา (Troubleshooting)

### ❌ Container ไม่ Start

```bash
# ดูข้อมูล Error
docker-compose logs server

# ลบทุกอย่างและสร้างใหม่
docker-compose down
docker-compose up -d --build
```

### ❌ Database Connection Error

```bash
# ตรวจสอบว่า Database Container ทำงาน
docker-compose ps

# เข้า Container Database
docker-compose exec db psql -U postgres
```

### ❌ Port ถูกใช้งานแล้ว

```bash
# เปลี่ยน Port ใน docker-compose.yml
# หรือ Kill Process ที่ใช้งาน Port
lsof -i :8080
kill -9 <PID>
```

---

## 🛑 Stop และ Remove Services

```bash
# หยุด Container (ข้อมูล Database ยังคงเหลือ)
docker-compose stop

# ลบทุกอย่าง (รวมถึงข้อมูล)
docker-compose down -v
```

---

## 📝 Development Notes

- โปรเจกต์นี้ใช้ **C++17 Standard**
- ใช้ Library: `cpp-httplib`, `libcurl`, `libpq`, `nlohmann/json`
- Database: **PostgreSQL 13+**
- ทำงานบน **Linux Docker Container**

---

## 📧 ติดต่อและสนับสนุน

สำหรับคำถามหรือปัญหา สามารถติดต่อทีมพัฒนา หรือเปิด Issue บน Repository

---

## 📄 License

Project นี้ได้รับใบอนุญาต MIT License - ดูไฟล์ LICENSE เพื่อรายละเอียดเพิ่มเติม

---

**Last Updated:** January 2026
**Version:** 1.0.0

#   M T o k e n - C -  
 