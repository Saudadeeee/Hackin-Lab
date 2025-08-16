# 🛡️ OS Command Injection Lab

Chào mừng đến với phòng lab OS Command Injection! Đây là một môi trường học tập an toàn để tìm hiểu về lỗ hổng OS Command Injection và cách khai thác chúng.

## 📋 Mục tiêu

OS Command Injection là một lỗ hổng bảo mật cho phép kẻ tấn công thực thi các lệnh hệ điều hành tùy ý trên máy chủ. Lab này sẽ giúp bạn:

- Hiểu cách OS Command Injection hoạt động
- Học các kỹ thuật bypass filter
- Thực hành khai thác trong môi trường an toàn
- Nắm vững cách phòng chống lỗ hổng này

## 🎯 Cấu trúc Lab

### 📚 Các Level

1. **Level 1** - Basic Command Injection
2. **Level 2** - Command Chaining
3. **Level 3** - Filter Bypass (Space filtering)
4. **Level 4** - Filter Bypass (Keyword filtering)
5. **Level 5** - Blind Command Injection
6. **Level 6** - Time-based Detection
7. **Level 7** - Output Redirection & Encoding
8. **Level 8** - WAF Bypass & Context Breaking
9. **Level 9** - Out-of-Band Injection
10. **Level 10** - Race Condition & Automation

## 🚀 Cách sử dụng

1. Chạy Docker container:
   ```bash
   docker-compose up -d
   ```

2. Truy cập http://localhost:8080

3. Bắt đầu từ Level 1 và tiến dần lên các level khó hơn

## 🛠️ Yêu cầu hệ thống

- Docker & Docker Compose
- Web browser
- Kiến thức cơ bản về command line

## ⚠️ Lưu ý bảo mật

**CẢNH BÁO**: Lab này chứa các lỗ hổng bảo mật được cố ý tạo ra cho mục đích học tập. 

- **KHÔNG** triển khai trên môi trường production
- **KHÔNG** kết nối với mạng internet công cộng
- Chỉ sử dụng trong môi trường isolated/sandbox

## 📖 Tài liệu tham khảo

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/os-command-injection)

## 🏆 Flags

Mỗi level sẽ có một flag ẩn mà bạn cần tìm ra thông qua việc khai thác OS Command Injection.

Format flag: `FLAG{command_injection_xxx}`

---

**Happy Hacking! 🔐**