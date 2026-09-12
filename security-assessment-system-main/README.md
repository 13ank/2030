# คู่มือการติดตั้งโปรเจค Security Misconfiguration Assessment

หากต้องการนำโปรเจคนี้ไปรันบนเครื่อง Kali Linux เครื่องอื่น กรุณาทำตามขั้นตอนด้านล่างนี้เพื่อให้ระบบมีเครื่องมือและไลบรารีครบถ้วนสมบูรณ์

## 1. การอัปเดตระบบพื้นฐาน (แนะนำ)
ก่อนติดตั้งเครื่องมือใดๆ ควรตรวจสอบให้แน่ใจว่าระบบ Kali Linux อัปเดตล่าสุด
```bash
sudo apt update && sudo apt upgrade -y
```

## 2. การติดตั้ง Python Dependencies (ไลบรารีของโปรเจค)
โปรเจคนี้ใช้ Python 3 ในการทำงาน และจำเป็นต้องติดตั้งไลบรารีเพิ่มเติม ให้เปิด Terminal ไปที่โฟลเดอร์ของโปรเจค แล้วรันคำสั่ง:
```bash
pip3 install -r requirements.txt
```
> **หมายเหตุ:** หากระบบบังคับให้ติดตั้งผ่าน virtual environment (PEP 668) ให้ใช้คำสั่ง:
> `pip3 install -r requirements.txt --break-system-packages`

## 3. การติดตั้ง Security Tools (เครื่องมือสแกนทั้ง 6 ตัว)
ระบบต้องการเครื่องมือสแกนช่องโหว่ 6 ตัว รันคำสั่งด้านล่างนี้เพื่อติดตั้งทั้งหมด:
```bash
sudo apt install -y nmap whatweb nikto gobuster testssl.sh nuclei
```

**รายละเอียดแต่ละเครื่องมือ:**
- `nmap`: ใช้สำหรับสแกนพอร์ตและ Network Exposure
- `whatweb`: ใช้สำหรับดู Tech Stack และเวอร์ชันซอฟต์แวร์
- `nikto`: ใช้สแกน Web Server Misconfiguration 
- `gobuster`: ใช้สำหรับ Brute-force หาไฟล์และโฟลเดอร์ลับ
- `testssl.sh`: ใช้สำหรับสแกนความปลอดภัยของ SSL/TLS
- `nuclei`: ใช้สแกนหาช่องโหว่ขั้นสูง (CVEs/Exposures) ผ่านเทมเพลต

## 4. การติดตั้ง Wordlists (พจนานุกรมสำหรับ Gobuster)
โปรเจคนี้ตั้งค่าเริ่มต้นให้ Gobuster เรียกใช้ไฟล์ `/usr/share/wordlists/dirb/common.txt` ซึ่งปกติจะมีมาให้ใน Kali Linux อยู่แล้ว แต่ถ้าเครื่องเป้าหมายไม่มี ให้ติดตั้งแพ็กเกจ dirb:
```bash
sudo apt install -y dirb
```

## 5. การตั้งค่า / อัปเดตฐานข้อมูลเครื่องมือ (ก่อนใช้งานครั้งแรก)
- **สำหรับ Nuclei:** ควรดาวน์โหลดและอัปเดตเทมเพลตช่องโหว่ล่าสุดก่อนรันโปรเจค ให้รันคำสั่งนี้ใน Terminal 1 ครั้ง:
  ```bash
  nuclei -update-templates
  ```
- **สำหรับ Nikto (ทางเลือก):** อัปเดตฐานข้อมูลช่องโหว่พื้นฐาน
  ```bash
  sudo nikto -update
  ```

## 6. วิธีรันโปรเจคเพื่อทดสอบ
เมื่อติดตั้งทุกอย่างครบถ้วนแล้ว สามารถทดสอบรันโปรเจคได้ด้วยคำสั่ง:
```bash
python3 main.py -u https://example.com
```
*(ผลลัพธ์รายงานจะถูกสร้างและเก็บไว้ในโฟลเดอร์ `/reports`)*
