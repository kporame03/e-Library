# ใช้ Ubuntu เป็นฐาน
FROM ubuntu:22.04

# ป้องกันการถาม Interactive ขณะติดตั้ง
ENV DEBIAN_FRONTEND=noninteractive

# 1. ติดตั้ง Compiler และ Library ที่จำเป็น
RUN apt-get update && apt-get install -y \
    g++ \
    make \
    libcurl4-openssl-dev \
    libpq-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# 2. ดาวน์โหลด Header Libraries (JSON & HTTP)
RUN wget -q https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp -O /usr/include/json.hpp
RUN wget -q https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h -O /usr/include/httplib.h

# 3. เตรียมโฟลเดอร์ทำงาน
WORKDIR /app

# 4. Copy โค้ดทั้งหมดเข้า Container
COPY . .

# 5. สั่ง Compile (เพิ่ม -I/usr/include/postgresql เพื่อให้หา libpq เจอ)
RUN g++ server.cpp -o server -O2 -std=c++17 -I/usr/include/postgresql -lcurl -lpq

# 6. เปิด Port 8080 (ภายใน)
EXPOSE 8080

# 7. รันโปรแกรม
CMD ["./server"]