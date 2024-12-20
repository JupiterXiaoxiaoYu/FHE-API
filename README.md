# FHE-API

[English](#english) | [中文](#chinese)

## English

### Introduction
FHE-API is a Fully Homomorphic Encryption (FHE) API service built with Rust and TFHE-rs library. It provides secure computation capabilities on encrypted data without decrypting it, ensuring data privacy during processing.

### Features
- Generate FHE key pairs
- Encrypt/decrypt data
- Perform secure computations on encrypted data
- Support for basic arithmetic operations
- RESTful API interface

### Prerequisites
- Rust (latest stable version)
- Cargo
- Node.js (for testing)
- CUDA Toolkit (for GPU acceleration)

### Installation & Setup
1. Clone the repository:

```bash
git clone https://github.com/JupiterXiaoxiaoYu/FHE-API.git
cd FHE-API
```

2. Build the project:
```bash
cargo build --release
```

3. Setup test environment:

```bash
cd test
npm install
```

### Running the Service
1. Start the server:

```bash
cargo run 
```

2. Run the test client:

```bash
cd test
npm run test
```

---

## Chinese

### 项目介绍
FHE-API 是一个基于 Rust 和 TFHE-rs 库构建的全同态加密(FHE)API服务。它能够在不解密的情况下对加密数据进行计算，确保数据处理过程中的隐私安全。

### 功能特点
- 生成 FHE 密钥对
- 数据加密/解密
- 对加密数据进行安全计算
- 支持基本算术运算
- RESTful API 接口

### 环境要求
- Rust (最新稳定版)
- Cargo
- Node.js (用于测试)
- CUDA Toolkit (用于 GPU 加速)

### 安装与设置
1. 克隆仓库：

```bash
git clone https://github.com/JupiterXiaoxiaoYu/FHE-API.git
cd FHE-API
```

2. 构建项目：

```bash
cargo build
```
3. 设置测试环境：

```bash
cd test
npm install
```

### 运行服务
1. 启动服务器：

```bash
cargo run 
```

2. 运行测试客户端：

```bash
cd test
npm run test
```
