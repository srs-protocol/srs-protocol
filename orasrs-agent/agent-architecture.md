# OraSRS Agent 架构设计文档

## 概述

OraSRS Agent 是 OraSRS v2.0 框架的边缘层核心组件，是一个超轻量级的威胁检测和响应代理，部署在终端设备和网络边缘，资源占用 < 5MB。

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    OraSRS Agent Core                        │
├─────────────────────────────────────────────────────────────┤
│  Memory Limit: < 5MB    Privacy Level: Configurable        │
│  Runtime: Rust/WASM     Compliance: Auto-regional          │
└─────────────────────────────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  Monitor   │ │  Analyzer   │ │  Reporter   │
│   Layer    │ │   Layer     │ │   Layer     │
└─────────────┘ └─────────────┘ └─────────────┘
        │           │           │
        ▼           ▼           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Threat Intelligence Fabric                │
│              P2P Network + Multi-Chain                      │
└─────────────────────────────────────────────────────────────┘
```

## 核心模块

### 1. 监控层（Monitor Layer）

#### 1.1 网络流监控（netflow）
- **技术**: eBPF (Linux) / ETW (Windows) / EndpointSecurity (macOS)
- **功能**: 实时监控网络流量模式，提取威胁特征
- **资源**: CPU < 2%, Memory < 1MB

#### 1.2 系统调用监控（syscall）
- **技术**: 系统调用拦截、行为分析
- **功能**: 检测异常进程行为和潜在威胁
- **资源**: CPU < 1%, Memory < 0.5MB

#### 1.3 TLS检查（tls-inspect）
- **功能**: 提取SNI/证书指纹，不破解内容
- **隐私**: 仅提取元数据，保护用户隐私
- **资源**: CPU < 1%, Memory < 0.5MB

#### 1.4 地理围栏（geo-fence）
- **技术**: MaxMind DB 本地IP地理定位
- **功能**: 基于地理位置的风险评估
- **资源**: CPU < 0.5%, Memory < 0.5MB

### 2. 分析层（Analyzer Layer）

#### 2.1 威胁检测引擎
- **算法**: 机器学习模型 + 规则引擎
- **功能**: 本地威胁识别和分类
- **隐私**: 所有分析本地完成，不上传原始数据

#### 2.2 行为分析器
- **功能**: 用户和进程行为基线建立
- **技术**: 异常检测算法
- **隐私**: 基线数据本地存储加密

### 3. 报告层（Reporter Layer）

#### 3.1 证据收集器
- **功能**: 威胁证据提取和哈希计算
- **技术**: Blake3 + 国密SM3
- **隐私**: 证据脱敏和加密

#### 3.2 P2P客户端
- **技术**: libp2p gossipsub
- **功能**: 与威胁情报协调网络通信
- **合规**: 自动区域合规处理

## 配置选项

### 隐私级别
- **Level 1 (GDPR)**: IP匿名化至 /24
- **Level 2 (CCPA)**: IP匿名化至 /16
- **Level 3 (China)**: 保留完整IP，符合等保要求
- **Level 4 (Global)**: 默认匿名化至 /16

### 性能配置
- **内存限制**: 默认 5MB，可配置范围 2MB-10MB
- **CPU限制**: 默认 5%，可配置范围 1%-20%
- **网络限制**: 默认 10KB/s，可配置范围 1KB/s-100KB/s

## 合规引擎

### 自动区域合规
- **中国**: 使用国密算法，数据存长安链，日志保留180天
- **欧盟**: GDPR合规，支持数据删除API
- **美国**: CCPA合规，支持"Do Not Sell"
- **全球**: ISO 27001审计日志

## 安全特性

### 代码完整性
- **签名验证**: Agent二进制文件数字签名
- **运行时检查**: 内存完整性验证
- **自我保护**: 防止恶意篡改

### 通信加密
- **传输层**: TLS 1.3 + 国密SM2
- **数据层**: AES-256-GCM + 国密SM4
- **身份验证**: 基于声誉的访问控制

## 部署模式

### 个人/开发者
```bash
curl -sSf https://orasrs.global/install.sh | sh
```

### 企业内网
```yaml
# Kubernetes DaemonSet
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: orasrs-agent
spec:
  template:
    spec:
      containers:
      - name: agent
        image: orasrs/agent:latest
        resources:
          limits:
            memory: "5Mi"
            cpu: "100m"
```

### IoT设备
- **语言**: C语言微型实现
- **内存**: < 1MB
- **功能**: 基础威胁检测，通过网关上报

## API接口

### 本地管理API
```
GET /api/v2/agent/status          # Agent状态
GET /api/v2/agent/config          # 当前配置
POST /api/v2/agent/config         # 更新配置
GET /api/v2/agent/threats         # 本地威胁列表
POST /api/v2/agent/compliance     # 合规状态
```

### 威胁情报API
```
POST /api/v2/threats/submit       # 提交威胁证据
GET /api/v2/threats/query         # 查询威胁情报
POST /api/v2/threats/verify       # P2P威胁验证
```

## 故障恢复机制

### 自我修复
- **进程监控**: 自动重启失败模块
- **配置恢复**: 从备份恢复损坏配置
- **网络重连**: 自动重连P2P网络

### 降级模式
- **离线模式**: 本地威胁检测，不上传数据
- **最小模式**: 仅运行核心监控模块
- **只读模式**: 仅接收威胁情报，不主动上报
```