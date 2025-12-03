# OraSRS Agent 使用指南

## 概述

OraSRS Agent 是 OraSRS v2.0 协调防御框架的边缘层组件，是一个超轻量级的威胁检测和响应代理，资源占用 < 5MB，部署在终端设备和网络边缘。

## 安装

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/srs-protocol/orasrs-agent.git
cd orasrs-agent

# 构建发布版本
cargo build --release

# 运行代理
./target/release/orasrs-agent
```

### 使用预构建二进制文件

```bash
# 下载预构建的二进制文件
curl -L https://orasrs.global/downloads/agent-v2.0.0-linux-amd64.tar.gz -o agent.tar.gz
tar -xzf agent.tar.gz
./orasrs-agent
```

## 配置

### 默认配置

OraSRS Agent 使用以下默认配置：

```toml
[agent]
agent_id = "auto-generated-uuid"
region = "auto"  # 自动检测部署区域
privacy_level = 2  # GDPR级别 (1-4)
compliance_mode = "global"  # 合规模式
max_memory = 5242880  # 5MB
cpu_limit = 5.0  # 5% CPU使用率限制
network_limit = 10240  # 10KB/s网络限制

[modules]
netflow = true
syscall = true
tls_inspect = true
geo_fence = true

[p2p]
bootstrap_nodes = [
  "/ip4/159.138.224.180/tcp/4001/p2p/...",
  "/ip4/159.138.224.181/tcp/4001/p2p/..."
]
listen_port = 4001
max_connections = 50
reconnect_interval = 30

[crypto]
use_sm_crypto = false
encryption_algorithm = "aes256"

[storage]
data_dir = "./data"
max_log_size = 10485760  # 10MB
retention_days = 30
encryption_enabled = true
```

### 配置文件示例

创建 `config.toml` 文件：

```toml
[agent]
agent_id = "my-agent-001"
region = "CN"
privacy_level = 3  # 中国模式，保留完整IP
compliance_mode = "china"
max_memory = 3145728  # 3MB
cpu_limit = 3.0
network_limit = 5120  # 5KB/s

[modules]
netflow = true
syscall = false  # 禁用系统调用监控
tls_inspect = true
geo_fence = true
```

## 部署模式

### 个人/开发者模式

```bash
# 快速安装
curl -sSf https://orasrs.global/install.sh | sh

# 后台运行
orasrs-agent &
```

### 企业内网部署 (Kubernetes)

```yaml
# orasrs-agent-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: orasrs-agent
  namespace: security
spec:
  selector:
    matchLabels:
      app: orasrs-agent
  template:
    metadata:
      labels:
        app: orasrs-agent
    spec:
      hostNetwork: true  # 需要网络监控权限
      containers:
      - name: agent
        image: orasrs/agent:2.0.0
        imagePullPolicy: Always
        resources:
          limits:
            memory: "5Mi"
            cpu: "100m"
        env:
        - name: ORASRS_AGENT_REGION
          value: "CN"
        - name: ORASRS_AGENT_COMPLIANCE
          value: "china"
        securityContext:
          privileged: true  # 需要系统监控权限
        volumeMounts:
        - name: data
          mountPath: /data
      volumes:
      - name: data
        hostPath:
          path: /var/lib/orasrs-agent
          type: DirectoryOrCreate
---
apiVersion: v1
kind: Service
metadata:
  name: orasrs-agent-service
  namespace: security
spec:
  selector:
    app: orasrs-agent
  ports:
  - port: 8080
    targetPort: 8080
    name: management
```

### IoT设备部署

对于资源受限的IoT设备，可使用C语言的微型实现：

```c
// orasrs-agent-micro.c (概念示例)
#include "orasrs_micro.h"

int main() {
    // 初始化微型代理
    orasrs_config_t config = {
        .memory_limit = 1024 * 1024,  // 1MB
        .privacy_level = PRIVACY_LEVEL_2,
        .compliance_mode = COMPLIANCE_GLOBAL
    };
    
    orasrs_agent_init(&config);
    
    // 启动基本威胁监控
    orasrs_start_monitoring();
    
    while(1) {
        // 检查威胁
        if (orasrs_check_threats()) {
            orasrs_report_threat();
        }
        
        sleep(30);  // 每30秒检查一次
    }
    
    return 0;
}
```

## API接口

### 管理API

```bash
# 获取代理状态
curl http://localhost:8080/api/v2/agent/status

# 获取当前配置
curl http://localhost:8080/api/v2/agent/config

# 更新配置
curl -X POST http://localhost:8080/api/v2/agent/config \
  -H "Content-Type: application/json" \
  -d '{"privacy_level": 1, "compliance_mode": "gdpr"}'

# 获取本地威胁列表
curl http://localhost:8080/api/v2/agent/threats

# 获取合规状态
curl http://localhost:8080/api/v2/agent/compliance
```

### 威胁情报API

```bash
# 提交威胁证据
curl -X POST http://localhost:8080/api/v2/threats/submit \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "target_ip": "10.0.0.5",
    "threat_type": "ddos",
    "threat_level": 2,
    "context": "SYN flood attack detected",
    "geolocation": "Shanghai, China"
  }'

# 查询威胁情报
curl "http://localhost:8080/api/v2/threats/query?ip=192.168.1.100"

# 请求P2P验证
curl -X POST http://localhost:8080/api/v2/threats/verify \
  -H "Content-Type: application/json" \
  -d '{"evidence_id": "threat-12345"}'
```

## 合规特性

### 自动区域合规

- **中国**: 使用国密算法，数据存储在长安链，日志保留180天
- **欧盟**: GDPR合规，IP匿名化至/24，支持数据删除API
- **美国**: CCPA合规，支持"Do Not Sell"请求
- **全球**: 默认符合ISO 27001标准

### 隐私保护

- **数据最小化**: 仅收集威胁检测必需的数据
- **本地处理**: 敏感数据分析在本地完成
- **IP匿名化**: 根据区域合规要求匿名化IP地址
- **加密传输**: 所有通信使用TLS 1.3和国密SM2

## 监控模块

### 网络流监控 (netflow)

- 使用eBPF技术监控网络流量
- 检测异常流量模式
- 资源占用: < 2% CPU, < 1MB内存

### 系统调用监控 (syscall)

- 监控进程行为
- 检测异常系统调用
- 资源占用: < 1% CPU, < 0.5MB内存

### TLS检查 (tls-inspect)

- 提取SNI和证书指纹
- 不解密HTTPS流量内容
- 保护用户隐私

### 地理围栏 (geo-fence)

- 基于MaxMind DB的IP地理定位
- 检测来自高风险地区的连接
- 支持自定义风险地区列表

## 故障恢复

### 自我修复

- 进程监控和自动重启
- 配置损坏时从备份恢复
- 网络断线时自动重连

### 降级模式

- **离线模式**: 本地威胁检测，不上传数据
- **最小模式**: 仅运行核心监控模块
- **只读模式**: 仅接收威胁情报，不主动上报

## 性能指标

- **内存占用**: < 5MB (可配置2-10MB)
- **CPU使用率**: < 5% (可配置1-20%)
- **网络使用率**: < 10KB/s (可配置1KB-100KB/s)
- **检测延迟**: < 50ms
- **P2P连接**: < 50个并发连接

## 安全特性

- **代码完整性**: 二进制文件数字签名验证
- **通信加密**: TLS 1.3 + 国密SM2
- **数据加密**: AES-256-GCM + 国密SM4
- **访问控制**: 基于声誉的P2P网络访问控制
- **防篡改**: 运行时完整性检查

## 故障排除

### 常见问题

1. **代理无法启动**:
   - 检查系统权限（某些监控功能需要特权）
   - 确认网络连接

2. **P2P网络连接问题**:
   - 检查防火墙设置
   - 确认代理节点地址正确

3. **高资源使用率**:
   - 调整配置中的资源限制
   - 禁用不必要的监控模块

### 日志分析

```bash
# 查看实时日志
tail -f /var/log/orasrs-agent.log

# 查看错误日志
grep ERROR /var/log/orasrs-agent.log

# 查看性能指标
grep "memory_usage\|cpu_usage" /var/log/orasrs-agent.log
```

## 升级指南

### 从v1.x升级到v2.0

OraSRS Agent v2.0是完全重写的版本，不再使用质押机制，而是采用基于行为的声誉系统。升级时需要：

1. 停止旧版本代理
2. 清理旧配置（可选）
3. 安装新版本
4. 根据新配置格式更新配置文件

## 支持

- **文档**: https://orasrs.global/docs
- **社区**: https://orasrs.global/community
- **问题追踪**: https://github.com/srs-protocol/orasrs-agent/issues
- **安全报告**: security@orasrs.global
```