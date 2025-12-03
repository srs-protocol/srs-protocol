# OraSRS v2.0 — 全球轻量级主动防御协调框架
# OraSRS v2.0 — Global Lightweight Proactive Defense Coordination Framework

## 使命 / Mission
让每一次网络攻击在扩散前被群体免疫系统识别、阻断、存证。
Let the collective immune system identify, block, and evidence every cyber attack before it spreads.

## 核心价值主张 / Core Value Proposition
**"全球网络的第一道主动防御防线"**
**"The First Line of Active Defense for Global Networks"**

---

## 一、整体架构（三层去中心化设计）
## I. Overall Architecture (Three-Tier Decentralized Design)

### 🏗️ 三层架构 / Three-Tier Architecture

#### 1. Edge Layer（边缘层）：超轻量智能代理
#### 1. Edge Layer: Ultra-Lightweight Intelligent Agent
- **体积 / Size**: < 5MB RAM，静态编译，无外部依赖 / Static compilation, no external dependencies
- **语言 / Language**: Rust（内存安全 + 零成本抽象）/ Rust (memory safe + zero-cost abstraction)
- **功能 / Function**: 实时威胁检测与本地响应 / Real-time threat detection and local response

#### 2. Consensus Layer（共识层）：多链可信存证
#### 2. Consensus Layer: Multi-Chain Trusted Evidence Storage
- **区域化部署 / Regional Deployment**: 自动匹配合规要求 / Automatic compliance matching
- **加密标准 / Encryption Standards**: 国密 + 国际标准 / Chinese + International Standards
- **功能 / Function**: 威胁证据链上存证与验证 / On-chain evidence storage and verification

#### 3. Intelligence Fabric（智能层）：威胁情报协调网络
#### 3. Intelligence Fabric: Threat Intelligence Coordination Network
- **生态接入 / Ecosystem Integration**: 与主流安全系统协同 / Coordination with mainstream security systems
- **P2P 验证 / P2P Verification**: 去中心化威胁确认 / Decentralized threat confirmation
- **输出驱动 / Output Drive**: 驱动现有防御体系 / Drive existing defense systems

✅ 无中心服务器 / No Central Servers  
✅ 自动区域合规 / Automatic Regional Compliance  
✅ 秒级全球同步 / Second-Level Global Synchronization

---

## 二、核心组件详解
## II. Core Components Detailed

### 1. Edge Layer：超轻量智能代理（Agent）
### 1. Edge Layer: Ultra-Lightweight Intelligent Agent

**语言 / Language**: Rust（内存安全 + 零成本抽象）/ Rust (memory safe + zero-cost abstraction)  
**体积 / Size**: < 5MB RAM，静态编译，无外部依赖 / Static compilation, no external dependencies

#### 功能模块（可插拔）/ Functional Modules (Pluggable):
- **netflow**: 基于 eBPF 的网络流监控（Linux）/ Network flow monitoring based on eBPF (Linux)
- **syscall**: 进程行为审计（Windows ETW / macOS EndpointSecurity）/ Process behavior auditing (Windows ETW / macOS EndpointSecurity)
- **tls-inspect**: 提取 SNI/证书指纹，不破解内容 / Extract SNI/certificate fingerprints without breaking content
- **geo-fence**: 基于 MaxMind DB 的 IP 地理围栏 / IP geofencing based on MaxMind DB

#### 隐私保护 / Privacy Protection:
- 默认匿名化 IP（GDPR：/24；中国：保留完整）/ Default IP anonymization (GDPR: /24; China: full retention)
- 用户可完全关闭数据上报 / Users can completely disable data reporting
- 所有配置本地加密存储 / All configurations stored locally encrypted

### 2. Consensus Layer：多链可信存证层
### 2. Consensus Layer: Multi-Chain Trusted Evidence Storage Layer

| 区域 / Region | 链 / Chain | 加密 / Encryption | 用途 / Purpose |
|---------------|------------|-------------------|----------------|
| 中国 / China | 长安链 v2.3+ | SM2/SM3/SM4 | 政务/金融场景，满足等保2.0 / Government/financial scenes, compliance with Cybersecurity Protection Level 2.0 |
| 全球 / Global | Polygon PoS | Ed25519 + BLAKE3 | 公共威胁存证，低成本 / Public threat evidence, low cost |
| 存储 / Storage | IPFS + Filecoin | AES-256-GCM | 威胁日志加密分片存储 / Threat log encrypted sharding storage |

**上链内容（极简）/ On-Chain Content (Minimal)**:
```json
{
  "attestation_hash": "blake3(netflow + timestamp)",
  "source_reputation": 0.92,
  "geo_region": "EU",
  "compliance_tag": "gdpr_v2.1"
}
```

**不上链**: 原始流量、用户身份、设备信息  
**Off-chain**: Raw traffic, user identity, device information

### 3. Intelligence Fabric：威胁情报协调网络
### 3. Intelligence Fabric: Threat Intelligence Coordination Network

#### （1）输入：接入主流生态（只读）
#### (1) Input: Access Mainstream Ecosystems (Read-Only)
- **CISA AIS（TAXII 2.0）** → 权威政府情报 / Authoritative government intelligence
- **VirusTotal API** → 社区提交 IOC / Community-submitted IOC
- **MISP 实例** → 企业私有情报聚合 / Enterprise private intelligence aggregation
- **AlienVault OTX** → 开源 Pulse 订阅 / Open-source Pulse subscription

#### （2）处理：P2P 共识验证
#### (2) Processing: P2P Consensus Verification
- Agent 通过 libp2p gossipsub 广播可疑事件 / Agent broadcasts suspicious events via libp2p gossipsub
- ≥3 个独立地理位置节点确认 → 触发全局响应 / ≥3 independent geographic location nodes confirm → trigger global response
- 声誉系统动态评分 / Dynamic reputation scoring system

```
新声誉 = 旧声誉 × 0.9 + 准确率 × 0.1
New Reputation = Old Reputation × 0.9 + Accuracy × 0.1
```

#### （3）输出：驱动现有防御体系
#### (3) Output: Drive Existing Defense Systems

| 下游系统 / Downstream System | 输出方式 / Output Method | 示例 / Example |
|-----------------------------|-------------------------|----------------|
| 防火墙 / Firewall | https://orasrs.global/blocklist.txt | `iptables -A INPUT -m set --match-set orasrs src -j DROP` |
| SIEM | Syslog (CEF 格式) | `cs2Label=orasrs_tx_id cs2=0xabc123...` |
| SOAR | REST API Webhook | `POST /soar/trigger { "threat_level": "CRITICAL", "tx_id": "..." }` |
| 云 WAF / Cloud WAF | AWS IP Set / Azure Firewall Rule | 自动更新恶意 IP 列表 / Automatically update malicious IP lists |

---

## 三、合规引擎（内置自适应）
## III. Compliance Engine (Built-in Adaptive)

| 部署区域 / Deployment Region | 自动启用策略 / Automatic Policy |
|-----------------------------|-------------------------------|
| 中国大陆 / Mainland China | - 国密 SM 系列加密 / Chinese SM encryption series<br>- 数据仅存长安链 / Data stored only on ChainMaker<br>- 日志留存 ≥180 天 / Log retention ≥180 days<br>- 禁用跨境同步 / Disable cross-border synchronization |
| 欧盟 / EU | - IP 匿名化至 /24 / IP anonymization to /24<br>- GDPR 删除 API / GDPR deletion API<br>- 合法基础：Legitimate Interest / Legal basis: Legitimate Interest<br>- DPIA 模板内置 / DPIA template built-in |
| 美国 / USA | - CCPA "Do Not Sell" 声明 / CCPA "Do Not Sell" statement<br>- HIPAA 模式（医疗设备检测） / HIPAA mode (medical device detection)<br>- 州法扩展支持 / State law extension support |
| 全球默认 / Global Default | - ISO 27001 审计日志 / ISO 27001 audit logs<br>- NIST CSF 对齐 / NIST CSF alignment |

🔐 所有合规操作生成 链上可验证记录，供监管审计。  
🔐 All compliance operations generate on-chain verifiable records for regulatory audit.

---

## 四、抗毁与应急响应机制
## IV. Resilience and Emergency Response Mechanisms

| 攻击场景 / Attack Scenario | 应对措施 / Countermeasures |
|---------------------------|--------------------------|
| Agent 被控 / Agent Compromised | - 代码完整性自检 / Code integrity self-check<br>- 声誉熔断（连续误报暂停权限） / Reputation circuit breaker (suspend permissions for continuous false positives)<br>- 多源交叉验证 / Multi-source cross-validation |
| 虚假威胁泛滥 / False Threat Flooding | - 启动"免疫抑制"模式 / Activate "immune suppression" mode<br>- 切换至仅信任 CISA/VirusTotal / Switch to trust only CISA/VirusTotal<br>- DAO 社区投票冻结异常源 / DAO community vote to freeze abnormal sources |
| 链上存证被质疑 / On-Chain Evidence Questioned | - 提供 Merkle Proof + 时间戳 / Provide Merkle Proof + timestamp<br>- 支持司法取证包导出 / Support forensic package export |
| P2P 网络分裂 / P2P Network Split | - 本地缓存最近 1000 条规则 / Local cache of most recent 1000 rules<br>- 离线模式持续防御 / Offline mode continuous defense |

---

## 五、部署模式
## V. Deployment Modes

| 场景 / Scenario | 方案 / Solution |
|----------------|----------------|
| 个人/开发者 / Individual/Developer | `curl -sSf https://orasrs.global/install.sh` |
| 企业内网 / Enterprise Intranet | Helm Chart 部署 K8s DaemonSet + 私有长安链 / Helm Chart deploy K8s DaemonSet + Private ChainMaker |
| IoT 设备 / IoT Devices | C 语言微型 Agent（<1MB），通过网关聚合上报 / C language micro Agent (<1MB), aggregate reporting through gateway |
| 云原生 / Cloud Native | AWS Lambda / Azure Function 作为边缘节点 / AWS Lambda / Azure Function as edge nodes |

---

## 六、路线图（2025–2026）
## VI. Roadmap (2025–2026)

| 时间 / Time | 里程碑 / Milestone |
|------------|-------------------|
| 2025 Q2 | 开源 Agent 核心 + 长安链/Polygon 双链支持 / Open source Agent core + ChainMaker/Polygon dual-chain support |
| 2025 Q3 | 发布 Splunk/XSOAR 插件 + GDPR 合规模板 / Release Splunk/XSOAR plugins + GDPR compliance templates |
| 2025 Q4 | 启动 OraSRS DAO，社区治理声誉算法 / Launch OraSRS DAO, community governance reputation algorithm |
| 2026 Q1 | 集成 CISA AIS + VirusTotal 官方合作 / Integrate CISA AIS + VirusTotal official partnership |
| 2026 Q2 | 支持 FIDO2 安全启动，硬件级完整性验证 / Support FIDO2 secure boot, hardware-level integrity verification |

---

## 七、为什么 OraSRS v2.0 是"第一防线"？
## VII. Why OraSRS v2.0 is the "First Line of Defense"?

- **前置 / Pre-positioned**: 部署在终端/边缘，早于传统防火墙 / Deployed at terminal/edge, earlier than traditional firewalls
- **轻量 / Lightweight**: 资源消耗 < EDR 的 10%，适合 IoT/移动设备 / Resource consumption < 10% of EDR, suitable for IoT/mobile devices
- **协同 / Collaborative**: 单点发现 = 全球防御（群体免疫） / Single point discovery = Global defense (herd immunity)
- **可信 / Trustworthy**: 所有威胁有链上存证，可司法举证 / All threats have on-chain evidence, judicially admissible
- **合规 / Compliant**: 开箱即用满足全球主要法规 / Out-of-box compliance with global regulations

> OraSRS v2.0 不是另一个安全产品，而是现有安全生态的"免疫增强剂"。  
> OraSRS v2.0 is not another security product, but an "immune enhancer" for the existing security ecosystem.

---

## 八、技术架构详述
## VIII. Technical Architecture Details

### 8.1 Agent 架构（Rust 实现）
### 8.1 Agent Architecture (Rust Implementation)

```rust
// Agent 核心模块 / Agent Core Modules
pub struct OrasrsAgent {
    pub config: AgentConfig,
    pub network_monitor: NetworkMonitor,
    pub behavior_analyzer: BehaviorAnalyzer,
    pub threat_detector: ThreatDetector,
    pub evidence_collector: EvidenceCollector,
    pub p2p_client: P2pClient,
    pub compliance_engine: ComplianceEngine,
}

pub struct AgentConfig {
    pub region: String,           // 部署区域 / Deployment region
    pub compliance_mode: String,  // 合规模式 / Compliance mode
    pub memory_limit: usize,      // 内存限制 / Memory limit
    pub privacy_level: u8,        // 隐私级别 / Privacy level
    pub reputation: f64,          // 声誉分数 / Reputation score
}
```

### 8.2 存证合约（多链支持）
### 8.2 Evidence Contract (Multi-Chain Support)

```go
// 多链存证合约 / Multi-chain Evidence Contract
type ThreatAttestation struct {
    ID            string      `json:"id"`
    Timestamp     int64       `json:"timestamp"`
    SourceIP      string      `json:"source_ip"`
    TargetIP      string      `json:"target_ip"`
    ThreatType    string      `json:"threat_type"`
    ThreatLevel   ThreatLevel `json:"threat_level"`
    Context       string      `json:"context"`
    AgentID       string      `json:"agent_id"`
    EvidenceHash  string      `json:"evidence_hash"`
    Geolocation   string      `json:"geolocation"`
    NetworkFlow   string      `json:"network_flow"`
    ComplianceTag string      `json:"compliance_tag"`
    Region        string      `json:"region"`
}

type ThreatLevel int
const (
    Info ThreatLevel = iota
    Warning
    Critical
    Emergency
)
```

### 8.3 P2P 协调网络
### 8.3 P2P Coordination Network

```go
// P2P 威胁协调 / P2P Threat Coordination
type ThreatCoordination struct {
    pubsub: PubSub,           // GossipSub 广播 / GossipSub broadcast
    reputation_system: ReputationSystem,  // 声誉系统 / Reputation system
    evidence_verifier: EvidenceVerifier,  // 证据验证 / Evidence verification
    compliance_checker: ComplianceChecker, // 合规检查 / Compliance check
}

// 威胁广播消息 / Threat broadcast message
type ThreatBroadcast struct {
    attestation: ThreatAttestation,
    signature: String,         // 节点签名 / Node signature
    timestamp: i64,            // 时间戳 / Timestamp
    geo_location: String,      // 地理位置 / Geographic location
}
```

---

## 九、安全与隐私设计
## IX. Security and Privacy Design

### 9.1 隐私优先原则
### 9.1 Privacy-First Principles
- **数据最小化**: 仅收集威胁检测必需信息 / Data minimization: Only collect information necessary for threat detection
- **本地处理**: 敏感数据本地分析，不上报 / Local processing: Sensitive data analyzed locally, not reported
- **可删除性**: 支持数据完全删除 / Deletability: Support complete data deletion
- **匿名化**: 自动 IP 匿名化 / Anonymization: Automatic IP anonymization

### 9.2 安全保障机制
### 9.2 Security Assurance Mechanisms
- **代码完整性**: Agent 自我完整性检查 / Code integrity: Agent self-integrity check
- **运行时保护**: 防止 Agent 被篡改 / Runtime protection: Prevent Agent tampering
- **通信加密**: 所有通信端到端加密 / Communication encryption: End-to-end encryption for all communications
- **访问控制**: 基于声誉的访问控制 / Access control: Reputation-based access control

---

## 十、生态系统集成
## X. Ecosystem Integration

### 10.1 与现有安全栈协同
### 10.1 Coordination with Existing Security Stack

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   OraSRS v2.0   │◄──►│  Existing Stack  │◄──►│  Business Apps  │
│   (First Line)  │    │   (Second Line)  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Threat Intel   │    │   Firewalls,     │    │    Protected    │
│   Sharing &     │    │   EDR, SIEM,     │    │   Applications  │
│   Verification  │    │   WAF, etc.      │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### 10.2 API 接口规范
### 10.2 API Interface Specification

```yaml
# REST API 接口 / REST API Interfaces
ThreatSubmissionAPI:
  endpoint: /api/v2/threats/submit
  method: POST
  auth: Reputation-based + Signature
  rate_limit: 1000/minute per agent

ThreatQueryAPI:
  endpoint: /api/v2/threats/query
  method: GET
  auth: API Key + Compliance Check
  response: Minimal threat indicators

ComplianceAPI:
  endpoint: /api/v2/compliance/verify
  method: POST
  auth: Regulator credentials
  response: Audit trail + Evidence
```

OraSRS v2.0 代表了网络安全范式的转变：从被动防御到主动免疫，从中心化控制到分布式协作，从合规负担到合规赋能。通过这一框架，我们正在构建真正全球可用、本地合规、抗毁可信的网络防御基础设施。