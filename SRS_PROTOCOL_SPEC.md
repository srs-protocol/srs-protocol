# OraSRS (Oracle Security Root Service) 协议规范

## 概述 / Overview

OraSRS (Oracle Security Root Service) 是一个咨询式风险评分服务，旨在为互联网安全决策提供权威参考。与传统的阻断式防火墙不同，OraSRS 提供风险评估和建议，由客户端自主决定是否执行相应措施。
OraSRS (Oracle Security Root Service) is a consultative risk scoring service designed to provide authoritative references for internet security decisions. Unlike traditional blocking firewalls, OraSRS provides risk assessments and recommendations, allowing clients to decide whether to execute corresponding measures.

### OraSRS v2.0: 威胁情报升级 / OraSRS v2.0: Threat Intelligence Upgrade

OraSRS v2.0 introduces a major enhancement to the protocol with threat intelligence capabilities, moving beyond traditional firewall/WAF systems to create a distributed network of threat sensors that can detect, verify, and share threat intelligence in real-time across a blockchain network.

OraSRS v2.0 通过威胁情报功能对协议进行重大增强，超越传统的防火墙/WAF 系统，创建一个威胁传感器的分布式网络，能够在区块链网络上实时检测、验证和共享威胁情报。

#### Key Innovations in v2.0 / v2.0的主要创新

1. **Three-Layer Architecture (三层架构)**:
   - **Edge Layer (边缘层)**: Lightweight 5MB agent nodes deployed at network edges for real-time threat detection
   - **Consensus Layer (共识层)**: Verification and consensus nodes ensuring threat intelligence accuracy
   - **Intelligence Layer (智能层)**: Advanced analysis and threat intelligence correlation
   - **边缘层**: 5MB轻量级代理节点，部署在网络边缘进行实时威胁检测
   - **共识层**: 验证和共识节点，确保威胁情报准确性
   - **智能层**: 高级分析和威胁情报关联

2. **Threat Attestation and Verification (威胁证明和验证)**:
   - Immutable threat evidence storage on blockchain
   - Cross-validation between multiple nodes
   - Reputation-based verification scoring
   - 不可变的区块链威胁证据存储
   - 多节点交叉验证
   - 基于声誉的验证评分

3. **Real-time Global Threat Synchronization (实时全球威胁同步)**:
   - Instant threat intelligence sharing across global nodes
   - Decentralized threat evidence storage
   - Immutable on-chain evidence of attacks
   - 全球节点间的即时威胁情报共享
   - 去中心化的威胁证据存储
   - 不可篡改的链上攻击证据

4. **Compliance Standards (合规标准)**:
   - GDPR/CCPA compliance
   - ISO27001 compliance
   - China Cybersecurity Law (等保2.0) compliance
   - GDPR/CCPA合规
   - ISO27001合规
   - 中国网络安全法(等保2.0)合规

## 设计原则 / Design Principles

### 1. 咨询式服务模式 / Advisory Service Model
- **错误设计 / Incorrect Design**: OraSRS 返回 `{ action: "BLOCK" }`
- **正确设计 / Correct Design**: OraSRS 返回 `{ risk_score: 0.92, evidence: ["ddos_bot", "scan_24h"] }`
- **客户端强制执行** → **客户端自主决策是否拦截**
- **Client forced execution** → **Client autonomous decision to intercept or not**

> 类比：OraSRS 是信用评分机构（如 FICO），不是法院。客户端（如银行）自己决定是否采取行动。
> Analogy: OraSRS is a credit rating agency (like FICO), not a court. The client (like a bank) decides whether to take action.

### 2. 威胁情报增强设计 / Threat Intelligence Enhanced Design

#### (1) 主动威胁感知 / Active Threat Perception
- **OraSRS v1.0**: 被动接收威胁情报 / Passive threat intelligence reception
- **OraSRS v2.0**: 主动威胁检测与报告 / Active threat detection and reporting
- **实现方法 / Implementation Method**:
```json
{
  "threat_report": {
    "id": "threat_192.168.1.10_1701234567",
    "timestamp": 1701234567,
    "source_ip": "192.168.1.10",
    "target_ip": "10.0.0.5",
    "threat_type": "ddos_attack",
    "threat_level": "critical",
    "context": "SYN flood attack detected",
    "agent_id": "edge_agent_001",
    "evidence_hash": "a1b2c3d4e5f6...",
    "geolocation": "Shanghai, China",
    "network_flow": "source_port: 1024-65535, dest_port: 80"
  }
}
```

#### (2) 威胁验证机制 / Threat Verification Mechanism
- **多节点交叉验证 / Multi-node cross-validation**: 至少3个独立节点验证威胁报告 / At least 3 independent nodes verify threat reports
- **声誉系统评分 / Reputation-based scoring**: 高声誉节点的验证权重更高 / Higher weight for high-reputation nodes
- **链上证据存储 / On-chain evidence storage**: 所有威胁证据永久存储 / All threat evidence permanently stored

#### (3) 实时威胁同步 / Real-time Threat Synchronization
- **秒级更新 / Second-level updates**: 全球节点实时同步威胁情报 / Real-time threat intelligence synchronization across global nodes
- **自动阻断建议 / Automatic blocking recommendations**: 高威胁等级自动通知相关节点 / High threat level automatically notifies related nodes
- **智能缓存机制 / Intelligent caching mechanism**: 频繁威胁本地缓存，减少查询延迟 / Frequent threats cached locally to reduce query latency

### 3. 内置多重保护机制 / Built-in Multi-layer Protection Mechanisms

#### (1) 分级响应策略 / Tiered Response Strategy
```json
{
  "ip": "1.2.3.4",
  "risk_level": "medium",
  "threat_level": "warning",  // OraSRS v2.0 新增 / OraSRS v2.0 new addition
  "recommendations": {
    "public_services": "allow_with_captcha",
    "banking": "require_mfa",
    "admin_panel": "block",
    "threat_intel": {
      "is_threat_sensor": true,  // 是否为威胁传感器 / Whether it's a threat sensor
      "agent_version": "2.0.1",  // Agent版本 / Agent version
      "deployment_type": "edge", // 部署类型 / Deployment type: edge/consensus/intelligence
      "last_threat_report": 1701234567  // 最后威胁报告时间 / Last threat report time
    }
  }
}
```
- 不对所有服务一刀切 / Not a one-size-fits-all approach for all services
- 关键服务（如医疗、政府）默认放行 / Critical services (such as medical, government) are allowed by default

### 2. 内置多重保护机制

#### (1) 分级响应策略
```json
{
  "ip": "1.2.3.4",
  "risk_level": "medium",
  "recommendations": {
    "public_services": "allow_with_captcha",
    "banking": "require_mfa",
    "admin_panel": "block"
  }
}
```
- 不对所有服务一刀切
- 关键服务（如医疗、政府）默认放行

#### (2) 自动衰减与申诉通道 / Automatic Decay and Appeal Channel
- 风险分随时间衰减（如 24 小时后降级）
- 威胁情报自动更新与衰减（OraSRS v2.0新增）/ Threat intelligence automatic update and decay (new in OraSRS v2.0)
- 提供公开申诉接口：
```
POST /orasrs/v1/appeal
{ "ip": "1.2.3.4", "proof": "we_fixed_the_botnet" }

# OraSRS v2.0 威胁情报申诉接口 / OraSRS v2.0 Threat Intelligence Appeal Interface
POST /orasrs/v2/threat-appeal
{ 
  "report_id": "threat_192.168.1.10_1701234567", 
  "proof": "evidence_of_false_positive", 
  "verdict": "confirm/dispute" 
}
```

#### (3) 透明化与可审计 / Transparency and Auditability
- 所有标记记录上链（或公开日志）
- 威胁情报完全透明（OraSRS v2.0新增）/ Full threat intelligence transparency (new in OraSRS v2.0)
- 提供 `GET /orasrs/v1/explain?ip=1.2.3.4` 返回决策依据
- OraSRS v2.0 提供 `GET /orasrs/v2/threat-intel/{report_id}` 返回威胁报告详情 / OraSRS v2.0 provides `GET /orasrs/v2/threat-intel/{report_id}` to return threat report details

### 3. 公共服务豁免原则

在 OraSRS 策略中硬编码关键公共服务白名单，永不拦截：

| 服务类型 | 示例域名/IP |
|---------|------------|
| 政府 | .gov, .mil, 国家税务/社保 IP 段 |
| 医疗 | 医院官网、急救系统 |
| 金融基础设施 | SWIFT、央行支付系统 |
| 基础通信 | DNS 根服务器、NTP 池 |

## 增强型共识与质押机制

### 三层去中心化架构 / Three-Tier Decentralized Architecture

#### 边缘层（超轻量智能代理） / Edge Layer (Ultra-Lightweight Intelligent Agent)
- **技术栈**: Rust语言，<5MB内存占用
- **功能**: 实时威胁检测、本地响应、隐私保护
- **部署**: 终端设备、网络边缘、IoT设备
- **威胁情报功能** (OraSRS v2.0): 
  - 5MB轻量级威胁检测代理 / 5MB lightweight threat detection agent
  - 实时威胁检测与本地响应 / Real-time threat detection and local response
  - 隐私优先数据处理 / Privacy-first data processing
  - 自动区域合规 / Automatic regional compliance

#### 共识层（多链可信存证） / Consensus Layer (Multi-chain Trusted Evidence Storage)
- **技术栈**: 多链架构（中国-长安链，全球-Polygon）
- **加密标准**: 国密SM2/SM3/SM4 + 国际Ed25519/BLAKE3
- **功能**: 威胁证据链上存证、跨区域验证、司法举证
- **威胁情报功能** (OraSRS v2.0):
  - 威胁报告链上存证 / On-chain threat report evidence
  - 多区域合规验证 / Multi-regional compliance verification
  - 不可篡改证据存储 / Immutable evidence storage

#### 智能层（威胁情报协调网络） / Intelligence Fabric (Threat Intelligence Coordination Network)
- **技术栈**: P2P网络（libp2p gossipsub）
- **功能**: 威胁情报聚合、P2P验证、生态协同
- **威胁情报功能** (OraSRS v2.0):
  - 主流安全生态接入 / Mainstream security ecosystem integration
  - P2P共识验证 / P2P consensus verification
  - 驱动现有防御体系 / Drive existing defense systems

### 身份与准入机制

#### 三层准入机制
| 准入层级 | 要求 | 实现方式 |
|---------|------|----------|
| L1：合规认证 | 企业营业执照 + 区块链服务备案号 | 对接国家网信办备案系统API |
| L2：技术认证 | 通过OraSRS Agent能力测试 | 自动化测试套件 + 人工复核 |
| L3：声誉准入 | 初始声誉评分 > 60 | 基于历史行为和社区推荐 |

#### 合规要求
- Agent运营方需完成企业实名认证 + 区块链备案（依据《区块链信息服务管理规定》第9条）
- 支持CA机构签发的数字证书（如CFCA）作为L2凭证，符合《电子签名法》
- 所有操作符合区域合规要求（GDPR/CCPA/等保2.0）

### 动态声誉系统

```python
# 伪代码：声誉评分 = 基础分 + 行为加权
def calculate_reputation(agent):
    base = 100
    # 检测准确率（权重 40%）
    accuracy_score = agent.detection_accuracy * 40
    # 响应时间（权重 20%）
    response_score = max(0, 20 - agent.avg_response_time_ms / 50)
    # 证据质量（权重 25%）
    evidence_score = agent.evidence_quality * 25
    # 合规遵循度（权重 15%）
    compliance_score = agent.compliance_adherence * 15
    
    return base + accuracy_score + response_score + evidence_score + compliance_score
```

#### 声誉应用规则
- 声誉 < 70：降低验证权限，仅可作基础监控节点
- 声誉 > 120：提升验证权限，可参与关键威胁验证
- 声誉连续7天 < 50：自动触发节点声誉审查流程

#### 治理对齐
- 声誉算法由技术指导委员会每季度审计，防止中心化操控

### P2P威胁验证机制
- **触发条件**: 威胁情报被3个独立地理位置节点质疑 或 威胁等级为Critical/Emergency
- **验证流程**: 通过libp2p gossipsub网络进行P2P交叉验证
- **共识机制**: ≥3个独立验证节点确认 → 触发全局威胁响应

## API 端点 / API Endpoints

### 风险查询 / Risk Query
```
GET /orasrs/v1/query?ip={ip}&domain={domain}
```

**请求示例 / Request Example**:
```
GET /orasrs/v1/query?ip=1.2.3.4
Accept: application/json
```

**响应格式 / Response Format**:
```json
{
  "query": { "ip": "1.2.3.4" },
  "response": {
    "risk_score": 0.85,
    "confidence": "high",
    "risk_level": "high",
    "evidence": [
      { 
        "type": "behavior", 
        "detail": "SYN flood to 10 targets in 1h",
        "source": "node-abc123",
        "timestamp": "2025-12-01T10:00:00Z"
      }
    ],
    "recommendations": {
      "default": "challenge",
      "critical_services": "allow"
    },
    "appeal_url": "https://srs.net/appeal?ip=1.2.3.4",
    "expires_at": "2025-12-02T10:00:00Z",
    "disclaimer": "This is advisory only. Final decision rests with the client."
  }
}
```

### OraSRS v2.0 威胁情报端点 / OraSRS v2.0 Threat Intelligence Endpoints

#### 提交威胁报告 / Submit Threat Report
```
POST /orasrs/v2/threat-report
```

**请求体 / Request Body**:
```json
{
  "source_ip": "192.168.1.10",
  "target_ip": "10.0.0.5",
  "threat_type": "ddos_attack",
  "threat_level": "critical",
  "context": "SYN flood attack detected",
  "evidence_hash": "a1b2c3d4e5f6...",
  "geolocation": "Shanghai, China",
  "network_flow": "source_port: 1024-65535, dest_port: 80"
}
```

#### 验证威胁报告 / Verify Threat Report
```
POST /orasrs/v2/threat-verify
```

**请求体 / Request Body**:
```json
{
  "report_id": "threat_192.168.1.10_1701234567",
  "verdict": "confirm/dispute",
  "evidence": "additional evidence for verification"
}
```

#### 获取威胁报告 / Get Threat Report
```
GET /orasrs/v2/threat-report/{report_id}
```

#### 获取全局威胁列表 / Get Global Threat List
```
GET /orasrs/v2/threat-list
```

**响应格式 / Response Format**:
```json
{
  "threat_list": [
    {
      "ip": "1.2.3.4",
      "threat_level": "critical",
      "first_seen": "2025-12-01T10:00:00Z",
      "last_seen": "2025-12-01T12:00:00Z",
      "report_count": 15,
      "evidence": [
        {
          "source": "node-abc123",
          "timestamp": "2025-12-01T10:00:00Z",
          "type": "behavior"
        }
      ]
    }
  ],
  "last_update": "2025-12-01T12:00:00Z",
  "total_threats": 125
}
```

### 批量查询
```
POST /orasrs/v1/bulk-query
```

### 快速查询
```
GET /orasrs/v1/lookup/{indicator}
```

### 申诉接口
```
POST /orasrs/v1/appeal
```

**请求体**:
```json
{
  "ip": "1.2.3.4",
  "proof": "explanation_of_legitimate_use"
}
```

### 透明化接口
```
GET /orasrs/v1/explain?ip={ip}
```

### 节点管理接口
```
POST /orasrs/v1/node/stake          # 节点质押
GET /orasrs/v1/node/status/{id}     # 获取节点状态
POST /orasrs/v1/node/challenge      # 提交节点挑战
GET /orasrs/v1/architecture/status  # 获取架构状态
```

### GDPR/CCPA数据删除
```
DELETE /orasrs/v1/data?ip_hash={hash}
```

## 法律与合规设计

### 1. 明确免责声明
在 API 响应头加入：
```
X-OraSRS-Disclaimer: This is advisory only. Final decision rests with the client.
```

### 2. 遵循 GDPR/CCPA
- 不存储原始 IP，只存哈希
- 提供 DELETE 接口

### 3. 社区治理
- 技术委员会 = 7席（3企业 + 2高校 + 2社区）
- 升级提案需 ≥5票通过
- 设立紧急熔断权（2/3委员可暂停协议）

### 4. 数据安全与国产化适配 / Data Security and Localization Adaptation
- 国密加密：SM4加密风险评估结果 / SM4 encryption for risk assessment results
- 威胁情报国产化：OraSRS v2.0威胁情报使用国密算法加密 / Threat intelligence localization: OraSRS v2.0 threat intelligence uses Chinese national cryptography for encryption
- 数据不出境：所有节点部署于中国大陆境内 / Data does not leave mainland China: All nodes deployed within mainland China
- 日志脱敏：IP地址哈希后存储（SHA3-256 + Salt）/ Log anonymization: IP addresses stored after hashing (SHA3-256 + Salt)
- 威胁证据国密化：威胁证据使用SM3哈希，SM2签名 / Threat evidence localization: Threat evidence uses SM3 hash, SM2 signature
- 支持长安链或FISCO BCOS，支持国密SM2/SM3 / Supports ChainMaker or FISCO BCOS, supports Chinese national cryptography SM2/SM3

## 实现特点

1. **去中心化**: 基于节点联邦学习的威胁情报 + 三层共识架构
2. **隐私优先**: 差分隐私保护，本地数据处理，IP地址脱敏
3. **开源可验证**: 完全开源，全球审计，国密算法支持
4. **标准兼容**: 支持STIX/TAXII、RPZ等开放标准
5. **安全激励**: 声誉系统、P2P验证、协同防御机制
6. **合规可信**: 企业认证、区块链备案、合规监管

## 集成指南

客户端应:

1. 查询OraSRS获取风险评分
2. 根据自身策略和OraSRS建议做出最终决策
3. 记录决策日志用于审计
4. 提供反馈以改进OraSRS模型
5. 遵守API速率限制，使用认证密钥

## 责任声明

OraSRS仅提供风险评估和建议，最终的安全决策由客户端做出。OraSRS不承担因客户端执行决策而导致的任何后果。

## 性能目标
- 边缘层P95响应时间 ≤ 15ms
- 支持 ≥ 50个共识节点
- TPS ≥ 1000（测试网）

## OraSRS v2.0 威胁情报协议规范

### 1. 威胁情报数据结构 / Threat Intelligence Data Structures
- **ThreatAttestation (威胁证明)**: 包含威胁的完整信息和证据 / Contains complete information and evidence of threats
  - ID: 威胁报告唯一标识符 / Unique identifier for threat report
  - Timestamp: 威胁检测时间戳 / Threat detection timestamp
  - SourceIP: 威胁源IP / Threat source IP
  - TargetIP: 威胁目标IP / Threat target IP
  - ThreatType: 威胁类型（如ddos_attack, malware, phishing等）/ Threat type (e.g., ddos_attack, malware, phishing, etc.)
  - ThreatLevel: 威胁等级（Info/Warning/Critical/Emergency）/ Threat level (Info/Warning/Critical/Emergency)
  - Context: 威胁上下文描述 / Threat context description
  - AgentID: 报告代理ID / Reporting agent ID
  - Signature: 威胁报告数字签名 / Threat report digital signature
  - EvidenceHash: 证据哈希值 / Evidence hash value
  - Geolocation: 地理位置信息 / Geographic location information
  - NetworkFlow: 网络流量模式 / Network traffic pattern

### 2. 威胁情报验证机制 / Threat Intelligence Verification Mechanism
- **多节点交叉验证**: 至少3个独立节点验证每个威胁报告 / Multi-node cross-validation: At least 3 independent nodes verify each threat report
- **声誉加权**: 基于行为的动态声誉评分 / Reputation weighting: Behavior-based dynamic reputation scoring
- **时间窗口验证**: 防止重复威胁报告 / Time window verification: Prevent duplicate threat reports
- **证据链验证**: 确保威胁证据完整性和真实性 / Evidence chain verification: Ensure integrity and authenticity of threat evidence

### 3. 威胁情报同步机制 / Threat Intelligence Synchronization Mechanism
- **实时同步**: 秒级威胁情报更新 / Real-time synchronization: Second-level threat intelligence updates
- **分层扩散**: 按三层架构分发威胁情报 / Hierarchical distribution: Distribute threat intelligence according to three-layer architecture
- **智能缓存**: 频繁威胁本地缓存，减少网络传输 / Intelligent caching: Cache frequent threats locally to reduce network transmission
- **自动衰减**: 威胁等级随时间和验证结果自动调整 / Automatic decay: Threat level automatically adjusts with time and verification results

### 4. 合规性与隐私保护 / Compliance and Privacy Protection
- **GDPR/CCPA合规**: 支持威胁数据的删除和修改请求 / GDPR/CCPA compliance: Support deletion and modification requests for threat data
- **等保2.0合规**: 符合中国网络安全等级保护要求 / Compliance with China Cybersecurity Protection Level 2.0 requirements
- **数据最小化**: 仅收集必要的威胁相关信息 / Data minimization: Only collect necessary threat-related information
- **透明化**: 所有威胁情报处理过程可审计和验证 / Transparency: All threat intelligence processing is auditable and verifiable

## 国密算法集成规范

### 1. 支持的国密算法
- **SM2**: 椭圆曲线公钥密码算法，用于数字签名和密钥交换
- **SM3**: 密码杂凑算法，用于消息摘要和数据完整性校验
- **SM4**: 分组密码算法，用于数据加密

### 2. 质押合约中的国密算法应用
- **节点身份验证**: 使用SM2进行数字签名验证
- **数据完整性**: 使用SM3进行哈希计算
- **数据隐私**: 使用SM4进行敏感数据加密

### 3. OraSRS v2.0 威胁情报中的国密算法应用
- **威胁报告签名**: 使用SM2对威胁报告进行数字签名 / Threat report signing: Use SM2 for digital signature of threat reports
- **威胁证据哈希**: 使用SM3计算威胁证据的哈希值 / Threat evidence hashing: Use SM3 to calculate hash values of threat evidence
- **威胁情报加密**: 使用SM4加密敏感威胁情报数据 / Threat intelligence encryption: Use SM4 to encrypt sensitive threat intelligence data
- **节点通信加密**: 所有节点间威胁情报通信使用国密算法加密 / Node communication encryption: All inter-node threat intelligence communication encrypted with Chinese national cryptography

### 3. OraSRS v2.0 威胁情报中的国密算法应用
- **威胁报告签名**: 使用SM2对威胁报告进行数字签名 / Threat report signing: Use SM2 for digital signature of threat reports
- **威胁证据哈希**: 使用SM3计算威胁证据的哈希值 / Threat evidence hashing: Use SM3 to calculate hash values of threat evidence
- **威胁情报加密**: 使用SM4加密敏感威胁情报数据 / Threat intelligence encryption: Use SM4 to encrypt sensitive threat intelligence data
- **节点通信加密**: 所有节点间威胁情报通信使用国密算法加密 / Node communication encryption: All inter-node threat intelligence communication encrypted with Chinese national cryptography

### 4. 国密算法部署要求
- 合约需部署在支持国密算法的国产联盟链上（如长安链）/ Contracts must be deployed on domestic consortium chains supporting Chinese national cryptography (such as ChainMaker)
- 节点需使用国密算法生成和管理密钥对 / Nodes must use Chinese national cryptography to generate and manage key pairs
- 所有签名和哈希操作均使用国密算法 / All signing and hashing operations use Chinese national cryptography

### 5. 合规性要求
- 符合《密码法》要求 / Comply with the requirements of the Cryptography Law
- 通过国家密码管理局认证 / Pass certification by the National Cryptography Administration
- 满足等保三级要求 / Meet the requirements of Cybersecurity Protection Level 3
- 数据不出境，境内部署 / Data does not leave the country, deployed domestically

### 5. 合规性要求
- 符合《密码法》要求
- 通过国家密码管理局认证
- 满足等保三级要求
- 数据不出境，境内部署