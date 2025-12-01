# OraSRS (Oracle Security Root Service) 协议规范

## 概述

OraSRS (Oracle Security Root Service) 是一个咨询式风险评分服务，旨在为互联网安全决策提供权威参考。与传统的阻断式防火墙不同，OraSRS 提供风险评估和建议，由客户端自主决定是否执行相应措施。

## 设计原则

### 1. 咨询式服务模式
- **错误设计**: OraSRS 返回 `{ action: "BLOCK" }`
- **正确设计**: OraSRS 返回 `{ risk_score: 0.92, evidence: ["ddos_bot", "scan_24h"] }`
- **客户端强制执行** → **客户端自主决策是否拦截**

> 类比：OraSRS 是信用评分机构（如 FICO），不是法院。客户端（如银行）自己决定是否采取行动。

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

#### (2) 自动衰减与申诉通道
- 风险分随时间衰减（如 24 小时后降级）
- 提供公开申诉接口：
```
POST /orasrs/appeal
{ "ip": "1.2.3.4", "proof": "we_fixed_the_botnet" }
```

#### (3) 透明化与可审计
- 所有标记记录上链（或公开日志）
- 提供 `GET /orasrs/explain?ip=1.2.3.4` 返回决策依据

### 3. 公共服务豁免原则

在 OraSRS 策略中硬编码关键公共服务白名单，永不拦截：

| 服务类型 | 示例域名/IP |
|---------|------------|
| 政府 | .gov, .mil, 国家税务/社保 IP 段 |
| 医疗 | 医院官网、急救系统 |
| 金融基础设施 | SWIFT、央行支付系统 |
| 基础通信 | DNS 根服务器、NTP 池 |

## API 端点

### 风险查询
```
GET /orasrs/v1/query?ip={ip}&domain={domain}
```

**请求示例**:
```
GET /orasrs/v1/query?ip=1.2.3.4
Accept: application/json
```

**响应格式**:
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
- 重大封禁规则需技术委员会投票
- 防止单点决策滥用

## 实现特点

1. **去中心化**: 基于节点联邦学习的威胁情报
2. **隐私优先**: 差分隐私保护，本地数据处理
3. **开源可验证**: 完全开源，全球审计
4. **标准兼容**: 支持STIX/TAXII、RPZ等开放标准

## 集成指南

客户端应:

1. 查询OraSRS获取风险评分
2. 根据自身策略和OraSRS建议做出最终决策
3. 记录决策日志用于审计
4. 提供反馈以改进OraSRS模型

## 责任声明

OraSRS仅提供风险评估和建议，最终的安全决策由客户端做出。OraSRS不承担因客户端执行决策而导致的任何后果。