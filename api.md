# OraSRS v2.0 API 接口文档
# OraSRS v2.0 API Interface Documentation

## 1. API 基础信息
## 1. API Basic Information

- **API 版本**: v2.0
- **API Version**: v2.0
- **基础 URL**: `https://api.orasrs.example.com/api/v2`
- **Base URL**: `https://api.orasrs.example.com/api/v2`
- **内容类型**: `application/json`
- **Content Type**: `application/json`
- **认证方式**: API Key + 国密算法签名
- **Authentication**: API Key + SM Algorithm Signature

## 2. 认证 (Authentication)

所有 API 请求都需要在请求头中包含以下信息：

```http
Authorization: Bearer {your_api_key}
X-OraSRS-Signature: {sm2_signature}
X-OraSRS-Timestamp: {timestamp}
X-OraSRS-Nonce: {random_nonce}
```

## 3. 威胁情报 API (Threat Intelligence API)

### 3.1 提交威胁报告 (Submit Threat Report)
- **端点 / Endpoint**: `POST /threats/submit`
- **描述 / Description**: 向 OraSRS 网络提交威胁证据
- **Description**: Submit threat evidence to the OraSRS network

#### 请求参数 (Request Parameters)
```json
{
  "threatType": "DDoS|Malware|Phishing|BruteForce|SuspiciousConnection|AnomalousBehavior|IoCMatch",
  "sourceIP": "string",
  "targetIP": "string",
  "threatLevel": "Info|Warning|Critical|Emergency",
  "context": "string",
  "evidenceHash": "string",
  "geolocation": "string",
  "networkFlow": "string",
  "complianceTag": "string",
  "region": "string"
}
```

#### 示例请求 (Example Request)
```bash
curl -X POST "https://api.orasrs.example.com/api/v2/threats/submit" \
  -H "Authorization: Bearer your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "threatType": "DDoS",
    "sourceIP": "192.168.1.100",
    "targetIP": "10.0.0.1",
    "threatLevel": "Critical",
    "context": "SYN flood attack detected",
    "evidenceHash": "sm3_hash_value",
    "geolocation": "Shanghai, China",
    "networkFlow": "TCP SYN flood",
    "complianceTag": "GDPR_v2.1",
    "region": "EU"
  }'
```

#### 响应 (Response)
```json
{
  "success": true,
  "data": {
    "threatId": "threat_192.168.1.100_1623456789",
    "timestamp": 1623456789,
    "status": "pending_verification"
  },
  "message": "Threat report submitted successfully"
}
```

### 3.2 查询威胁报告 (Query Threat Report)
- **端点 / Endpoint**: `GET /threats/{threatId}`
- **描述 / Description**: 根据 ID 查询特定威胁报告
- **Description**: Query a specific threat report by ID

#### 示例请求 (Example Request)
```bash
curl -X GET "https://api.orasrs.example.com/api/v2/threats/threat_192.168.1.100_1623456789" \
  -H "Authorization: Bearer your_api_key"
```

#### 响应 (Response)
```json
{
  "success": true,
  "data": {
    "id": "threat_192.168.1.100_1623456789",
    "timestamp": 1623456789,
    "sourceIP": "192.168.1.100",
    "targetIP": "10.0.0.1",
    "threatType": "DDoS",
    "threatLevel": "Critical",
    "context": "SYN flood attack detected",
    "evidenceHash": "sm3_hash_value",
    "geolocation": "Shanghai, China",
    "networkFlow": "TCP SYN flood",
    "agentID": "agent-001",
    "verified": true,
    "verificationCount": 5,
    "complianceTag": "GDPR_v2.1",
    "region": "EU"
  },
  "message": "Threat report retrieved successfully"
}
```

### 3.3 验证威胁报告 (Verify Threat Report)
- **端点 / Endpoint**: `POST /threats/{threatId}/verify`
- **描述 / Description**: 验证特定威胁报告
- **Description**: Verify a specific threat report

#### 请求参数 (Request Parameters)
```json
{
  "verdict": true,
  "confidence": 0.9,
  "justification": "string"
}
```

#### 示例请求 (Example Request)
```bash
curl -X POST "https://api.orasrs.example.com/api/v2/threats/threat_192.168.1.100_1623456789/verify" \
  -H "Authorization: Bearer your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "verdict": true,
    "confidence": 0.9,
    "justification": "Confirmed by multiple sources"
  }'
```

### 3.4 获取全局威胁列表 (Get Global Threat List)
- **端点 / Endpoint**: `GET /threats/global`
- **描述 / Description**: 获取全局威胁列表
- **Description**: Get the global threat list

#### 查询参数 (Query Parameters)
- `limit`: 限制返回结果数量 (Limit number of results returned)
- `offset`: 偏移量 (Offset)
- `threatLevel`: 过滤威胁级别 (Filter by threat level)
- `region`: 过滤区域 (Filter by region)

#### 示例请求 (Example Request)
```bash
curl -X GET "https://api.orasrs.example.com/api/v2/threats/global?limit=10&threatLevel=Critical" \
  -H "Authorization: Bearer your_api_key"
```

## 4. 区块链威胁证据合约 API (Blockchain Threat Evidence Contract API)

### 4.1 提交威胁证据到区块链 (Submit Threat Evidence to Blockchain)
- **端点 / Endpoint**: `POST /blockchain/submit`
- **描述 / Description**: 将威胁证据提交到区块链进行不可篡改存储
- **Description**: Submit threat evidence to blockchain for immutable storage

#### 请求参数 (Request Parameters)
```json
{
  "reportData": {
    "threatType": 0,
    "sourceIP": "string",
    "targetIP": "string", 
    "threatLevel": 2,
    "context": "string",
    "evidenceHash": "string",
    "geolocation": "string"
  },
  "nonce": 123456
}
```

### 4.2 获取链上威胁证据 (Get On-chain Threat Evidence)
- **端点 / Endpoint**: `GET /blockchain/threats/{threatId}`
- **描述 / Description**: 从区块链获取威胁证据
- **Description**: Get threat evidence from blockchain

## 5. 代理管理 API (Agent Management API)

### 5.1 获取代理状态 (Get Agent Status)
- **端点 / Endpoint**: `GET /agent/status`
- **描述 / Description**: 获取当前代理状态
- **Description**: Get current agent status

#### 示例响应 (Example Response)
```json
{
  "success": true,
  "data": {
    "agentId": "agent-001",
    "version": "2.0.0",
    "uptime": 86400,
    "threatCount": 150,
    "reputation": 0.95,
    "memoryUsage": 2048576,
    "cpuUsage": 15.5,
    "networkUsage": 10485760,
    "lastThreatReport": 1623456789,
    "p2pConnected": true,
    "complianceMode": "GDPR"
  }
}
```

### 5.2 更新代理配置 (Update Agent Configuration)
- **端点 / Endpoint**: `POST /agent/config`
- **描述 / Description**: 更新代理配置
- **Description**: Update agent configuration

## 6. 合规 API (Compliance API)

### 6.1 验证合规状态 (Verify Compliance Status)
- **端点 / Endpoint**: `POST /compliance/verify`
- **描述 / Description**: 验证请求是否符合合规要求
- **Description**: Verify if request complies with compliance requirements

#### 请求参数 (Request Parameters)
```json
{
  "data": "string",
  "region": "EU|China|Global",
  "dataTypes": ["threat_intel", "network_flow", "anonymized_data"]
}
```

## 7. 错误码 (Error Codes)

| 错误码 / Code | 描述 / Description |
|---------------|---------------------|
| 200 | 成功 / Success |
| 400 | 请求参数错误 / Bad Request |
| 401 | 未授权 / Unauthorized |
| 403 | 禁止访问 / Forbidden |
| 404 | 资源未找到 / Not Found |
| 429 | 请求过于频繁 / Too Many Requests |
| 500 | 服务器内部错误 / Internal Server Error |
| 503 | 服务不可用 / Service Unavailable |

## 8. 限流 (Rate Limiting)

API 实施以下限流策略：
- 每分钟最多 1000 个请求
- 每小时最多 50000 个请求
- 每天最多 1000000 个请求

API implements the following rate limiting:
- Maximum 1,000 requests per minute
- Maximum 50,000 requests per hour
- Maximum 1,000,000 requests per day

## 9. 国密算法集成 (SM Algorithm Integration)

API 支持国密算法进行数据加密和签名：
- SM2: 数字签名和密钥交换
- SM3: 哈希算法
- SM4: 块密码

API supports Chinese national cryptographic algorithms:
- SM2: Digital signature and key exchange
- SM3: Hash algorithm
- SM4: Block cipher