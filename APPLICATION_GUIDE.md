# OraSRS 增强版应用指南

本指南说明如何使用 OraSRS 协议的增强功能，包括共识机制、质押、声誉系统等。

## 1. 初始化 OraSRS v2.0 引擎

```javascript
const OrasrsEngine = require('./orasrs-engine');

// 初始化 OraSRS v2.0 协调防御引擎
const orasrsEngine = new OrasrsEngine({
  edgeAgent: {
    maxMemory: 5 * 1024 * 1024,  // 最大内存: 5MB
    privacyLevel: 'gdpr',        // 隐私级别: gdpr/ccpa/china/global
    enableNetflow: true,         // 启用网络流监控
    enableSyscall: true,         // 启用系统调用监控
    enableTlsInspect: true,      // 启用TLS检查
    enableGeoFence: true         // 启用地理围栏
  },
  consensusLayer: {
    regionalChain: 'auto',       // 区域链: auto/china/global
    enableSmCrypto: true,        // 启用国密算法
    enableEd25519: true,         // 启用国际算法
    evidenceRetention: 180       // 证据保留天数
  },
  intelligenceFabric: {
    enableP2p: true,            // 启用P2P网络
    enableCisaAis: false,       // 启用CISA AIS接入
    enableVirusTotal: false,    // 启用VirusTotal接入
    enableMisp: false,          // 启用MISP接入
    enableAlienVault: false     // 启用AlienVault OTX接入
  },
  complianceEngine: {
    autoRegion: true,           // 自动区域合规
    enableGdpr: true,           // 启用GDPR合规
    enableCcpa: true,           // 启用CCPA合规
    enableCyberSecurityLaw: true // 启用网络安全法合规
  }
});
```

## 2. Agent 部署与管理

### 2.1 边缘Agent部署

```javascript
// 部署边缘Agent
const agentConfig = {
  region: 'CN',                 // 部署区域
  complianceMode: 'cybersecurity_law', // 合规模式
  privacyLevel: 24,             // IP匿名化级别 (/24)
  maxMemory: 5 * 1024 * 1024,   // 最大内存 5MB
  reputationThreshold: 0.7      // 声誉阈值
};

try {
  const result = orasrsEngine.deployEdgeAgent(
    'agent-001',                // Agent ID
    agentConfig                 // Agent配置
  );
  console.log('边缘Agent部署成功:', result);
} catch (error) {
  console.error('边缘Agent部署失败:', error.message);
}
```

### 2.2 Agent 配置管理

```javascript
// 更新Agent配置
try {
  const result = orasrsEngine.updateAgentConfig(
    'agent-001',                // Agent ID
    { 
      privacyLevel: 16,          // 调整IP匿名化级别
      enableNetflow: true,       // 启用网络流监控
      enableSyscall: false       // 禁用系统调用监控（性能考虑）
    }
  );
  console.log('Agent配置更新成功:', result);
} catch (error) {
  console.error('Agent配置更新失败:', error.message);
}
```

## 3. 声誉系统

### 3.1 更新Agent声誉

```javascript
// 更新Agent声誉
const performanceData = {
  detectionAccuracy: 0.95,         // 检测准确率
  responseTime: 50,                // 响应时间(ms)
  evidenceQuality: 0.92,           // 证据质量
  complianceAdherence: 1.0,        // 合规遵循度
  falsePositiveRate: 0.02          // 误报率
};

const newReputation = orasrsEngine.updateAgentReputation('agent-001', performanceData);
console.log(`Agent声誉更新为: ${newReputation}`);
```

### 3.2 获取Agent状态

```javascript
// 获取Agent状态
const agentStatus = orasrsEngine.getAgentStatus('agent-001');
console.log('Agent状态:', agentStatus);

// 获取全局声誉统计
const reputationStats = orasrsEngine.getReputationStats();
console.log('声誉统计:', reputationStats);
```

## 4. 治理机制

### 4.1 添加治理委员会成员

```javascript
// 添加企业席位成员
const enterpriseMember = {
  name: 'Tech Corp Ltd.',
  type: 'enterprise',             // enterprise, academia, community
  qualification: '区块链技术服务提供商',
  expertise: '网络安全与共识算法'
};

srsEngine.addGovernanceMember('member-001', enterpriseMember);
```

### 4.2 创建和投票提案

```javascript
// 创建升级提案
srsEngine.createGovernanceProposal(
  'upgrade-proposal-001',
  '共识算法升级',
  '将共识算法从PBFT升级为HotStuff',
  'member-001',
  'standard'  // standard, emergency
);

// 开始投票
srsEngine.startProposalVoting('upgrade-proposal-001');

// 委员会成员投票
srsEngine.committeeVote('member-001', 'upgrade-proposal-001', 'yes');
```

### 4.3 紧急熔断

```javascript
// 触发紧急熔断（需要2/3以上委员同意）
const haltResult = srsEngine.emergencyHalt('检测到51%攻击');
console.log('紧急熔断结果:', haltResult);
```

## 5. 三层架构操作

### 5.1 初始化三层架构

```javascript
// 初始化OraSRS v2.0三层架构
await orasrsEngine.initializeThreeTierArchitecture();
```

### 5.2 边缘层操作

```javascript
// 配置边缘Agent
const edgeConfig = {
  agentId: 'edge-agent-001',
  maxMemory: 5 * 1024 * 1024,    // 5MB内存限制
  privacyLevel: 'gdpr',          // GDPR隐私级别
  enabledModules: {
    netflow: true,               // 网络流监控
    syscall: true,               // 系统调用监控
    tlsInspect: true,            // TLS检查
    geoFence: true               // 地理围栏
  }
};

// 部署边缘Agent
await orasrsEngine.deployEdgeAgent(edgeConfig);
```

### 5.3 共识层操作

```javascript
// 提交威胁证据到共识层
const threatEvidence = {
  sourceIP: '192.168.1.10',
  targetIP: '10.0.0.5',
  threatType: 'ddos_attack',
  threatLevel: 'critical',
  context: 'SYN flood detected',
  evidenceHash: 'blake3_hash_value',
  geolocation: 'Shanghai, China',
  timestamp: Date.now()
};

// 根据区域自动选择合适的链
const submissionResult = await orasrsEngine.submitToConsensusLayer(
  threatEvidence,
  'auto'  // 自动选择区域链
);

console.log('威胁证据提交结果:', submissionResult);
```

### 5.4 智能层操作

```javascript
// 获取全局威胁情报
const globalThreatIntel = await orasrsEngine.getIntelligenceFabricData();

// P2P威胁验证
const verificationResult = await orasrsEngine.p2pThreatVerification(
  'threat-id-12345',
  threatEvidence
);

console.log('P2P验证结果:', verificationResult);

// 驱动下游防御系统
await orasrsEngine.driveDownstreamDefenseSystems({
  threatLevel: 'critical',
  targetIP: '192.168.1.10',
  action: 'block'
});
```

### 5.5 架构状态监控

```javascript
// 获取三层架构状态
const architectureStatus = orasrsEngine.getThreeTierStatus();
console.log('三层架构状态:', architectureStatus);

// 系统健康检查
const health = orasrsEngine.architectureHealthCheck();
console.log('健康检查结果:', health);

// 执行跨层合规审计
const complianceAudit = await orasrsEngine.performCrossLayerComplianceAudit();
console.log('跨层合规审计报告:', complianceAudit);
```

## 7. 安全与合规

### 7.1 数据加密

```javascript
// 使用SM4加密敏感数据
const encrypted = srsEngine.encryptWithSM4(sensitiveData, encryptionKey);
console.log('加密结果:', encrypted);

// 数据脱敏
const sanitized = srsEngine.sanitizeData(userData);
console.log('脱敏后数据:', sanitized);
```

### 7.2 合规报告

```javascript
// 生成合规报告
const complianceReport = srsEngine.generateComplianceReport();
console.log('合规报告:', complianceReport);
```

## 8. 风险评估API

### 8.1 基础风险评估

```javascript
// 使用增强版风险评估
const riskAssessment = await srsEngine.getRiskAssessment('1.2.3.4', 'example.com');
console.log('风险评估结果:', riskAssessment);
```

### 8.2 申诉处理

```javascript
// 提交申诉
const appealResult = await srsEngine.processAppeal('1.2.3.4', '我们已经解决了机器人问题');
console.log('申诉结果:', appealResult);
```

## 9. 性能监控

```javascript
// 运行边缘缓存维护任务
srsEngine.runEdgeCacheMaintenance();

// 获取联邦学习状态
const fedStatus = srsEngine.getFederationStatus();
console.log('联邦学习状态:', fedStatus);
```

## 10. 跨链适配器

OraSRS 增强版支持多种区块链网络的适配：

- 政务链：蚂蚁链（FAIR 协议）
- 工业链：浪潮云洲链
- 金融链：BCOS

适配器实现示例：

```javascript
// 适配器注册（概念性）
const adapterRegistry = {
  register: (blockchainName, adapterImplementation) => {
    // 注册跨链适配器
  },
  
  executeCrossChainQuery: (blockchain, query) => {
    // 执行跨链查询
  }
};

## 11. OraSRS v2.0 威胁情报协议集成

### 11.1 威胁情报合约部署

OraSRS v2.0威胁情报合约需要部署在支持智能合约的区块链网络上：

```javascript
// 连接到支持威胁情报的链
const web3 = new Web3('http://chainmaker-node:8545'); // 或其他支持威胁情报的链端点

// 部署威胁情报合约
const threatIntelContract = new web3.eth.Contract(OrasrsThreatIntelContract.abi);
const deployedContract = await threatIntelContract
  .deploy({ 
    data: OrasrsThreatIntelContract.bytecode,
    arguments: [governanceCommitteeAddress]
  })
  .send({ from: deployerAddress, gas: 8000000 });

console.log('威胁情报合约部署成功:', deployedContract.options.address);
```

### 11.2 威胁报告提交

```javascript
// 使用威胁情报合约提交威胁报告
const threatReport = {
  sourceIP: '192.168.1.10',
  targetIP: '10.0.0.5',
  threatType: 'ddos_attack',
  threatLevel: 2, // 0=Info, 1=Warning, 2=Critical, 3=Emergency
  context: 'SYN flood attack detected',
  evidenceHash: 'a1b2c3d4e5f6...',
  geolocation: 'Shanghai, China',
  networkFlow: 'source_port: 1024-65535, dest_port: 80'
};

// 提交威胁报告
const result = await deployedContract.methods
  .submitThreatReport(
    threatReport.threatType,
    threatReport.sourceIP,
    threatReport.targetIP,
    threatReport.threatLevel.toString(),
    threatReport.context,
    threatReport.evidenceHash,
    threatReport.geolocation,
    threatReport.networkFlow
  )
  .send({ from: threatSensorAddress });

console.log('威胁报告提交结果:', result);
```

### 11.3 威胁验证与查询

```javascript
// 验证威胁报告（仅授权验证器可调用）
await deployedContract.methods
  .verifyThreatReport('threat_192.168.1.10_1701234567')
  .send({ from: validatorAddress });

// 获取特定威胁报告
const threatReport = await deployedContract.methods
  .getThreatReport('threat_192.168.1.10_1701234567')
  .call();

console.log('威胁报告详情:', threatReport);

// 获取全局威胁列表
const globalThreatList = await deployedContract.methods
  .getGlobalThreatList()
  .call();

console.log('全局威胁列表:', globalThreatList);
```

### 11.4 威胁情报合约集成（增强版）

```javascript
// 结合质押合约和威胁情报合约的完整操作
const fullIntegration = async () => {
  // 获取节点信息，检查是否为威胁传感器
  const nodeInfo = await deployedContract.methods
    .getNodeInfo(nodeAddress)
    .call();
    
  if (nodeInfo.node.isThreatSensor) {
    console.log('节点是威胁传感器，启用威胁检测功能');
    
    // 启动威胁检测代理
    const threatAgent = {
      version: nodeInfo.node.agentVersion,
      deploymentType: nodeInfo.node.deploymentType,
      lastThreatReport: nodeInfo.node.lastThreatReport
    };
    
    console.log('威胁代理配置:', threatAgent);
  }
};
```

## 12. OraSRS v2.0 协调防御系统集成

### 12.1 部署多链存证系统

OraSRS v2.0多链存证系统需要部署在支持国密算法的区域链上：

```javascript
// 连接到区域链（自动选择）
const chainConnector = new ChainConnector({
  region: 'auto',  // 自动识别部署区域
  chains: {
    china: 'chainmaker-node:8545',      // 长安链端点
    global: 'polygon-rpc-endpoint'      // Polygon端点
  }
});

// 部署威胁证据存证合约
const threatEvidenceContract = new chainConnector.Contract(ThreatEvidence.abi);
const deployedContract = await threatEvidenceContract
  .deploy({ 
    data: ThreatEvidence.bytecode,
    arguments: [governanceAddress, complianceEngineAddress]
  })
  .send({ from: deployerAddress, gas: 8000000 });
```

### 12.2 威胁证据提交（国密签名版）

```javascript
// 使用国密算法生成威胁证据签名
const threatReport = {
  sourceIP: '192.168.1.10',
  targetIP: '10.0.0.5',
  threatType: 'ddos_attack',
  threatLevel: 2, // 0=Info, 1=Warning, 2=Critical, 3=Emergency
  context: 'SYN flood attack detected',
  evidenceHash: 'blake3_hash_value',
  geolocation: 'Shanghai, China',
  networkFlow: 'source_port: 1024-65535, dest_port: 80',
  timestamp: Date.now()
};

// 准备证据数据并使用SM2签名
const evidenceData = {
  ...threatReport,
  agentId: 'edge-agent-001',
  complianceTag: 'gdpr_v2.1'
};

// 使用SM3哈希和SM2签名
const sm3HashValue = sm3(JSON.stringify(evidenceData));
const sm2Signature = generateSm2Signature(sm3HashValue, privateKey);

// 提交威胁证据
const result = await deployedContract.methods
  .submitThreatEvidence(
    evidenceData.threatType,
    evidenceData.sourceIP,
    evidenceData.targetIP,
    evidenceData.threatLevel,
    evidenceData.context,
    evidenceData.evidenceHash,
    evidenceData.geolocation,
    evidenceData.networkFlow,
    sm2Signature,
    sm3HashValue
  )
  .send({ from: agentAddress });

console.log('威胁证据提交结果:', result);
```

### 12.3 获取威胁情报

```javascript
// 获取特定威胁证据
const threatEvidence = await deployedContract.methods
  .getThreatEvidence('threat-id-12345')
  .call();

console.log('威胁证据详情:', threatEvidence);

// 获取区域威胁列表
const regionalThreatList = await deployedContract.methods
  .getRegionalThreatList('EU')
  .call();

console.log('区域威胁列表:', regionalThreatList);
```

### 12.4 P2P验证集成

```javascript
// 提交P2P验证请求
await deployedContract.methods
  .submitP2pVerification(
    'threat-id-12345',
    verificationEvidence,
    geolocationData
  )
  .send({ from: verifierAddress });

// 获取验证结果（仅授权验证器可调用）
const verificationResult = await deployedContract.methods
  .getVerificationResult('threat-id-12345')
  .call();

console.log('P2P验证结果:', verificationResult);
```

### 12.5 合规审计集成

```javascript
// 执行合规审计（仅监管机构可调用）
const auditReport = await deployedContract.methods
  .performComplianceAudit('2025-01-01', '2025-01-31')
  .call();

console.log('合规审计报告:', auditReport);
```

### 12.6 驱动下游防御系统

```javascript
// 生成并推送威胁情报到下游系统
await deployedContract.methods
  .pushThreatIntelligenceToDownstream({
    threatLevel: 'CRITICAL',
    targetIP: '192.168.1.10',
    action: 'BLOCK',
    evidenceTxId: 'tx-hash-12345'
  })
  .send({ from: intelligenceFabricAddress });

// 生成SIEM兼容的日志
const siemLog = generateCefFormatLog({
  threatLevel: 'CRITICAL',
  sourceIP: '192.168.1.10',
  targetIP: '10.0.0.5',
  threatType: 'DDoS',
  orasrsTxId: 'tx-hash-12345'
});

console.log('SIEM日志:', siemLog);
````