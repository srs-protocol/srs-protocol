# OraSRS Protocol (Oracle Security Root Service) / OraSRS 协议 (Oracle Security Root Service)
> 一种隐私优先、联邦学习驱动、三层共识架构的安全决策协议。
> A privacy-first, federated learning-driven, three-layer consensus architecture security decision protocol.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GitHub Discussions](https://img.shields.io/github/discussions/SRS协议/orasrs-protocol)](https://github.com/SRS协议/orasrs-protocol/discussions)

## 🔍 什么是 OraSRS？ / What is OraSRS?
OraSRS 是一种轻量、去中心化的安全决策协议。它允许网络设备在面临未知流量时，通过查询权威服务获取风险评估建议，辅助本地策略执行。
OraSRS is a lightweight, decentralized security decision protocol. It allows network devices to query authoritative services for risk assessment recommendations when facing unknown traffic, assisting local policy enforcement.

> ⚠️ **核心原则 / Core Principle**:  
> OraSRS 是 **咨询式服务**（Advisory），不直接阻断流量。最终决策权始终保留在客户端。
> OraSRS is an **Advisory Service** and does not directly block traffic. The final decision always remains with the client.

## ✨ 增强功能 / Enhanced Features
- **三层去中心化架构 / Three-Tier Decentralized Architecture**: 超轻量边缘代理 + 多链可信存证 + 威胁情报协调网络 / Ultra-lightweight Edge Agent + Multi-chain Trusted Evidence Storage + Threat Intelligence Coordination Network
- **无质押声誉系统 / Stake-Free Reputation System**: 基于行为的动态声誉评分，无需经济质押 / Behavior-based dynamic reputation scoring, no economic staking required
- **BFT 共识算法 / BFT Consensus Algorithm**: 支持多链部署，区域化合规 / Multi-chain deployment support, regional compliance
- **国产化支持 / Localization Support**: 支持国密算法（SM2/SM3/SM4），适配长安链 / Supports Chinese national cryptography (SM2/SM3/SM4), compatible with ChainMaker
- **合规治理 / Compliance Governance**: 自动区域合规引擎，满足GDPR/CCPA/等保2.0 / Automatic regional compliance engine, compliant with GDPR/CCPA/Cybersecurity Protection Level 2.0
- **OraSRS v2.0 协调防御 / OraSRS v2.0 Coordinated Defense**: 全球轻量级主动防御协调框架 / Global Lightweight Proactive Defense Coordination Framework
- **OraSRS Agent**: 超轻量级威胁检测代理，< 5MB内存占用 / Ultra-lightweight threat detection agent with < 5MB memory footprint

## 📚 协议规范 / Protocol Specifications
- [v0.1 规范文档 / v0.1 Specification Document](SRS_PROTOCOL_SPEC.md)（中文/英文 / Chinese/English）
- [OraSRS v2.0 威胁情报协议 / OraSRS v2.0 Threat Intelligence Protocol](OraSRS_v2.0_Threat_Intelligence_Protocol.md)（中英双语 / Chinese-English）
- [共识参数白皮书 / Consensus Parameters Whitepaper](CONSENSUS_PARAMETERS_WHITEPAPER.md)
- [国密算法集成指南 / SM Cryptography Integration Guide](SM_CRYPTO_INTEGRATION.md)
- [设计哲学 / Design Philosophy](docs/design.md)
- [应用指南 / Application Guide](APPLICATION_GUIDE.md)
- [API 接口 / API Interface](api.md)

## 🧩 智能合约 / Smart Contracts
- [国密版质押合约 / SM Cryptography Staking Contract](contracts/orasrs-staking-gm.sol)
- [国密算法库 / SM Cryptography Library](contracts/libs/GmSupport.sol)

## 🔒 安全测试 / Security Testing
- [安全测试指南 / Security Testing Guide](SECURITY_TESTING_GUIDE.md)
- [安全测试脚本 / Security Testing Script](test-security.sh)
- [安全测试合约 / Security Testing Contract](test/orasrs-security.t.sol)
- [安全配置文件 / Security Configuration File](security-config.json)
- [安全分析报告 / Security Analysis Report](SECURITY_ANALYSIS_REPORT.md)

## 🚀 部署方案 / Deployment Solutions
- [长安链部署技术方案 / ChainMaker Deployment Technical Solution](CHAINMAKER_DEPLOYMENT_PLAN.md)
- [ChainMaker 迁移指南 / ChainMaker Migration Guide](CHAINMAKER_MIGRATION_GUIDE.md)
- [ChainMaker 安全测试 / ChainMaker Security Testing](CHAINMAKER_SECURITY_TESTING.md)

## 🔐 ChainMaker 合约 / ChainMaker Contract
- [ChainMaker 合约代码 / ChainMaker Contract Code](chainmaker-contract/orasrscontract/orasrscontract.go)
- [威胁情报扩展 / Threat Intelligence Extensions](chainmaker-contract/orasrscontract/extra_methods.go)
- [安全测试代码 / Security Test Code](chainmaker-contract/security_test.go)
- [安全测试报告 / Security Test Report](CHAINMAKER_CONTRACT_SECURITY_REPORT.md)
- [合约创建总结 / Contract Creation Summary](CHAINMAKER_CONTRACT_SUMMARY.md)
- [构建测试脚本 / Build and Test Script](build-and-test.sh)

## 🤖 OraSRS Agent
- [Agent 架构设计 / Agent Architecture Design](orasrs-agent/agent-architecture.md)
- [使用指南 / Usage Guide](orasrs-agent/USAGE.md)
- [源代码 / Source Code](orasrs-agent/src/)
- [配置示例 / Configuration Examples](orasrs-agent/config.example.toml)

## 🧩 客户端库 / Client Libraries
- [客户端实现指南 / Client Implementation Guide](CLIENT_IMPLEMENTATION_GUIDE.md)
- Node.js: `npm install @orasrs-client`
- Python: `pip install orasrs-client`

## 🌐 使用场景 / Use Cases
- 边缘防火墙（pfSense, OPNsense）/ Edge Firewalls (pfSense, OPNsense)
- Web 应用防火墙（WAF）/ Web Application Firewalls (WAF)
- IoT/工业控制系统 / IoT/Industrial Control Systems
- 去中心化网络节点（Web3）/ Decentralized Network Nodes (Web3)
- 政务链、工业链、金融链风险评估 / Government chains, industrial chains, financial chain risk assessment

## 🛡️ 安全与隐私 / Security and Privacy
- IP 匿名化处理 / IP Anonymization Processing
- 不收集原始日志 / No Raw Log Collection
- 公共服务豁免机制 / Public Service Exemption Mechanism
- 国密算法加密 / Chinese National Cryptography Encryption
- 数据不出境（中国大陆）/ Data Does Not Leave (Mainland China)

## 🤝 贡献与社区 / Contribution and Community
- 提问或建议：[GitHub Discussions](https://github.com/SRS协议/orasrs-protocol/discussions)
- Ask questions or make suggestions: [GitHub Discussions](https://github.com/SRS协议/orasrs-protocol/discussions)

## 🛡️ 商标声明 / Trademark Statement
"OraSRS" and "Open & Advisory Risk Scoring Service" are trademarks of OraSRS Protocol. 
You may use them only to refer to the official protocol. 
Modified implementations must use a different name.

## 📄 许可证 / License
本项目采用 [Apache License 2.0](LICENSE) 开源。
This project is open source under the [Apache License 2.0](LICENSE).