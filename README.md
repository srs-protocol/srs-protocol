# OraSRS Protocol (Oracle Security Root Service)
> A privacy-first, federated security decision protocol.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![GitHub Discussions](https://img.shields.io/github/discussions/SRS协议/orasrs-protocol)](https://github.com/SRS协议/orasrs-protocol/discussions)

## 🔍 什么是 OraSRS？
OraSRS 是一种轻量、去中心化的安全决策协议。它允许网络设备在面临未知流量时，通过查询权威服务获取风险评估建议，辅助本地策略执行。

> ⚠️ **核心原则**：  
> OraSRS 是 **咨询式服务**（Advisory），不直接阻断流量。最终决策权始终保留在客户端。

## 📚 协议规范
- [v0.1 规范文档](spec/v0.1.md)（中文/英文）
- [设计哲学](docs/design.md)
- [API 接口](api.md)

## 🧩 客户端库
- Node.js: `npm install @orasrs-client`
- Python: `pip install orasrs-client`

## 🌐 使用场景
- 边缘防火墙（pfSense, OPNsense）
- Web 应用防火墙（WAF）
- IoT/工业控制系统
- 去中心化网络节点（Web3）

## 🛡️ 安全与隐私
- IP 匿名化处理
- 不收集原始日志
- 公共服务豁免机制

## 🤝 贡献与社区
- 提问或建议：[GitHub Discussions](https://github.com/SRS协议/orasrs-protocol/discussions)
- 提交 PR 或 Issue
- 加入 Telegram 社区（待建）

## 🛡️ 商标声明
"OraSRS" and "Open & Advisory Risk Scoring Service" are trademarks of OraSRS Protocol. 
You may use them only to refer to the official protocol. 
Modified implementations must use a different name.

## 📄 许可证
本项目采用 [Apache License 2.0](LICENSE) 开源。
