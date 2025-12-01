/**
 * OraSRS (Oracle Security Root Service) Engine
 * 咨询式风险评分服务引擎
 * 定位为"咨询式服务"，而非"执行式防火墙"
 * OraSRS 是信用评分机构（如 FICO），不是法院。客户端自己决定是否采取行动。
 */

const FederatedLearning = require('./src/federated-learning');

class SRSEngine {
  constructor(options = {}) {
    this.riskScores = new Map(); // 存储风险评分
    this.evidenceLog = new Map(); // 存储证据日志
    this.appealRequests = new Map(); // 存储申诉请求
    this.criticalServiceWhitelist = new Set(); // 关键服务白名单
    this.federatedLearning = new FederatedLearning(options.federatedLearning || {}); // 联邦学习模块
    this.nodeId = options.nodeId || 'default-node'; // 节点ID
    
    // 初始化关键服务白名单
    this.initializeCriticalServiceWhitelist();
    
    // 注意：在生产环境中，风险评分衰减应由外部调度器或cron作业管理
    // 以避免在某些环境中的定时器问题
    // this.startRiskDecayScheduler();
  }

  /**
   * 初始化关键服务白名单
   * 遵守"公共服务豁免"原则
   */
  initializeCriticalServiceWhitelist() {
    // 政府服务
    this.criticalServiceWhitelist.add('.gov');
    this.criticalServiceWhitelist.add('.mil');
    // 医疗服务
    this.criticalServiceWhitelist.add('.edu');
    this.criticalServiceWhitelist.add('who.int');
    // 金融基础设施
    this.criticalServiceWhitelist.add('swift.com');
    this.criticalServiceWhitelist.add('federalreserve.gov');
    // 基础通信
    this.criticalServiceWhitelist.add('192.168.1.1'); // 示例 - DNS根服务器等
    this.criticalServiceWhitelist.add('8.8.8.8'); // Google DNS
    this.criticalServiceWhitelist.add('1.1.1.1'); // Cloudflare DNS
  }

  /**
   * 检查是否为关键公共服务
   */
  isCriticalPublicService(target) {
    // 检查IP或域名是否在白名单中
    if (this.criticalServiceWhitelist.has(target)) {
      return true;
    }

    // 检查域名后缀
    for (const whitelistItem of this.criticalServiceWhitelist) {
      if (whitelistItem.startsWith('.') && target.endsWith(whitelistItem)) {
        return true;
      }
    }

    return false;
  }

  /**
   * 计算风险评分
   */
  calculateRiskScore(ip, evidence) {
    let riskScore = 0;
    
    // 根据证据类型计算风险评分
    for (const item of evidence) {
      switch (item.type) {
        case 'ddos_bot':
          riskScore += 0.3;
          break;
        case 'scan_24h':
          riskScore += 0.2;
          break;
        case 'malware_distribution':
          riskScore += 0.4;
          break;
        case 'behavior':
          if (item.detail && item.detail.includes('SYN flood')) {
            riskScore += 0.35;
          } else if (item.detail && item.detail.includes('brute force')) {
            riskScore += 0.25;
          }
          break;
        default:
          riskScore += 0.1;
      }
    }
    
    // 限制风险评分在0-1之间
    return Math.min(riskScore, 1.0);
  }

  /**
   * 生成风险评估报告
   */
  async getRiskAssessment(ip, domain = null) {
    // 检查是否为关键公共服务
    if (this.isCriticalPublicService(ip) || (domain && this.isCriticalPublicService(domain))) {
      return {
        query: { ip, domain },
        response: {
          risk_score: 0,
          confidence: 'high',
          bypass: true,
          recommendations: {
            default: 'allow',
            critical_services: 'allow'
          },
          appeal_url: null,
          expires_at: null
        }
      };
    }

    // 检查缓存中是否已有风险评分
    const cacheKey = ip + (domain ? `_${domain}` : '');
    if (this.riskScores.has(cacheKey)) {
      const cached = this.riskScores.get(cacheKey);
      // 检查是否过期
      if (cached.expires_at && new Date(cached.expires_at) > new Date()) {
        return cached;
      } else {
        // 如果过期则移除
        this.riskScores.delete(cacheKey);
      }
    }

    // 模拟从威胁情报源获取证据
    const evidence = await this.gatherEvidence(ip, domain);
    const riskScore = this.calculateRiskScore(ip, evidence);

    // 确定风险等级
    let riskLevel = 'low';
    if (riskScore >= 0.7) {
      riskLevel = 'high';
    } else if (riskScore >= 0.4) {
      riskLevel = 'medium';
    }

    // 生成推荐策略
    const recommendations = this.generateRecommendations(riskLevel);

    // 生成响应对象
    const response = {
      query: { ip, domain },
      response: {
        risk_score: riskScore,
        confidence: riskLevel === 'high' ? 'high' : riskLevel === 'medium' ? 'medium' : 'low',
        risk_level: riskLevel,
        evidence,
        recommendations,
        appeal_url: `https://api.orasrs.net/appeal?ip=${ip}`,
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24小时后过期
        disclaimer: 'This is advisory only. Final decision rests with the client.'
      }
    };

    // 缓存结果
    this.riskScores.set(cacheKey, response);

    return response;
  }

  /**
   * 收集证据（模拟）
   */
  async gatherEvidence(ip, domain) {
    // 模拟威胁情报收集
    const evidence = [];

    // 模拟从不同来源收集证据
    if (Math.random() > 0.7) {
      evidence.push({
        type: 'behavior',
        detail: 'SYN flood to 10 targets in 1h',
        source: 'node-' + Math.random().toString(36).substring(2, 8),
        timestamp: new Date().toISOString()
      });
    }

    if (Math.random() > 0.8) {
      evidence.push({
        type: 'scan_24h',
        detail: 'Port scanning activity detected',
        source: 'node-' + Math.random().toString(36).substring(2, 8),
        timestamp: new Date().toISOString()
      });
    }

    if (Math.random() > 0.9) {
      evidence.push({
        type: 'ddos_bot',
        detail: 'Identified as part of DDoS botnet',
        source: 'ai_analysis',
        timestamp: new Date().toISOString()
      });
    }

    // 如果没有证据，返回空数组
    if (evidence.length === 0) {
      return [];
    }

    return evidence;
  }

  /**
   * 生成推荐策略
   */
  generateRecommendations(riskLevel) {
    let recommendations = {
      default: 'allow',
      public_services: 'allow',
      banking: 'allow',
      admin_panel: 'allow'
    };

    switch (riskLevel) {
      case 'high':
        recommendations = {
          default: 'block',
          public_services: 'allow_with_captcha',
          banking: 'require_mfa',
          admin_panel: 'block',
          critical_services: 'allow'
        };
        break;
      case 'medium':
        recommendations = {
          default: 'challenge',
          public_services: 'allow_with_captcha',
          banking: 'require_additional_verification',
          admin_panel: 'challenge',
          critical_services: 'allow'
        };
        break;
      case 'low':
      default:
        recommendations = {
          default: 'allow',
          public_services: 'allow',
          banking: 'allow',
          admin_panel: 'allow',
          critical_services: 'allow'
        };
    }

    return recommendations;
  }

  /**
   * 申诉处理
   */
  async processAppeal(ip, proof) {
    const appealId = `appeal_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
    
    const appealData = {
      id: appealId,
      ip,
      proof,
      status: 'pending',
      submitted_at: new Date().toISOString(),
      processed_at: null
    };

    this.appealRequests.set(appealId, appealData);

    // 立即降低该IP的风险评分
    this.reduceRiskScoreForAppeal(ip);

    return {
      appeal_id: appealId,
      status: 'received',
      message: 'Appeal request received. Risk score temporarily reduced during review.',
      estimated_resolution_time: '24-48 hours'
    };
  }

  /**
   * 为申诉的IP降低风险评分
   */
  reduceRiskScoreForAppeal(ip) {
    // 在24小时内降低该IP的风险评分
    const cacheKey = ip;
    if (this.riskScores.has(cacheKey)) {
      const currentData = this.riskScores.get(cacheKey);
      // 创建调整后的数据
      const adjustedResponse = JSON.parse(JSON.stringify(currentData));
      adjustedResponse.response.risk_score = Math.max(0, adjustedResponse.response.risk_score - 0.3);
      adjustedResponse.response.evidence = [
        ...adjustedResponse.response.evidence,
        {
          type: 'appeal_pending',
          detail: 'Risk score temporarily reduced during appeal review',
          timestamp: new Date().toISOString()
        }
      ];
      // 更新过期时间为1小时后
      adjustedResponse.response.expires_at = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      
      this.riskScores.set(cacheKey, adjustedResponse);
    }
  }

  /**
   * 获取决策解释
   */
  getExplanation(ip) {
    const cacheKey = ip;
    if (this.riskScores.has(cacheKey)) {
      const cached = this.riskScores.get(cacheKey);
      return {
        ip,
        risk_score: cached.response.risk_score,
        risk_level: cached.response.risk_level,
        evidence: cached.response.evidence,
        recommendations: cached.response.recommendations,
        appealed: this.isAppealed(ip),
        last_updated: cached.response.expires_at
      };
    }

    return {
      ip,
      message: 'No risk assessment found for this IP. The IP may be in the critical services whitelist or not yet assessed.',
      risk_score: 0
    };
  }

  /**
   * 检查IP是否有申诉
   */
  isAppealed(ip) {
    for (const [_, appeal] of this.appealRequests) {
      if (appeal.ip === ip && appeal.status === 'pending') {
        return true;
      }
    }
    return false;
  }

  /**
   * 风险评分衰减调度器
   */
  startRiskDecayScheduler() {
    // 每小时执行一次风险评分衰减
    setInterval(() => {
      this.applyRiskDecay();
    }, 60 * 60 * 1000); // 1小时
  }

  /**
   * 应用风险评分衰减
   */
  applyRiskDecay() {
    // 遍历所有风险评分，按时间衰减
    for (const [key, data] of this.riskScores) {
      // 检查是否存在有效的过期时间
      if (data.response.expires_at) {
        const hoursSinceAssessment = (Date.now() - new Date(data.response.expires_at).getTime()) / (1000 * 60 * 60);
        
        // 如果超过24小时，将风险评分降低10%
        if (hoursSinceAssessment > 24) {
          const newRiskScore = Math.max(0, data.response.risk_score - 0.1);
          data.response.risk_score = newRiskScore;
          
          // 更新过期时间
          data.response.expires_at = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        }
      }
    }
  }

  /**
   * 获取SRS响应格式（安全版）
   */
  async getSRSResponse(ip, domain = null) {
    return await this.getRiskAssessment(ip, domain);
  }

  /**
   * 联邦学习：注册到联邦网络
   */
  registerToFederation(nodeId, config) {
    return this.federatedLearning.registerNode(nodeId, config);
  }

  /**
   * 联邦学习：提交本地模型更新
   */
  async submitLocalUpdate(localUpdates) {
    return await this.federatedLearning.collectLocalUpdates(this.nodeId, localUpdates);
  }

  /**
   * 联邦学习：执行联邦学习轮次
   */
  async performFederatedRound() {
    return await this.federatedLearning.federatedRound();
  }

  /**
   * 联邦学习：获取联邦状态
   */
  getFederationStatus() {
    return this.federatedLearning.getStatus();
  }

  /**
   * 更新风险评估模型（从联邦学习中）
   */
  updateModelFromFederation() {
    // 从聚合模型中获取更新并应用到本地模型
    const aggregatedModel = this.federatedLearning.aggregatedModel;
    
    if (aggregatedModel.size > 0) {
      // 这里可以应用聚合模型来更新本地风险评估逻辑
      console.log('从联邦模型更新本地风险评估参数');
      // 实现具体的模型更新逻辑
    }
  }
}

// 导出SRS引擎
module.exports = SRSEngine;

// 如果直接运行此文件，启动测试
if (require.main === module) {
  console.log('OraSRS Engine initialized');
  console.log('This engine provides advisory risk scoring services.');
  console.log('It does NOT directly block traffic - clients make the final decision.');
}