/**
 * SRS (Security Root Service) Service
 * 完整的SRS服务实现，包含引擎、API和管理功能
 */

const express = require('express');
const SRSEngine = require('./srs-engine');
const srsRoutes = require('./routes/srs-routes');
const fs = require('fs').promises;
const path = require('path');

class SRSService {
  constructor(config = {}) {
    this.config = {
      port: config.port || 3000,
      host: config.host || '0.0.0.0',
      enableLogging: config.enableLogging !== false,
      logFile: config.logFile || './logs/srs-service.log',
      ...config
    };
    
    this.engine = new SRSEngine();
    this.app = express();
    
    // 中间件
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));
    
    // CORS支持
    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
      if (req.method === 'OPTIONS') {
        res.sendStatus(200);
      } else {
        next();
      }
    });
    
    // SRS API路由
    this.app.use('/srs/v1', srsRoutes);
    
    // 健康检查端点
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'healthy',
        service: 'SRS (Security Root Service)',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      });
    });
    
    // 根路径返回服务信息
    this.app.get('/', (req, res) => {
      res.status(200).json({
        service: 'SRS (Security Root Service)',
        description: 'Advisory Risk Scoring Service - Provides risk assessments for IPs and domains. Clients make final decisions based on our recommendations.',
        endpoints: {
          query: '/srs/v1/query?ip={ip}&domain={domain}',
          bulkQuery: '/srs/v1/bulk-query',
          lookup: '/srs/v1/lookup/{indicator}',
          appeal: '/srs/v1/appeal',
          explain: '/srs/v1/explain?ip={ip}',
          dataDeletion: '/srs/v1/data?ip_hash={hash}',
          health: '/health'
        },
        disclaimer: 'This service provides advisory risk scoring only. Final decisions are made by clients using our recommendations.',
        compliance: 'GDPR/CCPA compliant'
      });
    });
    
    // 错误处理中间件
    this.app.use((error, req, res, next) => {
      console.error('SRS Service Error:', error);
      res.status(500).json({
        error: 'Internal server error',
        code: 'INTERNAL_ERROR',
        timestamp: new Date().toISOString()
      });
    });
  }

  /**
   * 启动SRS服务
   */
  async start() {
    return new Promise((resolve, reject) => {
      this.server = this.app.listen(
        { 
          port: this.config.port, 
          host: this.config.host 
        },
        () => {
          console.log(`SRS Service listening on ${this.config.host}:${this.config.port}`);
          console.log('SRS (Security Root Service) - Advisory Risk Scoring Service is now running');
          console.log('Important: This service provides advisory recommendations only, not direct blocking commands.');
          resolve();
        }
      );

      this.server.on('error', (error) => {
        console.error('Failed to start SRS Service:', error);
        reject(error);
      });
    });
  }

  /**
   * 停止SRS服务
   */
  async stop() {
    if (this.server) {
      return new Promise((resolve) => {
        this.server.close(() => {
          console.log('SRS Service stopped');
          resolve();
        });
      });
    }
  }

  /**
   * 获取SRS引擎实例
   */
  getEngine() {
    return this.engine;
  }

  /**
   * 记录SRS服务日志
   */
  async logEvent(eventType, data) {
    if (!this.config.enableLogging) return;
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      eventType,
      ...data
    };
    
    try {
      await fs.appendFile(this.config.logFile, JSON.stringify(logEntry) + '\n');
    } catch (error) {
      console.error('Failed to write SRS log:', error);
    }
  }

  /**
   * 获取服务统计信息
   */
  getStats() {
    return {
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      engineStats: {
        cachedAssessments: this.engine.riskScores.size,
        pendingAppeals: Array.from(this.engine.appealRequests.values()).filter(a => a.status === 'pending').length,
        criticalServiceWhitelistSize: this.engine.criticalServiceWhitelist.size
      }
    };
  }

  /**
   * 获取透明度报告
   */
  getTransparencyReport() {
    const now = new Date();
    const last24Hours = new Date(now - 24 * 60 * 60 * 1000);
    
    // 在实际实现中，这将从日志或数据库中获取数据
    // 这里我们返回模拟数据
    return {
      reportPeriod: {
        start: last24Hours.toISOString(),
        end: now.toISOString()
      },
      totalQueries: Math.floor(Math.random() * 10000) + 5000, // 模拟数据
      totalAppeals: Math.floor(Math.random() * 100) + 10, // 模拟数据
      averageRiskScore: (Math.random() * 0.5).toFixed(2), // 模拟数据
      criticalServicesBypassed: Math.floor(Math.random() * 50), // 模拟数据
      topEvidenceTypes: [
        { type: 'behavior', count: Math.floor(Math.random() * 1000) },
        { type: 'scan_24h', count: Math.floor(Math.random() * 800) },
        { type: 'ddos_bot', count: Math.floor(Math.random() * 500) }
      ],
      compliance: {
        gdprCompliant: true,
        dataMinimization: true,
        automatedDecisioning: false // 因为我们只提供咨询，不直接阻断
      }
    };
  }
}

// 如果直接运行此文件，启动SRS服务
if (require.main === module) {
  const srsService = new SRSService({
    port: 3006, // 使用专用端口以避免与主服务器冲突
    enableLogging: true
  });
  
  srsService.start()
    .then(() => {
      console.log('SRS Service started successfully on port 3006');
      console.log('Access the service at: http://localhost:3006');
      console.log('SRS API endpoints available at: http://localhost:3006/srs/v1');
    })
    .catch(error => {
      console.error('Failed to start SRS Service:', error);
      process.exit(1);
    });
  
  // 优雅关闭
  process.on('SIGINT', async () => {
    console.log('\nShutting down SRS Service...');
    await srsService.stop();
    process.exit(0);
  });
}

module.exports = SRSService;