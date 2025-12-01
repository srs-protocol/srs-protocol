#!/usr/bin/env node

/**
 * SRS (Security Root Service) 启动脚本
 * 启动咨询式风险评分服务
 */

const SRSService = require('./srs-service');

// 从环境变量或默认值获取配置
const config = {
  port: process.env.SRS_PORT || 3006,
  host: process.env.SRS_HOST || '0.0.0.0',
  enableLogging: process.env.SRS_ENABLE_LOGGING !== 'false',
  logFile: process.env.SRS_LOG_FILE || './logs/srs-service.log'
};

console.log('🚀 启动 SRS (Security Root Service)...');
console.log('🔧 配置:', config);

// 确保日志目录存在
const fs = require('fs');
const path = require('path');
const logDir = path.dirname(config.logFile);
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const srsService = new SRSService(config);

async function startService() {
  try {
    await srsService.start();
    
    console.log('\n✅ SRS 服务启动成功!');
    console.log(`🌐 服务地址: http://${config.host}:${config.port}`);
    console.log('📋 API 端点:');
    console.log(`   - 风险查询: http://${config.host}:${config.port}/srs/v1/query?ip=1.2.3.4`);
    console.log(`   - 批量查询: http://${config.host}:${config.port}/srs/v1/bulk-query`);
    console.log(`   - 快速查询: http://${config.host}:${config.port}/srs/v1/lookup/1.2.3.4`);
    console.log(`   - 申诉接口: http://${config.host}:${config.port}/srs/v1/appeal`);
    console.log(`   - 透明化: http://${config.host}:${config.port}/srs/v1/explain?ip=1.2.3.4`);
    console.log(`   - 健康检查: http://${config.host}:${config.port}/health`);
    console.log('\n⚠️  重要提醒: 此服务提供咨询建议，最终决策由客户端做出');
    
    // 定期输出服务统计（每5分钟）
    setInterval(() => {
      const stats = srsService.getStats();
      console.log(`\n📊 SRS 服务统计 [${new Date().toISOString()}]`);
      console.log(`   缓存评估数: ${stats.engineStats.cachedAssessments}`);
      console.log(`   待处理申诉: ${stats.engineStats.pendingAppeals}`);
      console.log(`   关键服务白名单: ${stats.engineStats.criticalServiceWhitelistSize}`);
    }, 5 * 60 * 1000); // 5分钟
    
  } catch (error) {
    console.error('❌ 启动 SRS 服务失败:', error);
    process.exit(1);
  }
}

// 启动服务
startService();

// 优雅关闭
process.on('SIGINT', async () => {
  console.log('\n🛑 正在关闭 SRS 服务...');
  try {
    await srsService.stop();
    console.log('✅ SRS 服务已关闭');
  } catch (error) {
    console.error('关闭 SRS 服务时出错:', error);
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 正在关闭 SRS 服务...');
  try {
    await srsService.stop();
    console.log('✅ SRS 服务已关闭');
  } catch (error) {
    console.error('关闭 SRS 服务时出错:', error);
  }
  process.exit(0);
});