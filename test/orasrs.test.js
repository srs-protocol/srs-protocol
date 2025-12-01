/**
 * OraSRS 基本功能单元测试
 */

const assert = require('assert');
const SRSEngine = require('../srs-engine');
const { MetricsCollector, StructuredLogger } = require('../src/monitoring');
const FederatedLearning = require('../src/federated-learning');
const AuthRateLimit = require('../src/auth-rate-limit');

async function testOraSRSEngine() {
  console.log('测试 OraSRS 引擎...');
  
  const srsEngine = new SRSEngine();

  console.log('测试1: 为有效IP创建风险评估...');
  try {
    const result = await srsEngine.getRiskAssessment('1.2.3.4');
    
    assert(result.query, '结果应包含query属性');
    assert(result.response, '结果应包含response属性');
    assert.strictEqual(result.query.ip, '1.2.3.4', '查询IP应为1.2.3.4');
    assert(result.response.risk_score !== undefined, '响应应包含风险评分');
    assert(typeof result.response.risk_score === 'number', '风险评分应为数字');
    console.log('✓ 为有效IP创建风险评估测试通过');
  } catch (error) {
    console.log('✗ 为有效IP创建风险评估测试失败:', error.message);
  }

  console.log('测试2: 关键服务绕过...');
  try {
    const result = await srsEngine.getRiskAssessment('8.8.8.8'); // Google DNS
    
    assert.strictEqual(result.response.risk_score, 0, '关键服务的风险评分应为0');
    console.log('✓ 关键服务绕过测试通过');
  } catch (error) {
    console.log('✗ 关键服务绕过测试失败:', error.message);
  }

  console.log('测试3: 处理申诉请求...');
  try {
    const appealResult = await srsEngine.processAppeal('192.168.1.100', 'legitimate_traffic');
    
    assert(appealResult.appeal_id, '申诉结果应包含申诉ID');
    assert(appealResult.status, '申诉结果应包含状态');
    assert.strictEqual(appealResult.status, 'received', '申诉状态应为received');
    console.log('✓ 处理申诉请求测试通过');
  } catch (error) {
    console.log('✗ 处理申诉请求测试失败:', error.message);
  }

  console.log('测试4: 为IP生成解释...');
  try {
    const explanation = srsEngine.getExplanation('1.2.3.4');
    
    assert(explanation.ip, '解释应包含IP');
    assert.strictEqual(explanation.ip, '1.2.3.4', 'IP应为1.2.3.4');
    console.log('✓ 为IP生成解释测试通过');
  } catch (error) {
    console.log('✗ 为IP生成解释测试失败:', error.message);
  }
}

function testMonitoring() {
  console.log('测试监控功能...');

  console.log('测试1: 创建指标收集器...');
  try {
    const metrics = new MetricsCollector();
    
    assert(metrics, '指标收集器应存在');
    assert(metrics.getMetricsSnapshot, '指标收集器应有getMetricsSnapshot方法');
    console.log('✓ 创建指标收集器测试通过');
  } catch (error) {
    console.log('✗ 创建指标收集器测试失败:', error.message);
  }

  console.log('测试2: 记录请求指标...');
  try {
    const metrics = new MetricsCollector();
    
    metrics.recordRequest('GET', '/test', 200, 100);
    
    const snapshot = metrics.getMetricsSnapshot();
    assert.strictEqual(snapshot.requests.total, 1, '总请求数应为1');
    assert.strictEqual(snapshot.requests.byMethod.GET, 1, 'GET方法请求数应为1');
    assert.strictEqual(snapshot.requests.byStatusCode['200'], 1, '200状态码请求数应为1');
    console.log('✓ 记录请求指标测试通过');
  } catch (error) {
    console.log('✗ 记录请求指标测试失败:', error.message);
  }

  console.log('测试3: 创建结构化日志记录器...');
  try {
    const logger = new StructuredLogger({ level: 'info' });
    
    assert(logger, '日志记录器应存在');
    assert(logger.info, '日志记录器应有info方法');
    assert(logger.error, '日志记录器应有error方法');
    console.log('✓ 创建结构化日志记录器测试通过');
  } catch (error) {
    console.log('✗ 创建结构化日志记录器测试失败:', error.message);
  }
}

function testFederatedLearning() {
  console.log('测试联邦学习功能...');

  console.log('测试1: 创建联邦学习实例...');
  try {
    const fl = new FederatedLearning();
    
    assert(fl, '联邦学习实例应存在');
    assert(fl.registerNode, '联邦学习实例应有registerNode方法');
    assert(fl.collectLocalUpdates, '联邦学习实例应有collectLocalUpdates方法');
    console.log('✓ 创建联邦学习实例测试通过');
  } catch (error) {
    console.log('✗ 创建联邦学习实例测试失败:', error.message);
  }

  console.log('测试2: 注册节点...');
  try {
    const fl = new FederatedLearning();
    
    fl.registerNode('test-node', { location: 'us-east' });
    
    assert(fl.nodes.has('test-node'), '节点应在联邦学习实例中注册');
    console.log('✓ 注册节点测试通过');
  } catch (error) {
    console.log('✗ 注册节点测试失败:', error.message);
  }
}

function testAuthRateLimit() {
  console.log('测试认证和速率限制功能...');

  console.log('测试1: 创建认证速率限制器...');
  try {
    const auth = new AuthRateLimit();
    
    assert(auth, '认证速率限制器应存在');
    assert(auth.createApiKey, '认证速率限制器应有createApiKey方法');
    assert(auth.validateApiKey, '认证速率限制器应有validateApiKey方法');
    console.log('✓ 创建认证速率限制器测试通过');
  } catch (error) {
    console.log('✗ 创建认证速率限制器测试失败:', error.message);
  }

  console.log('测试2: 创建和验证API密钥...');
  try {
    const auth = new AuthRateLimit();
    const apiKeyData = auth.createApiKey({ name: 'test-key' });
    
    assert(apiKeyData, 'API密钥数据应存在');
    assert(apiKeyData.key, 'API密钥应存在');
    
    const validation = auth.validateApiKey(apiKeyData.key);
    assert.strictEqual(validation.valid, true, 'API密钥验证应成功');
    console.log('✓ 创建和验证API密钥测试通过');
  } catch (error) {
    console.log('✗ 创建和验证API密钥测试失败:', error.message);
  }
}

// 运行所有测试
async function runAllTests() {
  console.log('开始运行所有OraSRS测试...\n');
  
  await testOraSRSEngine();
  console.log('');
  
  testMonitoring();
  console.log('');
  
  testFederatedLearning();
  console.log('');
  
  testAuthRateLimit();
  console.log('');
  
  console.log('所有测试完成！');
}

// 如果直接运行此文件，则执行测试
if (require.main === module) {
  runAllTests().catch(error => {
    console.error('测试执行失败:', error);
    process.exit(1);
  });
}

// 兼容 Node.js 的 assert 和 Jest 的 expect
function expect(actual) {
  return {
    toBe: (expected) => assert.strictEqual(actual, expected),
    toHaveProperty: (prop) => assert.ok(prop in actual),
    toBeDefined: () => assert.ok(actual !== undefined),
    toBeTruthy: () => assert.ok(!!actual),
    toBeGreaterThan: (num) => assert.ok(actual > num),
    toBeGreaterThanOrEqual: (num) => assert.ok(actual >= num),
    toBeLessThanOrEqual: (num) => assert.ok(actual <= num),
    toBeInstanceOf: (constructor) => assert.ok(actual instanceof constructor)
  };
}