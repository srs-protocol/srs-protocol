/**
 * OraSRS 监控与日志模块
 * 提供Prometheus集成和结构化日志记录
 */

const fs = require('fs').promises;
const path = require('path');

// 简单的指标收集器
class MetricsCollector {
  constructor() {
    this.metrics = {
      requests: {
        total: 0,
        byEndpoint: {},
        byMethod: {},
        byStatusCode: {}
      },
      responseTime: {
        total: 0,
        count: 0,
        avg: 0,
        p95: 0,
        p99: 0
      },
      errors: {
        total: 0,
        byType: {}
      },
      activeConnections: 0,
      totalConnections: 0
    };
    
    this.responseTimes = []; // 用于计算百分位数
    this.startTimestamp = Date.now();
  }

  // 记录请求
  recordRequest(method, endpoint, statusCode, responseTime) {
    this.metrics.requests.total++;
    
    // 按端点统计
    if (!this.metrics.requests.byEndpoint[endpoint]) {
      this.metrics.requests.byEndpoint[endpoint] = 0;
    }
    this.metrics.requests.byEndpoint[endpoint]++;
    
    // 按方法统计
    if (!this.metrics.requests.byMethod[method]) {
      this.metrics.requests.byMethod[method] = 0;
    }
    this.metrics.requests.byMethod[method]++;
    
    // 按状态码统计
    if (!this.metrics.requests.byStatusCode[statusCode]) {
      this.metrics.requests.byStatusCode[statusCode] = 0;
    }
    this.metrics.requests.byStatusCode[statusCode]++;
    
    // 响应时间统计
    this.metrics.responseTime.total += responseTime;
    this.metrics.responseTime.count++;
    this.metrics.responseTime.avg = this.metrics.responseTime.total / this.metrics.responseTime.count;
    
    this.responseTimes.push(responseTime);
    if (this.responseTimes.length > 1000) { // 只保留最近1000个响应时间
      this.responseTimes = this.responseTimes.slice(-1000);
    }
  }

  // 记录错误
  recordError(errorType) {
    this.metrics.errors.total++;
    
    if (!this.metrics.errors.byType[errorType]) {
      this.metrics.errors.byType[errorType] = 0;
    }
    this.metrics.errors.byType[errorType]++;
  }

  // 更新连接数
  updateConnections(active, total) {
    this.metrics.activeConnections = active;
    this.metrics.totalConnections = total;
  }

  // 获取指标快照
  getMetricsSnapshot() {
    // 计算百分位数
    const sortedTimes = [...this.responseTimes].sort((a, b) => a - b);
    const n = sortedTimes.length;
    
    return {
      ...this.metrics,
      responseTime: {
        ...this.metrics.responseTime,
        p95: n > 0 ? sortedTimes[Math.floor(0.95 * n)] : 0,
        p99: n > 0 ? sortedTimes[Math.floor(0.99 * n)] : 0
      },
      uptime: Date.now() - this.startTimestamp,
      timestamp: new Date().toISOString()
    };
  }

  // 重置指标（可选）
  reset() {
    this.metrics = {
      requests: {
        total: 0,
        byEndpoint: {},
        byMethod: {},
        byStatusCode: {}
      },
      responseTime: {
        total: 0,
        count: 0,
        avg: 0,
        p95: 0,
        p99: 0
      },
      errors: {
        total: 0,
        byType: {}
      },
      activeConnections: 0,
      totalConnections: 0
    };
    this.responseTimes = [];
  }
}

// 结构化日志记录器
class StructuredLogger {
  constructor(options = {}) {
    this.level = options.level || 'info';
    this.logFile = options.logFile || './logs/orasrs.log';
    this.maxFileSize = options.maxFileSize || 10 * 1024 * 1024; // 10MB
    this.logToConsole = options.logToConsole !== false;
    
    // 确保日志目录存在
    const logDir = path.dirname(this.logFile);
    try {
      // 尝试创建日志目录
      require('fs').mkdirSync(logDir, { recursive: true });
    } catch (e) {
      // 如果无法创建目录，记录错误但不中断
      console.warn(`无法创建日志目录 ${logDir}:`, e.message);
    }
  }

  async log(level, message, meta = {}) {
    // 检查日志级别
    const levels = { error: 0, warn: 1, info: 2, debug: 3 };
    const currentLevel = levels[this.level] || 2;
    const messageLevel = levels[level] || 2;
    
    if (messageLevel > currentLevel) {
      return;
    }

    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      ...meta
    };

    // 格式化日志行
    const logLine = JSON.stringify(logEntry) + '\n';

    // 写入日志文件
    try {
      // 检查文件大小并执行轮转
      try {
        const stats = await fs.stat(this.logFile);
        if (stats.size > this.maxFileSize) {
          await this.rotateLog();
        }
      } catch (err) {
        // 如果文件不存在，忽略错误
        if (err.code !== 'ENOENT') {
          throw err;
        }
      }

      await fs.appendFile(this.logFile, logLine);
    } catch (error) {
      console.error('Failed to write to log file:', error);
    }

    // 同时输出到控制台（如果需要）
    if (this.logToConsole) {
      const consoleMessage = `[${level.toUpperCase()}] ${new Date().toISOString()} - ${message}`;
      if (Object.keys(meta).length > 0) {
        console.log(consoleMessage, meta);
      } else {
        console.log(consoleMessage);
      }
    }
  }

  async rotateLog() {
    const rotatedFile = this.logFile + '.' + Date.now();
    try {
      await fs.rename(this.logFile, rotatedFile);
    } catch (error) {
      console.error('Log rotation failed:', error);
    }
  }

  error(message, meta = {}) {
    return this.log('error', message, meta);
  }

  warn(message, meta = {}) {
    return this.log('warn', message, meta);
  }

  info(message, meta = {}) {
    return this.log('info', message, meta);
  }

  debug(message, meta = {}) {
    return this.log('debug', message, meta);
  }
}

// Prometheus指标格式化
function formatPrometheusMetrics(metrics) {
  const lines = [];
  
  lines.push('# HELP orasrs_requests_total Total number of requests');
  lines.push('# TYPE orasrs_requests_total counter');
  lines.push(`orasrs_requests_total ${metrics.requests.total}`);
  
  lines.push('# HELP orasrs_requests_by_endpoint_total Requests by endpoint');
  lines.push('# TYPE orasrs_requests_by_endpoint_total counter');
  for (const [endpoint, count] of Object.entries(metrics.requests.byEndpoint)) {
    lines.push(`orasrs_requests_by_endpoint_total{endpoint="${endpoint}"} ${count}`);
  }
  
  lines.push('# HELP orasrs_requests_by_method_total Requests by HTTP method');
  lines.push('# TYPE orasrs_requests_by_method_total counter');
  for (const [method, count] of Object.entries(metrics.requests.byMethod)) {
    lines.push(`orasrs_requests_by_method_total{method="${method}"} ${count}`);
  }
  
  lines.push('# HELP orasrs_requests_by_status_code_total Requests by status code');
  lines.push('# TYPE orasrs_requests_by_status_code_total counter');
  for (const [statusCode, count] of Object.entries(metrics.requests.byStatusCode)) {
    lines.push(`orasrs_requests_by_status_code_total{status_code="${statusCode}"} ${count}`);
  }
  
  lines.push('# HELP orasrs_response_time_seconds Average response time in seconds');
  lines.push('# TYPE orasrs_response_time_seconds gauge');
  lines.push(`orasrs_response_time_seconds ${metrics.responseTime.avg / 1000}`);
  
  lines.push('# HELP orasrs_response_time_p95_seconds 95th percentile response time in seconds');
  lines.push('# TYPE orasrs_response_time_p95_seconds gauge');
  lines.push(`orasrs_response_time_p95_seconds ${metrics.responseTime.p95 / 1000}`);
  
  lines.push('# HELP orasrs_response_time_p99_seconds 99th percentile response time in seconds');
  lines.push('# TYPE orasrs_response_time_p99_seconds gauge');
  lines.push(`orasrs_response_time_p99_seconds ${metrics.responseTime.p99 / 1000}`);
  
  lines.push('# HELP orasrs_errors_total Total number of errors');
  lines.push('# TYPE orasrs_errors_total counter');
  lines.push(`orasrs_errors_total ${metrics.errors.total}`);
  
  lines.push('# HELP orasrs_active_connections Current number of active connections');
  lines.push('# TYPE orasrs_active_connections gauge');
  lines.push(`orasrs_active_connections ${metrics.activeConnections}`);
  
  lines.push('# HELP orasrs_uptime_milliseconds Service uptime in milliseconds');
  lines.push('# TYPE orasrs_uptime_milliseconds gauge');
  lines.push(`orasrs_uptime_milliseconds ${metrics.uptime}`);
  
  return lines.join('\n') + '\n';
}

module.exports = {
  MetricsCollector,
  StructuredLogger,
  formatPrometheusMetrics
};
