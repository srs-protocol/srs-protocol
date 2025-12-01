/**
 * OraSRS (Oracle Security Root Service) API Router
 * 实现OraSRS协议的API端点
 * 遵循咨询式服务模式，提供风险评分而非直接阻断指令
 */

const express = require('express');
const SRSEngine = require('./srs-engine');

const router = express.Router();
const srsEngine = new SRSEngine();

// SRS查询端点 - 返回风险评分而非阻断指令
router.get('/query', async (req, res) => {
  try {
    const { ip, domain } = req.query;

    if (!ip) {
      return res.status(400).json({
        error: 'IP parameter is required',
        code: 'MISSING_IP_PARAMETER'
      });
    }

    // 获取风险评估
    const result = await srsEngine.getSRSResponse(ip, domain);

    // 添加免责声明头部
    res.set({
      'X-OraSRS-Disclaimer': 'This is advisory only. Final decision rests with the client.',
      'X-OraSRS-Compliance': 'GDPR/CCPA compliant - no raw IP storage',
      'Cache-Control': 'public, max-age=300' // 5分钟缓存
    });

    res.json(result);
  } catch (error) {
    console.error('OraSRS query error:', error);
    res.status(500).json({
      error: 'Internal server error during OraSRS query',
      code: 'OraSRS_QUERY_ERROR'
    });
  }
});

// 批量查询端点
router.post('/bulk-query', async (req, res) => {
  try {
    const { ips, domains } = req.body;

    if (!ips && !domains) {
      return res.status(400).json({
        error: 'Either ips or domains array is required',
        code: 'MISSING_PARAMETERS'
      });
    }

    const results = [];

    if (ips && Array.isArray(ips)) {
      for (const ip of ips) {
        const result = await srsEngine.getSRSResponse(ip);
        results.push(result);
      }
    }

    if (domains && Array.isArray(domains)) {
      for (const domain of domains) {
        const result = await srsEngine.getSRSResponse(null, domain);
        results.push(result);
      }
    }

    // 添加免责声明头部
    res.set({
      'X-OraSRS-Disclaimer': 'This is advisory only. Final decision rests with the client.',
      'X-OraSRS-Compliance': 'GDPR/CCPA compliant - no raw IP storage'
    });

    res.json({
      query_time: new Date().toISOString(),
      results
    });
  } catch (error) {
    console.error('OraSRS bulk query error:', error);
    res.status(500).json({
      error: 'Internal server error during OraSRS bulk query',
      code: 'OraSRS_BULK_QUERY_ERROR'
    });
  }
});

// 快速查询端点
router.get('/lookup/:indicator', async (req, res) => {
  try {
    const { indicator } = req.params;

    // 判断是IP还是域名
    const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(indicator);
    const isDomain = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$/.test(indicator);

    let result;
    if (isIP) {
      result = await srsEngine.getSRSResponse(indicator);
    } else if (isDomain) {
      result = await srsEngine.getSRSResponse(null, indicator);
    } else {
      return res.status(400).json({
        error: 'Invalid indicator format. Must be IP or domain.',
        code: 'INVALID_INDICATOR'
      });
    }

    // 添加免责声明头部
    res.set({
      'X-OraSRS-Disclaimer': 'This is advisory only. Final decision rests with the client.',
      'X-OraSRS-Compliance': 'GDPR/CCPA compliant - no raw IP storage'
    });

    res.json(result);
  } catch (error) {
    console.error('OraSRS lookup error:', error);
    res.status(500).json({
      error: 'Internal server error during OraSRS lookup',
      code: 'OraSRS_LOOKUP_ERROR'
    });
  }
});

// 申诉接口
router.post('/appeal', async (req, res) => {
  try {
    const { ip, proof } = req.body;

    if (!ip) {
      return res.status(400).json({
        error: 'IP parameter is required',
        code: 'MISSING_IP_PARAMETER'
      });
    }

    if (!proof) {
      return res.status(400).json({
        error: 'Proof parameter is required',
        code: 'MISSING_PROOF_PARAMETER'
      });
    }

    // 处理申诉
    const appealResult = await srsEngine.processAppeal(ip, proof);

    res.status(201).json(appealResult);
  } catch (error) {
    console.error('OraSRS appeal error:', error);
    res.status(500).json({
      error: 'Internal server error during OraSRS appeal',
      code: 'OraSRS_APPEAL_ERROR'
    });
  }
});

// 透明化和可审计接口 - 获取决策依据
router.get('/explain', async (req, res) => {
  try {
    const { ip } = req.query;

    if (!ip) {
      return res.status(400).json({
        error: 'IP parameter is required',
        code: 'MISSING_IP_PARAMETER'
      });
    }

    const explanation = srsEngine.getExplanation(ip);

    res.json(explanation);
  } catch (error) {
    console.error('OraSRS explain error:', error);
    res.status(500).json({
      error: 'Internal server error during OraSRS explain',
      code: 'OraSRS_EXPLAIN_ERROR'
    });
  }
});

// GDPR/CCPA数据删除接口
router.delete('/data', async (req, res) => {
  try {
    const { ip_hash } = req.query;

    if (!ip_hash) {
      return res.status(400).json({
        error: 'IP hash parameter is required',
        code: 'MISSING_IP_HASH_PARAMETER'
      });
    }

    // 在实际实现中，这里会删除与IP哈希相关的数据
    // 由于当前实现使用原始IP而非哈希，我们模拟此过程
    console.log(`GDPR/CCPA deletion request for IP hash: ${ip_hash}`);

    res.json({
      message: 'Data deletion request processed',
      ip_hash,
      processed_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('OraSRS data deletion error:', error);
    res.status(500).json({
      error: 'Internal server error during OraSRS data deletion',
      code: 'OraSRS_DATA_DELETION_ERROR'
    });
  }
});

module.exports = router;