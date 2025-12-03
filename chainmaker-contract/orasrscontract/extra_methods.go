package orasrscontract

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// submitThreatReport 提交威胁报告
func (c *OrasrsStakingContract) submitThreatReport() ([]byte, error) {
	// 验证调用者权限（必须是活跃节点）
	if err := c.onlyActiveNode(); err != nil {
		return nil, fmt.Errorf("only active nodes can submit threat reports: %v", err)
	}

	// 获取威胁报告参数
	threatTypeBytes, exists := c.Args["threat_type"]
	if !exists || len(threatTypeBytes) == 0 {
		return nil, fmt.Errorf("threat_type is required")
	}
	threatType := string(threatTypeBytes)

	sourceIPBytes, exists := c.Args["source_ip"]
	if !exists || len(sourceIPBytes) == 0 {
		return nil, fmt.Errorf("source_ip is required")
	}
	sourceIP := string(sourceIPBytes)

	targetIPBytes, exists := c.Args["target_ip"]
	if !exists || len(targetIPBytes) == 0 {
		return nil, fmt.Errorf("target_ip is required")
	}
	targetIP := string(targetIPBytes)

	threatLevelStrBytes, exists := c.Args["threat_level"]
	if !exists || len(threatLevelStrBytes) == 0 {
		return nil, fmt.Errorf("threat_level is required")
	}
	threatLevelStr := string(threatLevelStrBytes)

	// 解析威胁等级
	var threatLevel ThreatLevel
	switch threatLevelStr {
	case "Info":
		threatLevel = Info
	case "Warning":
		threatLevel = Warning
	case "Critical":
		threatLevel = Critical
	case "Emergency":
		threatLevel = Emergency
	default:
		return nil, fmt.Errorf("invalid threat_level: %s", threatLevelStr)
	}

	contextBytes, exists := c.Args["context"]
	if !exists || len(contextBytes) == 0 {
		return nil, fmt.Errorf("context is required")
	}
	context := string(contextBytes)

	// 生成威胁报告ID
	reportID := fmt.Sprintf("threat_%s_%d", sourceIP, c.TxTimeStamp)

	// 创建威胁证明
	attestation := ThreatAttestation{
		ID:           reportID,
		Timestamp:    c.TxTimeStamp,
		SourceIP:     sourceIP,
		TargetIP:     targetIP,
		ThreatType:   threatType,
		ThreatLevel:  threatLevel,
		Context:      context,
		AgentID:      c.Caller,
		EvidenceHash: string(c.Args["evidence_hash"]), // 可能为空
		Geolocation:  string(c.Args["geolocation"]),   // 可能为空
		NetworkFlow:  string(c.Args["network_flow"]),  // 可能为空
	}

	// 验证威胁报告
	if err := c.validateThreatReport(attestation); err != nil {
		return nil, fmt.Errorf("threat report validation failed: %v", err)
	}

	// 保存威胁报告
	attestationBytes, err := json.Marshal(attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal threat attestation: %v", err)
	}

	attestationKey := ThreatAttestationKey + reportID
	err = c.Put([]byte(attestationKey), attestationBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to save threat attestation: %v", err)
	}

	// 更新节点的威胁报告计数
	node, err := c.getNodeByAddress(c.Caller)
	if err != nil {
		return nil, fmt.Errorf("failed to get node: %v", err)
	}
	node.LastThreatReport = c.TxTimeStamp
	node.ChallengeCount++ // 威胁报告也算作一种挑战
	err = c.saveNode(*node)
	if err != nil {
		return nil, fmt.Errorf("failed to update node: %v", err)
	}

	// 检查是否需要添加到全局威胁列表
	if threatLevel >= Critical {
		err = c.addToGlobalThreatList(sourceIP, threatLevel)
		if err != nil {
			fmt.Printf("Warning: failed to add to global threat list: %v\n", err)
		}
	}

	// 记录威胁报告事件
	eventData := []string{reportID, sourceIP, targetIP, threatType, strconv.FormatInt(c.TxTimeStamp, 10)}
	c.EmitEvent("ThreatReported", eventData)

	return []byte(reportID), nil
}

// validateThreatReport 验证威胁报告的有效性
func (c *OrasrsStakingContract) validateThreatReport(attestation ThreatAttestation) error {
	// 验证IP格式
	if !c.isValidIP(attestation.SourceIP) {
		return fmt.Errorf("invalid source IP format: %s", attestation.SourceIP)
	}

	if !c.isValidIP(attestation.TargetIP) {
		return fmt.Errorf("invalid target IP format: %s", attestation.TargetIP)
	}

	// 防止重复报告
	existingKey := fmt.Sprintf("THREAT_DUPLICATE_%s_%s_%s", attestation.SourceIP, attestation.ThreatType, strconv.FormatInt(attestation.Timestamp/300, 10)) // 5分钟窗口
	if c.isThreatReportDuplicate(existingKey) {
		return fmt.Errorf("duplicate threat report detected")
	}

	// 标记为已处理，防止重复
	err := c.Put([]byte(existingKey), []byte("1"))
	if err != nil {
		return fmt.Errorf("failed to mark threat report as processed: %v", err)
	}

	return nil
}

// isValidIP 验证IP地址格式
func (c *OrasrsStakingContract) isValidIP(ip string) bool {
	// 简单的IP格式验证
	for _, part := range strings.Split(ip, ".") {
		if len(part) == 0 {
			continue // 允許网段格式如 192.168.1.x
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

// isThreatReportDuplicate 检查威胁报告是否重复
func (c *OrasrsStakingContract) isThreatReportDuplicate(key string) bool {
	_, err := c.Get([]byte(key))
	return err == nil
}

// addToGlobalThreatList 添加到全局威胁列表
func (c *OrasrsStakingContract) addToGlobalThreatList(ip string, level ThreatLevel) error {
	// 获取当前全局威胁列表
	threatListBytes, err := c.Get([]byte(GlobalThreatListKey))
	if err != nil {
		// 如果不存在，创建新的列表
		threatListBytes = []byte("[]")
	}

	var threatList []map[string]interface{}
	err = json.Unmarshal(threatListBytes, &threatList)
	if err != nil {
		return fmt.Errorf("failed to unmarshal threat list: %v", err)
	}

	// 检查IP是否已存在
	ipExists := false
	for i, threat := range threatList {
		if threat["ip"] == ip {
			// 如果新等级更高，更新等级
			if level > ThreatLevel(threat["level"].(float64)) {
				threatList[i]["level"] = level
				threatList[i]["last_updated"] = c.TxTimeStamp
			}
			ipExists = true
			break
		}
	}

	if !ipExists {
		// 添加新的威胁IP
		newThreat := map[string]interface{}{
			"ip":          ip,
			"level":       level,
			"first_seen":  c.TxTimeStamp,
			"last_seen":   c.TxTimeStamp,
			"report_count": 1,
		}
		threatList = append(threatList, newThreat)
	}

	// 保存更新后的威胁列表
	updatedBytes, err := json.Marshal(threatList)
	if err != nil {
		return fmt.Errorf("failed to marshal updated threat list: %v", err)
	}

	err = c.Put([]byte(GlobalThreatListKey), updatedBytes)
	if err != nil {
		return fmt.Errorf("failed to save updated threat list: %v", err)
	}

	return nil
}

// getGlobalThreatList 获取全局威胁列表
func (c *OrasrsStakingContract) getGlobalThreatList() ([]byte, error) {
	threatListBytes, err := c.Get([]byte(GlobalThreatListKey))
	if err != nil {
		return json.Marshal([]map[string]interface{}{})
	}
	return threatListBytes, nil
}

// verifyThreatReport 验证威胁报告
func (c *OrasrsStakingContract) verifyThreatReport() ([]byte, error) {
	// 仅验证节点可调用
	if err := c.onlyValidator(); err != nil {
		return nil, fmt.Errorf("only validators can verify threat reports: %v", err)
	}

	reportIDBytes, exists := c.Args["report_id"]
	if !exists || len(reportIDBytes) == 0 {
		return nil, fmt.Errorf("report_id is required")
	}
	reportID := string(reportIDBytes)

	// 获取威胁报告
	attestationKey := ThreatAttestationKey + reportID
	attestationBytes, err := c.Get([]byte(attestationKey))
	if err != nil {
		return nil, fmt.Errorf("threat report not found: %s", reportID)
	}

	var attestation ThreatAttestation
	err = json.Unmarshal(attestationBytes, &attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation: %v", err)
	}

	// 威胁验证逻辑（这里简化为基本验证）
	verificationResult := true // 在实际实现中，这将涉及多个节点的交叉验证

	// 保存验证结果
	verificationKey := ThreatVerificationKey + reportID + "_" + c.Caller
	resultData := map[string]interface{}{
		"verifier": c.Caller,
		"verified": verificationResult,
		"timestamp": c.TxTimeStamp,
		"report_id": reportID,
	}
	resultBytes, err := json.Marshal(resultData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verification result: %v", err)
	}

	err = c.Put([]byte(verificationKey), resultBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to save verification result: %v", err)
	}

	// 如果验证通过，更新相关节点声誉
	if verificationResult {
		node, err := c.getNodeByAddress(attestation.AgentID)
		if err != nil {
			fmt.Printf("Warning: failed to get agent node: %v\n", err)
		} else {
			// 提升报告节点的声誉
			node.ReputationScore += 5
			node.VerifiedThreats++
			err = c.saveNode(*node)
			if err != nil {
				fmt.Printf("Warning: failed to update node reputation: %v\n", err)
			}
		}
	}

	// 记录验证事件
	eventData := []string{reportID, c.Caller, strconv.FormatBool(verificationResult), strconv.FormatInt(c.TxTimeStamp, 10)}
	c.EmitEvent("ThreatVerified", eventData)

	return []byte("Threat verification recorded"), nil
}

// getThreatReport 获取威胁报告
func (c *OrasrsStakingContract) getThreatReport() ([]byte, error) {
	reportIDBytes, exists := c.Args["report_id"]
	if !exists || len(reportIDBytes) == 0 {
		return nil, fmt.Errorf("report_id is required")
	}
	reportID := string(reportIDBytes)

	attestationKey := ThreatAttestationKey + reportID
	attestationBytes, err := c.Get([]byte(attestationKey))
	if err != nil {
		return nil, fmt.Errorf("threat report not found: %s", reportID)
	}

	return attestationBytes, nil
}

// onlyActiveNode 仅活跃节点可调用
func (c *OrasrsStakingContract) onlyActiveNode() error {
	node, err := c.getNodeByAddress(c.Caller)
	if err != nil {
		return fmt.Errorf("node not found: %v", err)
	}

	if node.Status != Active {
		return fmt.Errorf("only active nodes can call this function, current status: %v", node.Status)
	}

	return nil
}