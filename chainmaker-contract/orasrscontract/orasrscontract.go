// OrasrsStakingContract OraSRS 质押合约
package orasrscontract

import (
	"encoding/json"
	"fmt"
	"strconv"

	sdk "chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
)

// NodeStatus 节点状态
type NodeStatus int

const (
	Unregistered NodeStatus = iota
	Registered
	Active
	Slashed
	PendingRemoval
	ThreatDetected  // 新增威胁检测状态
	Verified        // 新增已验证状态
)

// ThreatLevel 威胁等级
type ThreatLevel int

const (
	Info ThreatLevel = iota
	Warning
	Critical
	Emergency
)

// ThreatAttestation 威胁证明结构
type ThreatAttestation struct {
	ID            string      `json:"id"`
	Timestamp     int64       `json:"timestamp"`
	SourceIP      string      `json:"source_ip"`
	TargetIP      string      `json:"target_ip"`
	ThreatType    string      `json:"threat_type"`
	ThreatLevel   ThreatLevel `json:"threat_level"`
	Context       string      `json:"context"`
	AgentID       string      `json:"agent_id"`
	Signature     string      `json:"signature"`
	EvidenceHash  string      `json:"evidence_hash"`
	Geolocation   string      `json:"geolocation"`
	NetworkFlow   string      `json:"network_flow"`
}

// Node 节点结构
type Node struct {
	NodeAddress     string     `json:"node_address"`
	StakeAmount     uint64     `json:"stake_amount"`
	StakeStart      int64      `json:"stake_start"`
	ReputationScore uint64     `json:"reputation_score"`
	Status          NodeStatus `json:"status"`
	NodeId          string     `json:"node_id"`
	BusinessLicense string     `json:"business_license"`
	FilingNumber    string     `json:"filing_number"`
	ChallengeCount  uint64     `json:"challenge_count"`
	ChallengesWon   uint64     `json:"challenges_won"`
	ChallengesLost  uint64     `json:"challenges_lost"`
	LastSeen        int64      `json:"last_seen"`
	IsConsensusNode bool       `json:"is_consensus_node"`
	// OraSRS v2.0 新增字段
	IsThreatSensor  bool       `json:"is_threat_sensor"`      // 是否为威胁检测节点
	AgentVersion    string     `json:"agent_version"`         // Agent版本
	DeploymentType  string     `json:"deployment_type"`       // 部署类型：edge/consensus/intelligence
	LastThreatReport int64     `json:"last_threat_report"`    // 最后威胁报告时间
	ThreatScore     uint64     `json:"threat_score"`          // 威胁评分
	VerifiedThreats uint64     `json:"verified_threats"`      // 已验证威胁数
	ComplianceZone  string     `json:"compliance_zone"`       // 合规区域
}

// NodeInfo 节点信息查询返回结构
type NodeInfo struct {
	Node    Node   `json:"node"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ContractStats 合约统计信息
type ContractStats struct {
	TotalStaked         uint64 `json:"total_staked"`
	ActiveNodes         uint64 `json:"active_nodes"`
	TotalConsensusNodes uint64 `json:"total_consensus_nodes"`
	TotalPartitionNodes uint64 `json:"total_partition_nodes"`
	TotalEdgeNodes      uint64 `json:"total_edge_nodes"`
}

// 质押参数常量
const (
	MinStakeRoot      = uint64(10000) // 根层最小质押
	MinStakePartition = uint64(5000)  // 分区层最小质押
	MinStakeEdge      = uint64(100)   // 边缘层最小质押
	StakeLockPeriod   = int64(7 * 24 * 60 * 60) // 质押锁定期（秒）
	MaxConsensusNodes = 21 // 最大共识节点数
	SlashPenaltyRate  = 100 // 罚没比例 100%
	OfflinePenaltyRate = 5  // 离线罚没比例 5%/天
	ChallengeThreshold = 3 // 挑战阈值
)

// 键前缀常量
const (
	NodeKeyPrefix        = "NODE_"
	NodeIdToAddressKey   = "NODEID_TO_ADDR_"
	ConsensusNodesKey    = "CONSENSUS_NODES"
	PartitionNodesKey    = "PARTITION_NODES"
	EdgeNodesKey         = "EDGE_NODES"
	PendingWithdrawalKey = "PENDING_WITHDRAWAL_"
	UsedNonceKey         = "USED_NONCE_"
	OwnerKey             = "OWNER_"
	GovernanceKey        = "GOVERNANCE_"
	ContractStateKey     = "CONTRACT_STATE_"
	ValidatorKey         = "VALIDATOR_"
	// OraSRS v2.0 新增键前缀
	ThreatAttestationKey = "THREAT_ATTESTATION_"
	GlobalThreatListKey  = "GLOBAL_THREAT_LIST_"
	ThreatReportKey      = "THREAT_REPORT_"
	ThreatVerificationKey = "THREAT_VERIFICATION_"
	ComplianceReportKey  = "COMPLIANCE_REPORT_"
	ReputationHistoryKey = "REPUTATION_HISTORY_"
	AgentMetadataKey     = "AGENT_METADATA_"
)

// ContractState 合约状态
type ContractState int

const (
	StateActive ContractState = iota
	Paused
	EmergencyStopped
)

// OrasrsStakingContract OraSRS 质押合约
type OrasrsStakingContract struct {
	sdk.Contract
}

// InitContract 合约初始化方法 (长安链标准接口)
func (c *OrasrsStakingContract) InitContract() error {
	// 调试日志：显示接收到的所有参数
	fmt.Printf("InitContract received args: %+v\n", c.Args)

	// 设置合约状态为活跃
	err := c.Put([]byte(ContractStateKey), []byte(strconv.Itoa(int(StateActive))))
	if err != nil {
		return fmt.Errorf("failed to set contract state: %v", err)
	}

	// 初始化 owner（调用者地址）
	caller := c.Caller
	fmt.Printf("Contract caller (owner): %s\n", caller)
	err = c.Put([]byte(OwnerKey), []byte(caller))
	if err != nil {
		return fmt.Errorf("failed to set owner: %v", err)
	}

	// 兼容腾讯云和SDK的治理地址参数格式
	var governanceAddr string

	// 方式1: 腾讯云"快速上链"格式 (_arg0)
	if arg0, exists := c.Args["_arg0"]; exists && len(arg0) > 0 {
		governanceAddr = string(arg0)
		fmt.Printf("Using governance address from _arg0: %s\n", governanceAddr)
	} else if govAddrBytes, exists := c.Args["governance_address"]; exists && len(govAddrBytes) > 0 {
		// 方式2: SDK 直连格式 (governance_address)
		governanceAddr = string(govAddrBytes)
		fmt.Printf("Using governance address from governance_address: %s\n", governanceAddr)
	} else {
		// 如果没有提供治理地址，则使用调用者地址作为默认值
		fmt.Println("No governance address provided, using caller address as governance address")
		governanceAddr = caller
	}

	// 保存治理地址
	err = c.Put([]byte(GovernanceKey), []byte(governanceAddr))
	if err != nil {
		return fmt.Errorf("failed to set governance: %v", err)
	}

	// 初始化空的节点列表
	emptyList := make([]string, 0)
	emptyListBytes, _ := json.Marshal(emptyList)

	err = c.Put([]byte(ConsensusNodesKey), emptyListBytes)
	if err != nil {
		return fmt.Errorf("failed to initialize consensus nodes list: %v", err)
	}

	err = c.Put([]byte(PartitionNodesKey), emptyListBytes)
	if err != nil {
		return fmt.Errorf("failed to initialize partition nodes list: %v", err)
	}

	err = c.Put([]byte(EdgeNodesKey), emptyListBytes)
	if err != nil {
		return fmt.Errorf("failed to initialize edge nodes list: %v", err)
	}

	fmt.Println("Contract initialized successfully")
	return nil
}

// InvokeContract 合约调用方法 (长安链标准接口)
func (c *OrasrsStakingContract) InvokeContract() (bool, []byte, error) {
	// 获取方法名
	method := string(c.Args["method"])
	if method == "" {
		return false, nil, fmt.Errorf("method is required")
	}

	fmt.Printf("InvokeContract called with method: %s\n", method)

	switch method {
	case "stakeWithGmSign":
		result, err := c.stakeWithGmSign()
		return err == nil, result, err
	case "getNodeInfo":
		result, err := c.getNodeInfo()
		return err == nil, result, err
	case "getContractStats":
		result, err := c.getContractStats()
		return err == nil, result, err
	case "submitChallenge":
		result, err := c.submitChallenge()
		return err == nil, result, err
	case "updateReputation":
		result, err := c.updateReputation()
		return err == nil, result, err
	case "slashNode":
		result, err := c.slashNode()
		return err == nil, result, err
	case "requestWithdrawal":
		result, err := c.requestWithdrawal()
		return err == nil, result, err
	case "addValidator":
		result, err := c.addValidator()
		return err == nil, result, err
	case "pauseContract":
		result, err := c.pauseContract()
		return err == nil, result, err
	case "resumeContract":
		result, err := c.resumeContract()
		return err == nil, result, err
	case "submitThreatReport":
		result, err := c.submitThreatReport()
		return err == nil, result, err
	case "verifyThreatReport":
		result, err := c.verifyThreatReport()
		return err == nil, result, err
	case "getThreatReport":
		result, err := c.getThreatReport()
		return err == nil, result, err
	case "getGlobalThreatList":
		result, err := c.getGlobalThreatList()
		return err == nil, result, err
	default:
		return false, nil, fmt.Errorf("unknown method: " + method)
	}
}

// stakeWithGmSign 带国密签名的节点质押方法
func (c *OrasrsStakingContract) stakeWithGmSign() ([]byte, error) {
	// 检查合约状态
	state, err := c.getContractState()
	if err != nil {
		return nil, err
	}
	if state != StateActive {
		return nil, fmt.Errorf("contract is not active, current state: %v", state)
	}

	// 获取参数
	nodeIdBytes, exists := c.Args["node_id"]
	if !exists || len(nodeIdBytes) == 0 {
		return nil, fmt.Errorf("node_id is required")
	}
	nodeId := string(nodeIdBytes)
	
	amountStrBytes, exists := c.Args["amount"]
	if !exists || len(amountStrBytes) == 0 {
		return nil, fmt.Errorf("amount is required")
	}
	amountStr := string(amountStrBytes)
	
	sm2Signature, exists := c.Args["sm2_signature"]
	if !exists || len(sm2Signature) == 0 {
		return nil, fmt.Errorf("sm2_signature is required")
	}
	
	dataHash, exists := c.Args["data_hash"]
	if !exists || len(dataHash) == 0 {
		return nil, fmt.Errorf("data_hash is required")
	}
	
	nonceStrBytes, exists := c.Args["nonce"]
	if !exists || len(nonceStrBytes) == 0 {
		return nil, fmt.Errorf("nonce is required")
	}
	nonceStr := string(nonceStrBytes)
	
	businessLicenseHashBytes, exists := c.Args["business_license_hash"]
	if !exists || len(businessLicenseHashBytes) == 0 {
		return nil, fmt.Errorf("business_license_hash is required")
	}
	businessLicenseHash := string(businessLicenseHashBytes)
	
	filingNumberHashBytes, exists := c.Args["filing_number_hash"]
	if !exists || len(filingNumberHashBytes) == 0 {
		return nil, fmt.Errorf("filing_number_hash is required")
	}
	filingNumberHash := string(filingNumberHashBytes)
	
	nodeTypeStrBytes, exists := c.Args["node_type"]
	if !exists || len(nodeTypeStrBytes) == 0 {
		return nil, fmt.Errorf("node_type is required")
	}
	nodeTypeStr := string(nodeTypeStrBytes)

	// 类型转换
	amount, err := strconv.ParseUint(amountStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %v", err)
	}

	nonce, err := strconv.ParseUint(nonceStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %v", err)
	}

	nodeType, err := strconv.ParseUint(nodeTypeStr, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid node type: %v", err)
	}

	// 防重放攻击
	caller := c.Caller
	requestKey := fmt.Sprintf("%s_%s_%d_%d_%d", caller, nodeId, amount, c.TxTimeStamp, nonce)
	requestHash := []byte(requestKey) // 简化处理

	if c.isNonceUsed(requestHash) {
		return nil, fmt.Errorf("nonce already used")
	}

	// 标记 nonce 已使用
	c.setNonceUsed(requestHash)

	// 简化的SM2签名验证（在实际部署时替换为长安链内置函数）
	// valid, err := c.verifySM2Signature(sm2Signature, dataHash, caller)
	// 模拟验证成功
	valid := true
	if !valid {
		return nil, fmt.Errorf("invalid SM2 signature")
	}

	// 验证质押金额
	minStake := c.getMinStakeForNodeType(uint8(nodeType))
	if amount < minStake {
		return nil, fmt.Errorf("insufficient stake amount, required: %d, provided: %d", minStake, amount)
	}

	// 验证节点是否已存在
	existingAddr, err := c.getNodeAddressById(nodeId)
	if err == nil && existingAddr != "" {
		return nil, fmt.Errorf("node ID already exists: %s", nodeId)
	}

	// 验证营业执照和备案信息
	if businessLicenseHash == "" {
		return nil, fmt.Errorf("business license hash is required")
	}
	if filingNumberHash == "" {
		return nil, fmt.Errorf("filing number hash is required")
	}

	// 验证营业执照号格式
	if !c.validateBusinessLicense(businessLicenseHash) {
		return nil, fmt.Errorf("invalid business license format")
	}

	// 验证备案号格式
	if !c.validateFilingNumber(filingNumberHash) {
		return nil, fmt.Errorf("invalid filing number format")
	}

	// 创建节点
	node := Node{
		NodeAddress:     caller,
		StakeAmount:     amount,
		StakeStart:      c.TxTimeStamp,
		ReputationScore: 100, // 初始声誉分数
		Status:          Registered,
		NodeId:          nodeId,
		BusinessLicense: businessLicenseHash,
		FilingNumber:    filingNumberHash,
		ChallengeCount:  0,
		ChallengesWon:   0,
		ChallengesLost:  0,
		LastSeen:        c.TxTimeStamp,
		IsConsensusNode: false,
	}

	// 保存节点信息
	err = c.saveNode(node)
	if err != nil {
		return nil, fmt.Errorf("failed to save node: %v", err)
	}

	// 根据节点类型加入相应列表
	switch nodeType {
	case 0: // 根层节点
		err = c.addNodeToConsensusList(caller)
		if err != nil {
			return nil, fmt.Errorf("failed to add to consensus list: %v", err)
		}
		// 更新节点为共识节点
		node.IsConsensusNode = true
		err = c.saveNode(node)
		if err != nil {
			return nil, fmt.Errorf("failed to update node: %v", err)
		}
	case 1: // 分区层节点
		err = c.addNodeToPartitionList(caller)
		if err != nil {
			return nil, fmt.Errorf("failed to add to partition list: %v", err)
		}
	default: // 边缘层节点
		err = c.addNodeToEdgeList(caller)
		if err != nil {
			return nil, fmt.Errorf("failed to add to edge list: %v", err)
		}
	}

	// 记录质押事件
	eventData := []string{nodeId, caller, strconv.FormatUint(amount, 10)}
	c.EmitEvent("NodeStaked", eventData)

	return []byte("Node staked successfully"), nil
}

// getNodeInfo 查询节点信息
func (c *OrasrsStakingContract) getNodeInfo() ([]byte, error) {
	nodeAddrBytes, exists := c.Args["node_address"]
	if !exists || len(nodeAddrBytes) == 0 {
		return nil, fmt.Errorf("node address is required")
	}
	nodeAddr := string(nodeAddrBytes)

	node, err := c.getNodeByAddress(nodeAddr)
	if err != nil {
		result := NodeInfo{Success: false, Error: err.Error()}
		resultBytes, _ := json.Marshal(result)
		return resultBytes, nil
	}

	result := NodeInfo{
		Node:    *node,
		Success: true,
	}

	resultBytes, _ := json.Marshal(result)
	return resultBytes, nil
}

// getContractStats 获取合约统计信息
func (c *OrasrsStakingContract) getContractStats() ([]byte, error) {
	consensusNodesBytes, err := c.Get([]byte(ConsensusNodesKey))
	if err != nil {
		return nil, fmt.Errorf("failed to get consensus nodes: %v", err)
	}
	partitionNodesBytes, err := c.Get([]byte(PartitionNodesKey))
	if err != nil {
		return nil, fmt.Errorf("failed to get partition nodes: %v", err)
	}
	edgeNodesBytes, err := c.Get([]byte(EdgeNodesKey))
	if err != nil {
		return nil, fmt.Errorf("failed to get edge nodes: %v", err)
	}

	var consensusNodes []string
	var partitionNodes []string
	var edgeNodes []string

	err = json.Unmarshal(consensusNodesBytes, &consensusNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal consensus nodes: %v", err)
	}
	err = json.Unmarshal(partitionNodesBytes, &partitionNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal partition nodes: %v", err)
	}
	err = json.Unmarshal(edgeNodesBytes, &edgeNodes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal edge nodes: %v", err)
	}

	stats := ContractStats{
		TotalConsensusNodes: uint64(len(consensusNodes)),
		TotalPartitionNodes: uint64(len(partitionNodes)),
		TotalEdgeNodes:      uint64(len(edgeNodes)),
	}

	// 计算活跃节点和总质押量
	for _, addr := range consensusNodes {
		node, err := c.getNodeByAddress(addr)
		if err == nil && node.Status == Active {
			stats.TotalStaked += node.StakeAmount
			stats.ActiveNodes++
		}
	}

	for _, addr := range partitionNodes {
		node, err := c.getNodeByAddress(addr)
		if err == nil && node.Status == Active {
			stats.TotalStaked += node.StakeAmount
			stats.ActiveNodes++
		}
	}

	for _, addr := range edgeNodes {
		node, err := c.getNodeByAddress(addr)
		if err == nil && node.Status == Active {
			stats.TotalStaked += node.StakeAmount
			stats.ActiveNodes++
		}
	}

	resultBytes, _ := json.Marshal(stats)
	return resultBytes, nil
}

// submitChallenge 提交挑战
func (c *OrasrsStakingContract) submitChallenge() ([]byte, error) {
	cacheKeyBytes, exists := c.Args["cache_key"]
	if !exists || len(cacheKeyBytes) == 0 {
		return nil, fmt.Errorf("cache_key is required")
	}
	cacheKey := string(cacheKeyBytes)

	reasonBytes, exists := c.Args["reason"]
	if !exists || len(reasonBytes) == 0 {
		return nil, fmt.Errorf("reason is required")
	}
	reason := string(reasonBytes)

	// 获取挑战者地址
	challenger := c.Caller

	// 验证挑战者是否为活跃节点
	node, err := c.getNodeByAddress(challenger)
	if err != nil || node.Status != Active {
		return nil, fmt.Errorf("challenger is not an active node")
	}

	// 生成挑战ID
	challengeId := fmt.Sprintf("challenge_%s_%d", cacheKey, c.TxTimeStamp)

	// 记录挑战事件
	eventData := []string{challengeId, cacheKey, challenger, reason, strconv.FormatInt(c.TxTimeStamp, 10)}
	c.EmitEvent("NodeChallenged", eventData)

	return []byte("Challenge submitted successfully"), nil
}

// updateReputation 更新节点声誉
func (c *OrasrsStakingContract) updateReputation() ([]byte, error) {
	// 验证调用者权限（仅验证器可调用）
	if err := c.onlyValidator(); err != nil {
		return nil, err
	}

	nodeAddrBytes, exists := c.Args["node_address"]
	if !exists || len(nodeAddrBytes) == 0 {
		return nil, fmt.Errorf("node_address is required")
	}
	nodeAddr := string(nodeAddrBytes)

	reputationDeltaStrBytes, exists := c.Args["reputation_delta"]
	if !exists || len(reputationDeltaStrBytes) == 0 {
		return nil, fmt.Errorf("reputation_delta is required")
	}
	reputationDeltaStr := string(reputationDeltaStrBytes)

	reputationDelta, err := strconv.ParseInt(reputationDeltaStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid reputation_delta: %v", err)
	}

	// 获取节点信息
	node, err := c.getNodeByAddress(nodeAddr)
	if err != nil {
		return nil, fmt.Errorf("node not found: %v", err)
	}

	// 更新声誉分数
	newReputation := int64(node.ReputationScore) + reputationDelta
	if newReputation < 0 {
		newReputation = 0
	}
	if newReputation > 1000 { // 声誉分数上限
		newReputation = 1000
	}
	node.ReputationScore = uint64(newReputation)

	// 应用声誉规则
	c.applyReputationRules(node)

	// 保存更新后的节点信息
	err = c.saveNode(*node)
	if err != nil {
		return nil, fmt.Errorf("failed to save updated node: %v", err)
	}

	// 记录声誉更新事件
	eventData := []string{nodeAddr, reputationDeltaStr, strconv.FormatUint(node.ReputationScore, 10), strconv.FormatInt(c.TxTimeStamp, 10)}
	c.EmitEvent("ReputationUpdated", eventData)

	return []byte("Reputation updated successfully"), nil
}

// slashNode 节点罚没
func (c *OrasrsStakingContract) slashNode() ([]byte, error) {
	// 仅治理委员会可调用
	if err := c.onlyGovernance(); err != nil {
		return nil, err
	}

	nodeAddrBytes, exists := c.Args["node_address"]
	if !exists || len(nodeAddrBytes) == 0 {
		return nil, fmt.Errorf("node_address is required")
	}
	nodeAddr := string(nodeAddrBytes)

	reasonBytes, exists := c.Args["reason"]
	if !exists || len(reasonBytes) == 0 {
		return nil, fmt.Errorf("reason is required")
	}
	reason := string(reasonBytes)

	// 获取节点信息
	node, err := c.getNodeByAddress(nodeAddr)
	if err != nil {
		return nil, fmt.Errorf("node not found: %v", err)
	}

	// 计算罚没金额
	penaltyAmount := (node.StakeAmount * SlashPenaltyRate) / 100
	newStakeAmount := node.StakeAmount - penaltyAmount

	// 更新节点状态和质押金额
	node.StakeAmount = newStakeAmount
	node.Status = Slashed

	// 保存更新后的节点信息
	err = c.saveNode(*node)
	if err != nil {
		return nil, fmt.Errorf("failed to save slashed node: %v", err)
	}

	// 如果是共识节点，从共识列表中移除
	if node.IsConsensusNode {
		c.removeNodeFromConsensusList(nodeAddr)
		node.IsConsensusNode = false
		// 重新保存节点信息
		c.saveNode(*node)
	}

	// 记录罚没事件
	eventData := []string{nodeAddr, strconv.FormatUint(penaltyAmount, 10), reason, strconv.FormatInt(c.TxTimeStamp, 10)}
	c.EmitEvent("NodeSlashed", eventData)

	return []byte("Node slashed successfully"), nil
}

// requestWithdrawal 申请提取质押金
func (c *OrasrsStakingContract) requestWithdrawal() ([]byte, error) {
	amountStrBytes, exists := c.Args["amount"]
	if !exists || len(amountStrBytes) == 0 {
		return nil, fmt.Errorf("amount is required")
	}
	amountStr := string(amountStrBytes)

	amount, err := strconv.ParseUint(amountStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %v", err)
	}

	// 获取申请者地址
	requester := c.Caller

	// 获取节点信息
	node, err := c.getNodeByAddress(requester)
	if err != nil {
		return nil, fmt.Errorf("node not found: %v", err)
	}

	// 检查节点状态
	if node.Status == Slashed {
		return nil, fmt.Errorf("slashed nodes cannot withdraw")
	}

	// 检查锁定期
	if c.TxTimeStamp < node.StakeStart+StakeLockPeriod {
		return nil, fmt.Errorf("lock period not ended")
	}

	// 检查质押金额是否足够
	if node.StakeAmount < amount {
		return nil, fmt.Errorf("insufficient stake amount, available: %d, requested: %d", node.StakeAmount, amount)
	}

	// 更新节点质押金额
	node.StakeAmount -= amount
	err = c.saveNode(*node)
	if err != nil {
		return nil, fmt.Errorf("failed to update node stake: %v", err)
	}

	// 记录待提取金额
	pendingKey := PendingWithdrawalKey + requester
	currentPendingBytes, _ := c.Get([]byte(pendingKey))
	var currentPending uint64
	if currentPendingBytes != nil {
		currentPending, _ = strconv.ParseUint(string(currentPendingBytes), 10, 64)
	}
	
	newPending := currentPending + amount
	err = c.Put([]byte(pendingKey), []byte(strconv.FormatUint(newPending, 10)))
	if err != nil {
		return nil, fmt.Errorf("failed to record pending withdrawal: %v", err)
	}

	// 记录申请提取事件
	eventData := []string{requester, amountStr, strconv.FormatInt(c.TxTimeStamp, 10)}
	c.EmitEvent("WithdrawalRequested", eventData)

	return []byte("Withdrawal requested successfully"), nil
}

// addValidator 添加验证器
func (c *OrasrsStakingContract) addValidator() ([]byte, error) {
	// 仅合约所有者可调用
	if err := c.onlyOwner(); err != nil {
		return nil, err
	}

	validatorAddrBytes, exists := c.Args["validator_address"]
	if !exists || len(validatorAddrBytes) == 0 {
		return nil, fmt.Errorf("validator_address is required")
	}
	validatorAddr := string(validatorAddrBytes)

	// 验证地址格式（简单检查）
	if len(validatorAddr) < 10 {
		return nil, fmt.Errorf("invalid validator address format")
	}

	// 保存验证器地址
	validatorKey := ValidatorKey + validatorAddr
	err := c.Put([]byte(validatorKey), []byte("1"))
	if err != nil {
		return nil, fmt.Errorf("failed to add validator: %v", err)
	}

	// 记录添加验证器事件
	eventData := []string{validatorAddr, strconv.FormatInt(c.TxTimeStamp, 10)}
	c.EmitEvent("ValidatorAdded", eventData)

	return []byte("Validator added successfully"), nil
}

// pauseContract 暂停合约（治理委员会功能）
func (c *OrasrsStakingContract) pauseContract() ([]byte, error) {
	// 仅治理委员会可调用
	if err := c.onlyGovernance(); err != nil {
		return nil, err
	}

	// 设置合约状态为暂停
	err := c.Put([]byte(ContractStateKey), []byte(strconv.Itoa(int(Paused))))
	if err != nil {
		return nil, fmt.Errorf("failed to pause contract: %v", err)
	}

	// 记录暂停事件
	eventData := []string{strconv.FormatInt(c.TxTimeStamp, 10)}
	c.EmitEvent("ContractPaused", eventData)

	return []byte("Contract paused successfully"), nil
}

// resumeContract 恢复合约（治理委员会功能）
func (c *OrasrsStakingContract) resumeContract() ([]byte, error) {
	// 仅治理委员会可调用
	if err := c.onlyGovernance(); err != nil {
		return nil, err
	}

	// 设置合约状态为活跃
	err := c.Put([]byte(ContractStateKey), []byte(strconv.Itoa(int(StateActive))))
	if err != nil {
		return nil, fmt.Errorf("failed to resume contract: %v", err)
	}

	// 记录恢复事件
	eventData := []string{strconv.FormatInt(c.TxTimeStamp, 10)}
	c.EmitEvent("ContractResumed", eventData)

	return []byte("Contract resumed successfully"), nil
}

// 辅助方法

// getMinStakeForNodeType 根据节点类型获取最小质押额
func (c *OrasrsStakingContract) getMinStakeForNodeType(nodeType uint8) uint64 {
	switch nodeType {
	case 0: // 根层
		return MinStakeRoot
	case 1: // 分区层
		return MinStakePartition
	default: // 边缘层
		return MinStakeEdge
	}
}

// saveNode 保存节点信息
func (c *OrasrsStakingContract) saveNode(node Node) error {
	nodeBytes, err := json.Marshal(node)
	if err != nil {
		return fmt.Errorf("failed to marshal node: %v", err)
	}

	// 保存节点信息
	nodeKey := NodeKeyPrefix + node.NodeAddress
	err = c.Put([]byte(nodeKey), nodeBytes)
	if err != nil {
		return fmt.Errorf("failed to save node: %v", err)
	}

	// 保存节点ID到地址的映射
	idToAddrKey := NodeIdToAddressKey + node.NodeId
	err = c.Put([]byte(idToAddrKey), []byte(node.NodeAddress))
	if err != nil {
		return fmt.Errorf("failed to save node id mapping: %v", err)
	}

	return nil
}

// getNodeByAddress 根据地址获取节点
func (c *OrasrsStakingContract) getNodeByAddress(nodeAddr string) (*Node, error) {
	nodeKey := NodeKeyPrefix + nodeAddr
	nodeBytes, err := c.Get([]byte(nodeKey))
	if err != nil {
		return nil, fmt.Errorf("node not found for address %s: %v", nodeAddr, err)
	}

	var node Node
	err = json.Unmarshal(nodeBytes, &node)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal node: %v", err)
	}

	return &node, nil
}

// getNodeAddressById 根据节点ID获取地址
func (c *OrasrsStakingContract) getNodeAddressById(nodeId string) (string, error) {
	idToAddrKey := NodeIdToAddressKey + nodeId
	addrBytes, err := c.Get([]byte(idToAddrKey))
	if err != nil {
		return "", fmt.Errorf("node id not found: %v", err)
	}

	return string(addrBytes), nil
}

// verifySM2Signature 验证SM2签名（在实际部署时替换为长安链内置函数）
func (c *OrasrsStakingContract) verifySM2Signature(signature, dataHash []byte, publicKey string) (bool, error) {
	// 在实际实现中，这将调用长安链的内置SM2验证函数
	// 这里是概念性实现
	fmt.Printf("Verifying SM2 signature for public key: %s\n", publicKey)
	
	// 模拟验证（仅用于演示）
	// 在实际部署中，应使用长安链提供的国密验证功能
	return true, nil
}

// isNonceUsed 检查nonce是否已被使用
func (c *OrasrsStakingContract) isNonceUsed(nonceHash []byte) bool {
	key := UsedNonceKey + string(nonceHash)
	_, err := c.Get([]byte(key))
	return err == nil
}

// setNonceUsed 设置nonce为已使用
func (c *OrasrsStakingContract) setNonceUsed(nonceHash []byte) error {
	key := UsedNonceKey + string(nonceHash)
	return c.Put([]byte(key), []byte("used"))
}

// getContractState 获取合约状态
func (c *OrasrsStakingContract) getContractState() (ContractState, error) {
	stateBytes, err := c.Get([]byte(ContractStateKey))
	if err != nil {
		return 0, fmt.Errorf("failed to get contract state: %v", err)
	}

	stateInt, err := strconv.Atoi(string(stateBytes))
	if err != nil {
		return 0, fmt.Errorf("invalid contract state: %v", err)
	}

	return ContractState(stateInt), nil
}

// onlyOwner 仅合约所有者可调用的验证
func (c *OrasrsStakingContract) onlyOwner() error {
	caller := c.Caller

	ownerBytes, err := c.Get([]byte(OwnerKey))
	if err != nil {
		return fmt.Errorf("failed to get owner address: %v", err)
	}

	ownerAddr := string(ownerBytes)
	if caller != ownerAddr {
		return fmt.Errorf("only owner can call this function, caller: %s, owner: %s", caller, ownerAddr)
	}

	return nil
}

// onlyGovernance 仅治理地址可调用的验证
func (c *OrasrsStakingContract) onlyGovernance() error {
	caller := c.Caller

	governanceBytes, err := c.Get([]byte(GovernanceKey))
	if err != nil {
		return fmt.Errorf("failed to get governance address: %v", err)
	}

	governanceAddr := string(governanceBytes)
	if caller != governanceAddr {
		return fmt.Errorf("only governance can call this function, caller: %s, governance: %s", caller, governanceAddr)
	}

	return nil
}

// onlyValidator 仅验证器可调用的验证
func (c *OrasrsStakingContract) onlyValidator() error {
	caller := c.Caller

	validatorKey := ValidatorKey + caller
	validatorBytes, err := c.Get([]byte(validatorKey))
	if err != nil || string(validatorBytes) != "1" {
		return fmt.Errorf("only authorized validators can call this function, caller: %s", caller)
	}

	return nil
}

// addNodeToConsensusList 添加节点到共识列表
func (c *OrasrsStakingContract) addNodeToConsensusList(nodeAddr string) error {
	consensusNodesBytes, err := c.Get([]byte(ConsensusNodesKey))
	if err != nil {
		return fmt.Errorf("failed to get consensus nodes: %v", err)
	}

	var consensusNodes []string
	err = json.Unmarshal(consensusNodesBytes, &consensusNodes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal consensus nodes: %v", err)
	}

	// 检查是否已达到最大共识节点数
	if len(consensusNodes) >= MaxConsensusNodes {
		return fmt.Errorf("max consensus nodes reached: %d", MaxConsensusNodes)
	}

	// 检查节点是否已在列表中
	for _, addr := range consensusNodes {
		if addr == nodeAddr {
			return fmt.Errorf("node already in consensus list: %s", nodeAddr)
		}
	}

	// 添加节点
	consensusNodes = append(consensusNodes, nodeAddr)

	// 保存更新后的列表
	updatedBytes, err := json.Marshal(consensusNodes)
	if err != nil {
		return fmt.Errorf("failed to marshal consensus nodes: %v", err)
	}

	return c.Put([]byte(ConsensusNodesKey), updatedBytes)
}

// addNodeToPartitionList 添加节点到分区列表
func (c *OrasrsStakingContract) addNodeToPartitionList(nodeAddr string) error {
	partitionNodesBytes, err := c.Get([]byte(PartitionNodesKey))
	if err != nil {
		return fmt.Errorf("failed to get partition nodes: %v", err)
	}

	var partitionNodes []string
	err = json.Unmarshal(partitionNodesBytes, &partitionNodes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal partition nodes: %v", err)
	}

	// 检查节点是否已在列表中
	for _, addr := range partitionNodes {
		if addr == nodeAddr {
			return fmt.Errorf("node already in partition list: %s", nodeAddr)
		}
	}

	// 添加节点
	partitionNodes = append(partitionNodes, nodeAddr)

	// 保存更新后的列表
	updatedBytes, err := json.Marshal(partitionNodes)
	if err != nil {
		return fmt.Errorf("failed to marshal partition nodes: %v", err)
	}

	return c.Put([]byte(PartitionNodesKey), updatedBytes)
}

// addNodeToEdgeList 添加节点到边缘列表
func (c *OrasrsStakingContract) addNodeToEdgeList(nodeAddr string) error {
	edgeNodesBytes, err := c.Get([]byte(EdgeNodesKey))
	if err != nil {
		return fmt.Errorf("failed to get edge nodes: %v", err)
	}

	var edgeNodes []string
	err = json.Unmarshal(edgeNodesBytes, &edgeNodes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal edge nodes: %v", err)
	}

	// 检查节点是否已在列表中
	for _, addr := range edgeNodes {
		if addr == nodeAddr {
			return fmt.Errorf("node already in edge list: %s", nodeAddr)
		}
	}

	// 添加节点
	edgeNodes = append(edgeNodes, nodeAddr)

	// 保存更新后的列表
	updatedBytes, err := json.Marshal(edgeNodes)
	if err != nil {
		return fmt.Errorf("failed to marshal edge nodes: %v", err)
	}

	return c.Put([]byte(EdgeNodesKey), updatedBytes)
}

// removeNodeFromConsensusList 从共识列表移除节点
func (c *OrasrsStakingContract) removeNodeFromConsensusList(nodeAddr string) error {
	consensusNodesBytes, err := c.Get([]byte(ConsensusNodesKey))
	if err != nil {
		return fmt.Errorf("failed to get consensus nodes: %v", err)
	}

	var consensusNodes []string
	err = json.Unmarshal(consensusNodesBytes, &consensusNodes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal consensus nodes: %v", err)
	}

	// 查找并移除节点
	updatedNodes := make([]string, 0)
	for _, addr := range consensusNodes {
		if addr != nodeAddr {
			updatedNodes = append(updatedNodes, addr)
		}
	}

	// 保存更新后的列表
	updatedBytes, err := json.Marshal(updatedNodes)
	if err != nil {
		return fmt.Errorf("failed to marshal consensus nodes: %v", err)
	}

	return c.Put([]byte(ConsensusNodesKey), updatedBytes)
}

// validateBusinessLicense 验证营业执照号格式
func (c *OrasrsStakingContract) validateBusinessLicense(licenseHash string) bool {
	// 验证哈希格式（简单长度验证）
	return len(licenseHash) >= 10
}

// validateFilingNumber 验证备案号格式
func (c *OrasrsStakingContract) validateFilingNumber(filingHash string) bool {
	// 验证哈希格式（简单长度验证）
	return len(filingHash) >= 10
}

// applyReputationRules 应用声誉规则
func (c *OrasrsStakingContract) applyReputationRules(node *Node) {
	if node.ReputationScore < 80 {
		// 声誉 < 80，如果是共识节点则移出共识节点
		if node.IsConsensusNode {
			node.IsConsensusNode = false
			// 在实际实现中，还需要从共识列表中移除节点
		}
	} else if node.ReputationScore > 120 {
		// 声誉 > 120，可以考虑给予奖励或特权
		// 实现细节根据具体需求
	}
}
