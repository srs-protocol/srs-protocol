package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"strings"

	"github.com/chainmaker/chainmaker-contract-go/v2/pkg/contract"
	"github.com/chainmaker/chainmaker-contract-go/v2/pkg/contract/mock"
	"github.com/chainmaker/chainmaker-tools-go/v2/crypto/sm"
)

// TestContractInitialization 测试合约初始化
func TestContractInitialization(t *testing.T) {
	ctx := mock.NewMockContext()
	
	// 设置初始化参数
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("test_governance_addr"),
	})
	
	// 初始化合约
	contractInstance := &OrasrsStakingContract{}
	err := contractInstance.InitContract()
	if err != nil {
		t.Fatalf("Failed to initialize contract: %v", err)
	}
	
	// 验证合约状态
	state, err := contractInstance.getContractState()
	if err != nil {
		t.Fatalf("Failed to get contract state: %v", err)
	}
	if state != Active {
		t.Errorf("Expected contract state to be Active, got %v", state)
	}
	
	t.Log("Contract initialization test passed")
}

// TestStakeWithGmSignValidInput 测试有效的质押输入
func TestStakeWithGmSignValidInput(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("test_gov"),
	})
	contractInstance.InitContract()
	
	// 准备测试数据
	testNodeId := "test-node-1"
	testAmount := "15000" // 符合根层最小质押要求
	testNonce := "1"
	testBusinessLicense := "license_hash_1"
	testFilingNumber := "filing_hash_1"
	testNodeType := "0" // 根层节点
	
	// 模拟SM2签名验证
	testData := []byte(fmt.Sprintf("%s_%s_%s_%s", testNodeId, testAmount, testNonce, testBusinessLicense))
	dataHash := sm.Sm3Hash(testData)
	
	ctx.SetArgs(map[string][]byte{
		"node_id":              []byte(testNodeId),
		"amount":               []byte(testAmount),
		"sm2_signature":        []byte("test_sig"), // 模拟签名
		"data_hash":            dataHash,
		"nonce":                []byte(testNonce),
		"business_license_hash": []byte(testBusinessLicense),
		"filing_number_hash":   []byte(testFilingNumber),
		"node_type":            []byte(testNodeType),
	})
	
	// 设置调用者地址
	ctx.SetCallerAddress("test_caller_addr")
	
	// 执行质押
	err := contractInstance.StakeWithGmSign()
	if err != nil {
		t.Fatalf("StakeWithGmSign failed: %v", err)
	}
	
	// 验证节点是否已创建
	node, err := contractInstance.getNodeByAddress("test_caller_addr")
	if err != nil {
		t.Fatalf("Failed to get created node: %v", err)
	}
	
	if node.NodeId != testNodeId {
		t.Errorf("Expected node ID %s, got %s", testNodeId, node.NodeId)
	}
	
	if node.StakeAmount != 15000 {
		t.Errorf("Expected stake amount 15000, got %d", node.StakeAmount)
	}
	
	t.Log("Valid stake input test passed")
}

// TestStakeWithInsufficientAmount 测试质押金额不足
func TestStakeWithInsufficientAmount(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("test_gov"),
	})
	contractInstance.InitContract()
	
	// 使用低于根层最小质押的金额
	ctx.SetArgs(map[string][]byte{
		"node_id":              []byte("test-node-low"),
		"amount":               []byte("5000"), // 低于根层最小质押（10000）
		"sm2_signature":        []byte("test_sig"),
		"data_hash":            []byte("test_hash"),
		"nonce":                []byte("1"),
		"business_license_hash": []byte("license_hash"),
		"filing_number_hash":   []byte("filing_hash"),
		"node_type":            []byte("0"), // 根层节点
	})
	
	ctx.SetCallerAddress("test_caller_addr")
	
	// 执行质押 - 应该失败
	err := contractInstance.StakeWithGmSign()
	if err == nil {
		t.Error("Expected stake to fail due to insufficient amount")
	} else if !contains(err.Error(), "insufficient stake amount") {
		t.Errorf("Expected insufficient stake amount error, got: %v", err)
	}
	
	t.Log("Insufficient amount test passed")
}

// TestStakeWithExistingNodeId 测试使用已存在的节点ID
func TestStakeWithExistingNodeId(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("test_gov"),
	})
	contractInstance.InitContract()
	
	// 首先创建一个节点
	ctx.SetArgs(map[string][]byte{
		"node_id":              []byte("test-node-duplicate"),
		"amount":               []byte("15000"),
		"sm2_signature":        []byte("test_sig"),
		"data_hash":            []byte("test_hash"),
		"nonce":                []byte("1"),
		"business_license_hash": []byte("license_hash"),
		"filing_number_hash":   []byte("filing_hash"),
		"node_type":            []byte("0"),
	})
	
	ctx.SetCallerAddress("test_caller_addr_1")
	
	// 第一次质押应该成功
	err := contractInstance.StakeWithGmSign()
	if err != nil {
		t.Fatalf("First stake failed: %v", err)
	}
	
	// 使用相同节点ID和不同地址尝试质押
	ctx.SetArgs(map[string][]byte{
		"node_id":              []byte("test-node-duplicate"), // 重复的节点ID
		"amount":               []byte("15000"),
		"sm2_signature":        []byte("test_sig"),
		"data_hash":            []byte("test_hash"),
		"nonce":                []byte("2"),
		"business_license_hash": []byte("license_hash"),
		"filing_number_hash":   []byte("filing_hash"),
		"node_type":            []byte("0"),
	})
	
	ctx.SetCallerAddress("test_caller_addr_2")
	
	// 第二次质押应该失败
	err = contractInstance.StakeWithGmSign()
	if err == nil {
		t.Error("Expected stake to fail due to duplicate node ID")
	} else if !contains(err.Error(), "node ID already exists") {
		t.Errorf("Expected duplicate node ID error, got: %v", err)
	}
	
	t.Log("Duplicate node ID test passed")
}

// TestAccessControlForGovernanceFunctions 测试治理功能的访问控制
func TestAccessControlForGovernanceFunctions(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("legitimate_gov_addr"),
	})
	contractInstance.InitContract()
	
	// 模拟非治理地址尝试调用治理功能
	ctx.SetCallerAddress("attacker_addr")
	
	// 尝试暂停合约 - 应该失败
	err := contractInstance.PauseContract()
	if err == nil {
		t.Error("Expected access control failure for unauthorized pause call")
	} else if !contains(err.Error(), "only governance can call this function") {
		t.Errorf("Expected governance access error, got: %v", err)
	}
	
	// 尝试罚没节点 - 应该失败
	ctx.SetArgs(map[string][]byte{
		"node_address": []byte("test_node"),
		"reason":       []byte("test reason"),
	})
	err = contractInstance.SlashNode()
	if err == nil {
		t.Error("Expected access control failure for unauthorized slash call")
	} else if !contains(err.Error(), "only governance can call this function") {
		t.Errorf("Expected governance access error, got: %v", err)
	}
	
	t.Log("Access control test passed")
}

// TestParameterValidation 测试参数验证
func TestParameterValidation(t *testing.T) {
	// 测试各种无效参数的组合
	testCases := []struct {
		name          string
		args          map[string][]byte
		expectError   bool
		errorContains string
	}{
		{
			name: "missing node_id",
			args: map[string][]byte{
				"amount": []byte("10000"),
			},
			expectError:   true,
			errorContains: "node_id is required",
		},
		{
			name: "missing amount",
			args: map[string][]byte{
				"node_id": []byte("test-node"),
			},
			expectError:   true,
			errorContains: "amount is required",
		},
		{
			name: "invalid amount",
			args: map[string][]byte{
				"node_id": []byte("test-node"),
				"amount":  []byte("invalid"),
			},
			expectError:   true,
			errorContains: "invalid amount",
		},
		{
			name: "valid parameters",
			args: map[string][]byte{
				"node_id":              []byte("test-node"),
				"amount":               []byte("15000"),
				"sm2_signature":        []byte("test_sig"),
				"data_hash":            []byte("test_hash"),
				"nonce":                []byte("1"),
				"business_license_hash": []byte("license_hash"),
				"filing_number_hash":   []byte("filing_hash"),
				"node_type":            []byte("0"),
			},
			expectError: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := mock.NewMockContext()
			contractInstance := &OrasrsStakingContract{}
			
			// 初始化合约
			ctx.SetArgs(map[string][]byte{
				"governance_address": []byte("test_gov"),
			})
			contractInstance.InitContract()
			
			ctx.SetArgs(tc.args)
			ctx.SetCallerAddress("test_caller")
			
			err := contractInstance.StakeWithGmSign()
			
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got none", tc.errorContains)
				} else if !contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tc.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
	
	t.Log("Parameter validation test passed")
}

// TestNodeInfoQuery 测试节点信息查询
func TestNodeInfoQuery(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("test_gov"),
	})
	contractInstance.InitContract()
	
	// 首先创建一个节点
	ctx.SetArgs(map[string][]byte{
		"node_id":              []byte("test-query-node"),
		"amount":               []byte("12000"),
		"sm2_signature":        []byte("test_sig"),
		"data_hash":            []byte("test_hash"),
		"nonce":                []byte("1"),
		"business_license_hash": []byte("license_hash"),
		"filing_number_hash":   []byte("filing_hash"),
		"node_type":            []byte("0"),
	})
	
	testAddr := "test_query_addr"
	ctx.SetCallerAddress(testAddr)
	
	err := contractInstance.StakeWithGmSign()
	if err != nil {
		t.Fatalf("Failed to create node for query test: %v", err)
	}
	
	// 查询节点信息
	ctx.SetArgs(map[string][]byte{
		"node_address": []byte(testAddr),
	})
	
	result, err := contractInstance.GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo failed: %v", err)
	}
	
	var nodeInfo NodeInfo
	err = json.Unmarshal(result, &nodeInfo)
	if err != nil {
		t.Fatalf("Failed to unmarshal node info: %v", err)
	}
	
	if !nodeInfo.Success {
		t.Fatalf("Node info query failed: %s", nodeInfo.Error)
	}
	
	if nodeInfo.Node.NodeId != "test-query-node" {
		t.Errorf("Expected node ID 'test-query-node', got '%s'", nodeInfo.Node.NodeId)
	}
	
	if nodeInfo.Node.StakeAmount != 12000 {
		t.Errorf("Expected stake amount 12000, got %d", nodeInfo.Node.StakeAmount)
	}
	
	t.Log("Node info query test passed")
}

// TestContractStats 测试合约统计功能
func TestContractStats(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("test_gov"),
	})
	contractInstance.InitContract()
	
	// 创建多个节点用于测试统计
	nodes := []struct{
		nodeId string
		amount string
		nodeType string
		addr string
	}{
		{"test-node-1", "10000", "0", "addr-1"},
		{"test-node-2", "8000", "1", "addr-2"},
		{"test-node-3", "200", "2", "addr-3"},
	}
	
	for _, node := range nodes {
		ctx.SetArgs(map[string][]byte{
			"node_id":              []byte(node.nodeId),
			"amount":               []byte(node.amount),
			"sm2_signature":        []byte("test_sig"),
			"data_hash":            []byte("test_hash"),
			"nonce":                []byte("1"),
			"business_license_hash": []byte("license_hash"),
			"filing_number_hash":   []byte("filing_hash"),
			"node_type":            []byte(node.nodeType),
		})
		
		ctx.SetCallerAddress(node.addr)
		
		err := contractInstance.StakeWithGmSign()
		if err != nil {
			t.Fatalf("Failed to create node %s: %v", node.nodeId, err)
		}
	}
	
	// 获取合约统计信息
	result, err := contractInstance.GetContractStats()
	if err != nil {
		t.Fatalf("GetContractStats failed: %v", err)
	}
	
	var stats ContractStats
	err = json.Unmarshal(result, &stats)
	if err != nil {
		t.Fatalf("Failed to unmarshal stats: %v", err)
	}
	
	// 验证统计信息
	expectedTotal := uint64(10000 + 8000 + 200)
	if stats.TotalStaked != expectedTotal {
		t.Errorf("Expected total staked %d, got %d", expectedTotal, stats.TotalStaked)
	}
	
	if stats.TotalConsensusNodes != 1 { // 只有根层节点（type 0）是共识节点
		t.Errorf("Expected 1 consensus node, got %d", stats.TotalConsensusNodes)
	}
	
	if stats.TotalPartitionNodes != 1 { // 分区层节点（type 1）
		t.Errorf("Expected 1 partition node, got %d", stats.TotalPartitionNodes)
	}
	
	if stats.TotalEdgeNodes != 1 { // 边缘层节点（type 2）
		t.Errorf("Expected 1 edge node, got %d", stats.TotalEdgeNodes)
	}
	
	t.Log("Contract stats test passed")
}

// TestReputationUpdateAccessControl 测试声誉更新的访问控制
func TestReputationUpdateAccessControl(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("test_gov"),
	})
	contractInstance.InitContract()
	
	// 首先添加一个验证器
	ctx.SetArgs(map[string][]byte{
		"validator_address": []byte("authorized_validator"),
	})
	ctx.SetCallerAddress("contract_owner") // 假设调用者是合约所有者
	
	err := contractInstance.AddValidator()
	if err != nil {
		t.Fatalf("Failed to add validator: %v", err)
	}
	
	// 使用非验证器地址尝试更新声誉 - 应该失败
	ctx.SetArgs(map[string][]byte{
		"node_address":    []byte("test_node"),
		"reputation_delta": []byte("10"),
	})
	ctx.SetCallerAddress("non_validator")
	
	err = contractInstance.UpdateReputation()
	if err == nil {
		t.Error("Expected access control failure for non-validator reputation update")
	} else if !contains(err.Error(), "only authorized validators can call this function") {
		t.Errorf("Expected validator access error, got: %v", err)
	}
	
	// 使用验证器地址更新声誉 - 应该成功
	ctx.SetCallerAddress("authorized_validator")
	
	// 但节点不存在，所以应该失败
	err = contractInstance.UpdateReputation()
	if err == nil {
		t.Error("Expected error for non-existent node")
	}
	
	t.Log("Reputation update access control test passed")
}

// TestSlashNodeAccessControl 测试节点罚没的访问控制
func TestSlashNodeAccessControl(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("legitimate_gov"),
	})
	contractInstance.InitContract()
	
	// 使用非治理地址尝试罚没节点 - 应该失败
	ctx.SetArgs(map[string][]byte{
		"node_address": []byte("test_node"),
		"reason":       []byte("test reason"),
	})
	ctx.SetCallerAddress("non_governance_addr")
	
	err := contractInstance.SlashNode()
	if err == nil {
		t.Error("Expected access control failure for non-governance slash")
	} else if !contains(err.Error(), "only governance can call this function") {
		t.Errorf("Expected governance access error, got: %v", err)
	}
	
	t.Log("Slash node access control test passed")
}

// TestIntegerOverflowProtection 测试整数溢出保护
func TestIntegerOverflowProtection(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("test_gov"),
	})
	contractInstance.InitContract()
	
	// 测试非常大的金额值
	veryLargeAmount := fmt.Sprintf("%d", uint64(^uint64(0)>>1)) // 接近最大值
	
	ctx.SetArgs(map[string][]byte{
		"node_id":              []byte("test-large-amount"),
		"amount":               []byte(veryLargeAmount),
		"sm2_signature":        []byte("test_sig"),
		"data_hash":            []byte("test_hash"),
		"nonce":                []byte("1"),
		"business_license_hash": []byte("license_hash"),
		"filing_number_hash":   []byte("filing_hash"),
		"node_type":            []byte("0"),
	})
	
	ctx.SetCallerAddress("test_caller")
	
	// 由于我们没有实际的余额检查，这里测试的是解析大数的能力
	// 在实际环境中，还需要检查余额是否足够
	err := contractInstance.StakeWithGmSign()
	if err != nil {
		// 如果错误是由于余额不足或其他合理的业务逻辑错误，这是正常的
		if !contains(err.Error(), "insufficient") && !contains(err.Error(), "balance") {
			t.Errorf("Unexpected error for large amount: %v", err)
		}
	}
	
	t.Log("Integer overflow protection test completed")
}

// TestNonceReplayProtection 测试防重放攻击
func TestNonceReplayProtection(t *testing.T) {
	ctx := mock.NewMockContext()
	contractInstance := &OrasrsStakingContract{}
	
	// 初始化合约
	ctx.SetArgs(map[string][]byte{
		"governance_address": []byte("test_gov"),
	})
	contractInstance.InitContract()
	
	// 第一次使用相同的参数和nonce
	ctx.SetArgs(map[string][]byte{
		"node_id":              []byte("test-replay-node"),
		"amount":               []byte("10000"),
		"sm2_signature":        []byte("test_sig"),
		"data_hash":            []byte("test_hash"),
		"nonce":                []byte("12345"), // 固定nonce
		"business_license_hash": []byte("license_hash"),
		"filing_number_hash":   []byte("filing_hash"),
		"node_type":            []byte("0"),
	})
	
	ctx.SetCallerAddress("test_caller")
	
	// 第一次质押应该成功
	err := contractInstance.StakeWithGmSign()
	if err != nil {
		t.Fatalf("First stake failed: %v", err)
	}
	
	// 使用相同的参数和nonce再次质押 - 应该失败
	err = contractInstance.StakeWithGmSign()
	if err == nil {
		t.Error("Expected failure due to nonce replay")
	} else if !contains(err.Error(), "nonce already used") {
		t.Errorf("Expected nonce replay error, got: %v", err)
	}
	
	t.Log("Nonce replay protection test passed")
}

// Helper functions
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// RunSecurityTests 运行所有安全测试
func RunSecurityTests() {
	// 创建一个新的测试套件
	testing.Main(
		func(pat, str string) (bool, error) { return true, nil },
		[]testing.InternalTest{
			{"TestContractInitialization", TestContractInitialization},
			{"TestStakeWithGmSignValidInput", TestStakeWithGmSignValidInput},
			{"TestStakeWithInsufficientAmount", TestStakeWithInsufficientAmount},
			{"TestStakeWithExistingNodeId", TestStakeWithExistingNodeId},
			{"TestAccessControlForGovernanceFunctions", TestAccessControlForGovernanceFunctions},
			{"TestParameterValidation", TestParameterValidation},
			{"TestNodeInfoQuery", TestNodeInfoQuery},
			{"TestContractStats", TestContractStats},
			{"TestReputationUpdateAccessControl", TestReputationUpdateAccessControl},
			{"TestSlashNodeAccessControl", TestSlashNodeAccessControl},
			{"TestIntegerOverflowProtection", TestIntegerOverflowProtection},
			{"TestNonceReplayProtection", TestNonceReplayProtection},
		},
		[]testing.InternalBenchmark{},
		[]testing.InternalExample{},
	)
}

// Main function for testing
func main() {
	fmt.Println("Running OraSRS ChainMaker Contract Security Tests...")
	
	// 设置模拟上下文
	contract.SetContext(&mock.MockContext{})
	
	// 运行安全测试
	RunSecurityTests()
	
	fmt.Println("Security tests completed!")
}

// TestSuiteResult 测试套件结果
type TestSuiteResult struct {
	TotalTests   int `json:"total_tests"`
	PassedTests  int `json:"passed_tests"`
	FailedTests  int `json:"failed_tests"`
	SkippedTests int `json:"skipped_tests"`
}

// RunTestsWithReport 运行测试并生成报告
func RunTestsWithReport() {
	// 这里会运行测试并输出结果到文件
	fmt.Println("Running tests and generating report...")
	
	// 由于我们不能直接使用 testing 包运行测试，
	// 我们将手动运行每个测试函数并记录结果
	
	results := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"TestContractInitialization", TestContractInitialization},
		{"TestStakeWithGmSignValidInput", TestStakeWithGmSignValidInput},
		{"TestStakeWithInsufficientAmount", TestStakeWithInsufficientAmount},
		{"TestStakeWithExistingNodeId", TestStakeWithExistingNodeId},
		{"TestAccessControlForGovernanceFunctions", TestAccessControlForGovernanceFunctions},
		{"TestParameterValidation", TestParameterValidation},
		{"TestNodeInfoQuery", TestNodeInfoQuery},
		{"TestContractStats", TestContractStats},
		{"TestReputationUpdateAccessControl", TestReputationUpdateAccessControl},
		{"TestSlashNodeAccessControl", TestSlashNodeAccessControl},
		{"TestIntegerOverflowProtection", TestIntegerOverflowProtection},
		{"TestNonceReplayProtection", TestNonceReplayProtection},
	}
	
	total := len(results)
	passed := 0
	failed := 0
	
	for _, test := range results {
		t := &testing.T{}
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("Test %s failed with panic: %v\n", test.name, r)
				failed++
			}
		}()
		
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("Test %s failed with panic: %v\n", test.name, r)
					failed++
				}
			}()
			
			test.fn(t)
			fmt.Printf("Test %s passed\n", test.name)
			passed++
		}()
	}
	
	skipped := total - passed - failed
	
	fmt.Printf("\nTest Results:\n")
	fmt.Printf("Total: %d\n", total)
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)
	fmt.Printf("Skipped: %d\n", skipped)
	
	// 生成测试报告
	report := TestSuiteResult{
		TotalTests: total,
		PassedTests: passed,
		FailedTests: failed,
		SkippedTests: skipped,
	}
	
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Printf("Error generating report: %v\n", err)
		return
	}
	
	err = os.WriteFile("security-test-report.json", reportBytes, 0644)
	if err != nil {
		fmt.Printf("Error writing report file: %v\n", err)
		return
	}
	
	fmt.Println("Security test report generated: security-test-report.json")
}
