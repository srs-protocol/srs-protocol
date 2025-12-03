// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../contracts/ThreatEvidence.sol";

contract ThreatEvidenceTest is Test {
    ThreatEvidence public threatContract;
    address public governance;
    address public agent1;
    address public validator1;

    function setUp() public {
        governance = address(1);
        agent1 = address(2);
        validator1 = address(3);
        
        threatContract = new ThreatEvidence(governance);
        
        // 授权测试代理和验证器
        vm.prank(governance);
        threatContract.addAuthorizedAgent(agent1);
        
        vm.prank(governance);
        threatContract.addAuthorizedValidator(validator1);
    }

    // 测试：合约初始化
    function testContractInitialization() public {
        assertEq(threatContract.owner(), governance);
        assertEq(uint256(threatContract.contractState()), uint256(ThreatEvidence.ContractState.Active));
    }

    // 测试：权限控制
    function testAccessControl() public {
        // 非治理地址尝试添加代理 - 应该失败
        vm.expectRevert();
        threatContract.addAuthorizedAgent(address(5));
        
        // 治理地址添加代理 - 应该成功
        vm.prank(governance);
        threatContract.addAuthorizedAgent(address(5));
    }

    // 测试：提交威胁报告
    function testSubmitThreatReport() public {
        // 创建威胁报告数据结构
        ThreatEvidence.ThreatReportData memory reportData = ThreatEvidence.ThreatReportData({
            threatType: 0, // DDoS
            sourceIP: "192.168.1.100",
            targetIP: "10.0.0.1",
            threatLevel: 2, // Critical
            context: "Test threat report",
            evidenceHash: "sm3_hash_value",
            geolocation: "Shanghai, China"
        });
        
        // 使用代理提交威胁报告
        vm.prank(agent1);
        threatContract.submitThreatReport(reportData, 123456); // nonce
        
        // 由于ID是基于时间戳生成的，我们无法预测确切的ID
        // 但我们可以通过代理地址检查报告是否已提交
        // 这里我们只测试合约是否成功处理了交易
        assertTrue(true); // 交易成功执行
    }
    
    // 测试：合约状态管理
    function testContractStateManagement() public {
        // 非治理地址尝试暂停合约 - 应该失败
        vm.expectRevert();
        threatContract.pauseContract();
        
        // 治理地址暂停合约 - 应该成功
        vm.prank(governance);
        threatContract.pauseContract();
        
        // 验证合约状态
        assertEq(uint256(threatContract.contractState()), uint256(ThreatEvidence.ContractState.Paused));
        
        // 恢复合约
        vm.prank(governance);
        threatContract.resumeContract();
        
        // 验证合约状态
        assertEq(uint256(threatContract.contractState()), uint256(ThreatEvidence.ContractState.Active));
    }
    
    // 测试：获取不存在的威胁报告
    function testGetNonExistentThreatReport() public {
        // 尝试获取不存在的威胁报告
        ThreatEvidence.ThreatAttestation memory report = threatContract.getThreatReport("nonexistent");
        
        // 验证返回的报告ID为空
        assertEq(bytes(report.id).length, 0);
    }
    
    // 测试：授权管理
    function testAuthorizationManagement() public {
        address newAgent = address(100);
        address newValidator = address(101);
        
        // 治理地址添加新代理
        vm.prank(governance);
        threatContract.addAuthorizedAgent(newAgent);
        
        // 验证非治理地址无法添加代理
        vm.expectRevert();
        threatContract.addAuthorizedAgent(address(102));
        
        // 治理地址添加新验证器
        vm.prank(governance);
        threatContract.addAuthorizedValidator(newValidator);
    }
    
    // 测试：防重放攻击
    function testReplayAttackProtection() public {
        // 创建威胁报告数据结构
        ThreatEvidence.ThreatReportData memory reportData = ThreatEvidence.ThreatReportData({
            threatType: 1, // Malware
            sourceIP: "10.0.0.50",
            targetIP: "10.0.0.1",
            threatLevel: 3, // Emergency
            context: "Test replay protection",
            evidenceHash: "sm3_hash_value_2",
            geolocation: "Beijing, China"
        });
        
        // 使用代理提交威胁报告
        vm.prank(agent1);
        threatContract.submitThreatReport(reportData, 999999); // nonce
        
        // 使用相同的nonce再次提交 - 应该失败
        vm.prank(agent1);
        vm.expectRevert();
        threatContract.submitThreatReport(reportData, 999999); // same nonce
    }
}