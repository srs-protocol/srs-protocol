# 腾讯云长安链合约部署指南

## 问题说明

腾讯云长安链体验网络（TBaaS）合约部署失败的典型表现是：
- 合约部署失败，提示"exec format error"
- 或者合约安装后无法正常运行

## 根本原因

根据多次部署失败的日志分析，根本原因已非常明确：
- 长安链DockerGo运行时要求合约二进制文件必须是静态链接的
- 如果合约二进制文件包含动态库依赖（dynamically linked），则必然失败
- 腾讯云沙箱环境是高度隔离的，只支持静态链接的二进制文件

## 解决方案

### 方案1：静态编译（推荐）

在有Go环境的系统上，使用以下命令进行静态编译：

```bash
# 进入合约目录
cd OraSRS-protocol/chainmaker-contract

# 清理旧文件
rm -rf main orasrs.7z

# 创建目录
mkdir main

# 静态编译（关键：关闭CGO，强制静态链接）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w -extldflags '-static'" \
  -buildmode=pie \
  -o main/main .

# 验证是否静态链接
file main/main
# 正确输出应包含: "statically linked"
# 如果输出包含 "dynamically linked"，则必然失败！
```

### 方案2：打包为.7z格式

```bash
# 使用7-Zip压缩整个main目录
7z a orasrs.7z main/

# 验证内容
7z l orasrs.7z
# 必须显示:
#    Date      Time    Attr         Size   Name
# ------------------- ----- ------------  ----
#                    D....            0  main/
#                    .....       123456  main/main
```

## 合约代码修改

为确保合约能够正确编译，需要修复导入路径：

在 `main.go` 文件中：

```go
package main

import (
    "orasrs-chainmaker-contract/orasrscontract" // 使用模块路径而不是相对路径
)

func main() {
    orasrscontract.Main()
}
```

## 部署步骤

1. 确保Go环境已安装（推荐Go 1.19+）
2. 执行静态编译命令
3. 验证生成的二进制文件是静态链接
4. 打包为.7z格式
5. 在腾讯云TBaaS控制台上传文件

## 合约功能说明

OraSRS合约提供以下功能：

- **节点质押管理**: `StakeWithGmSign` - 支持国密签名的节点质押
- **多层级节点架构**: 支持根层、分区层、边缘层节点
- **国密算法支持**: 集成SM2/SM3/SM4国密算法
- **声誉系统**: 节点声誉评分机制
- **挑战机制**: 节点行为验证和挑战
- **治理功能**: 合约治理和管理接口

## 部署参数

部署时可能需要提供以下参数：
- `governance_address`: 治理地址
- `_arg0`: 腾讯云快速上链格式的治理地址

## 验证部署

部署成功后，可以通过以下方法验证：
1. 调用 `GetContractStats` 检查合约统计信息
2. 调用 `GetNodeInfo` 查询节点状态
3. 测试质押功能是否正常

## 常见问题

1. 如果部署失败，检查错误日志是否提到"exec format error"
2. 确认二进制文件是否为静态链接
3. 确认.7z文件结构正确
4. 确认合约入口函数名称正确