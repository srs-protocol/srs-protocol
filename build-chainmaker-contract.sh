#!/bin/bash

# 腾讯云长安链合约静态编译脚本
# 用于生成腾讯云TBaaS网络兼容的静态链接合约

set -e  # 遇到错误时退出

echo "开始构建腾讯云长安链兼容合约..."

# 检查是否安装了必要的工具
if ! command -v go &> /dev/null; then
    echo "错误: 未找到Go工具，请先安装Go"
    exit 1
fi

if ! command -v 7z &> /dev/null; then
    echo "错误: 未找到7z工具，请先安装p7zip"
    echo "Ubuntu/Debian: sudo apt-get install p7zip-full"
    echo "CentOS/RHEL: sudo yum install p7zip"
    exit 1
fi

# 定义变量
CONTRACT_DIR="./chainmaker-contract"
OUTPUT_DIR="main"
ARCHIVE_NAME="orasrs.7z"

echo "清理旧文件..."
rm -rf "$OUTPUT_DIR" "$ARCHIVE_NAME"

echo "创建输出目录..."
mkdir -p "$OUTPUT_DIR"

echo "开始静态编译..."
# 设置静态编译环境变量
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

# 执行静态编译，使用特殊链接标志确保完全静态链接
cd "$CONTRACT_DIR"
go build \
  -ldflags="-s -w -extldflags '-static'" \
  -buildmode=pie \
  -o "../$OUTPUT_DIR/main" .

echo "编译完成，返回主目录..."
cd ..

echo "验证二进制文件是否为静态链接..."
if command -v file &> /dev/null; then
    file_result=$(file "$OUTPUT_DIR/main")
    echo "二进制文件信息: $file_result"
    
    if [[ "$file_result" == *"dynamically linked"* ]]; then
        echo "错误: 生成的二进制文件是动态链接的，无法在腾讯云长安链上运行"
        echo "请检查CGO_ENABLED=0环境变量和-static链接标志"
        exit 1
    elif [[ "$file_result" == *"statically linked"* ]]; then
        echo "✓ 二进制文件为静态链接，符合腾讯云长安链要求"
    else
        echo "⚠ 警告: 无法确定二进制文件链接类型，但将尝试继续"
    fi
else
    echo "警告: 未找到file命令，无法验证二进制文件链接类型"
fi

echo "创建合约包 $ARCHIVE_NAME..."
# 使用7z压缩main目录
7z a "$ARCHIVE_NAME" "$OUTPUT_DIR/"

echo "验证压缩包内容..."
7z l "$ARCHIVE_NAME"

echo "构建完成！"
echo "生成的文件: $ARCHIVE_NAME"
echo "请在腾讯云TBaaS控制台上传此文件以部署合约"
echo ""
echo "部署注意事项:"
echo "1. 确保使用长安链DockerGo运行时"
echo "2. 合约入口函数为: orasrscontract.Main()"
echo "3. 初始化参数可能需要: governance_address"
echo ""
echo "合约功能:"
echo "- 节点质押管理 (StakeWithGmSign)"
echo "- 国密签名验证"
echo "- 多层级节点架构 (根层、分区层、边缘层)"
echo "- 声誉系统和挑战机制"
echo "- 治理和验证器功能"
