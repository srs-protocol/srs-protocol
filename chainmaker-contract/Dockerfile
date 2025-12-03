FROM golang:1.19-alpine AS builder

# 安装依赖
RUN apk add --no-cache git ca-certificates

# 设置工作目录
WORKDIR /app

# 复制go mod文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY *.go ./

# 编译合约
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# 最终镜像
FROM alpine:latest

# 安装ca-certificates
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# 从builder镜像复制编译好的合约
COPY --from=builder /app/main .

# 合约入口点
CMD ["./main"]