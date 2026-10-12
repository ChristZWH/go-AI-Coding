# ============================================================
# Banner 指纹识别系统 —— 多阶段构建
#   阶段一 builder：完整 Go 工具链编译静态二进制
#   阶段二 runtime：最小运行镜像（不含编译工具链，攻击面小）
# ============================================================

FROM golang:1.24-alpine AS builder
# 国内网络默认走 goproxy.cn；本项目零第三方依赖，此层为缓存加速层
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 静态编译（运行镜像无需 glibc）；-trimpath 去本机路径；-s -w 剥离符号缩小体积
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fp-server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fp-client ./cmd/client

FROM alpine:3.21
# ca-certificates 供将来 HTTPS 出站使用；busybox 自带 wget 供 healthcheck 调用
RUN apk add --no-cache ca-certificates \
 && addgroup -S app \
 && adduser -S -G app app
COPY --from=builder /out/fp-server /out/fp-client /usr/local/bin/
# 权限收紧：非 root 运行；Compose 侧叠加 read_only / cap_drop ALL / no-new-privileges
USER app
EXPOSE 8080
CMD ["fp-server"]
