Proxy 示例与说明

本示例提供两条路线：

1) 推荐（用于 MVP 与长期扩展）：Envoy
   - 优点：L7 能力、支持 SNI/Host 匹配、动态配置（xDS）、丰富的过滤器与日志
   - 适合用于域名/Host/SNI 级别白名单与审计

2) 轻量快速验证：tinyproxy / socat
   - 优点：启动和配置简单，便于快速 demo
   - 缺点：无法做 L7 Host/path 级精细控制

如何使用（示例）：
- 使用 Envoy：
  - 安装 Envoy（Linux/macOS）
  - 运行： envoy -c examples/proxy/envoy.yaml
  - 在 MXC policy 中设置 runtimeConfig.networkProxy 指向 http://127.0.0.1:15000 或在 network.proxy.url 字段中填写

- 作为快速验证可选 tinyproxy：
  - 根据平台安装 tinyproxy 或 使用 socat 做简单的 TCP 转发

详情见 envoy.yaml 示例配置（即可用于 HTTP Host 白名单 demo）。
