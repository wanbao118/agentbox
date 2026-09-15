# MXC Integration Design Document

此文档概述将 wanbao118/agentbox 与 Microsoft MXC（v0.8 schema）整合的设计与 MVP 交付物。文档以中文撰写，包含目标、组件、风险与验收标准，便于快速评审与实现。

## 背景与目标
- 目标：为 agentbox 提供与 MXC 的对接能力，满足细粒度安全控制、受控凭证注入、域名级网络白名单、沙箱内部动态端口支持，以及避免高风险宿主依赖（如 Java Attach）。
- 交付：实现 policy 生成器骨架、proxy-only 出站代理 demo（Envoy 为首选）、secret broker 本地示例、端口协调 demo、以及文档与测试骨架。

## MVP 组件
1. tools/mxc-policy-generator：从简化的能力声明（YAML/JSON）生成 MXC 兼容 policy JSON，并做 schema 验证（可选）。
2. examples/proxy：Envoy 配置示例（同时保留 tinyproxy/socat 轻量 demo），演示域名/Host 白名单与 proxy-only 模式。
3. examples/secrets：本地 secret broker stub，通过临时只读文件方式注入并在 deprovision 时删除。
4. examples/port-coordinator：端口注册协议草案与 demo，展示 agent 运行时向 agentbox 报告监听端口并由 host/proxy 建立映射。
5. docs/mxc-integration.md：详细设计与风险说明（本仓库 docs 下）。

## 关键设计点
- 网络：在 policy 中设置 `egress.default: deny`，并使用 `runtimeConfig.networkProxy` 或 `network.proxy` 字段指向本地 loopback proxy，从而通过代理实现域名/URL 级白名单与审计。
- 凭证注入：优先使用临时只读文件挂载；可选实现 Unix domain socket 的 secret broker；环境变量注入仅用于非敏感短期数据。
- 动态端口：建议 agent 在启动时声明端口范围；后续通过 Unix socket 报告实际端口并由 agentbox 更新 proxy/路由。
- Java Attach：不建议授予 ptrace/attach；推荐在 JVM 启动时注入 -javaagent 作为管理通道。

## 验收标准
- policy generator 能输出并通过 schema 验证的 policy（覆盖 process/network/filesystem/runtimeConfig）
- proxy demo 能基于域名白名单允许/阻断 HTTP 请求
- secret broker demo 能生成临时凭证文件并在 run 结束时清理
- 端口协调 demo 演示运行时注册端口并在 host 侧建立转发

## 风险与注意事项
- 严禁将 host 上长期凭证直接挂载到沙箱
- 避免允许 ptrace/attach；如需 attach 必须审计并额外审批
- 若需对 HTTPS 做深度检测（URL/path/content），需 MITM 模式并处理证书管理风险

## 下一步
- 将此 design doc 与 skeleton 提交为 PR，随后分步实现 tools/mxc-policy-generator 与示例

