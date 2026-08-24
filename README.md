# agentbox

[![ci](https://github.com/wanbao118/agentbox/actions/workflows/ci.yml/badge.svg)](https://github.com/wanbao118/agentbox/actions/workflows/ci.yml)

**基于 [Microsoft eXecution Containers (MXC)](https://github.com/microsoft/mxc) 的多 coding-agent 安全沙箱运行时。**

agentbox 不重复造沙箱：MXC 负责内核级隔离（macOS Seatbelt / Linux Bubblewrap），agentbox 补齐它缺的最后一块——**生产级 enforcing 出站代理 + 多 agent 编排**，让"域名级网络白名单"真正成为强制策略而非君子协定。

## 架构

```
┌────────────────────────── agentbox run <profile> ──────────────────────────┐
│                                                                            │
│   ab-proxy (127.0.0.1:<ephemeral>)          MXC 沙箱                        │
│   ┌─────────────────────────┐               ┌───────────────────────────┐  │
│   │ 域名 allowlist 强制      │◄── CONNECT ───│  claude / codex / gemini  │  │
│   │ IP 字面量默认拒绝         │   (唯一出口)   │  aider / opencode / shell │  │
│   │ DNS 在代理侧解析         │               │                           │  │
│   │ token 认证 (macOS)       │               │  文件系统: 仅 workspace 可写│  │
│   │ JSONL 审计日志           │               │  HOME = 会话快照 scratch   │  │
│   └─────────────────────────┘               │  凭证按白名单注入           │  │
│                                             └───────────────────────────┘  │
│   内核层保证（MXC）: 沙箱出站只能到达 127.0.0.1:<代理端口>                     │
│     macOS: Seatbelt deny-all + 精确端口放行                                  │
│     Linux: 私有 netns + slirp4netns + netns 内 iptables（免 root）            │
└────────────────────────────────────────────────────────────────────────────┘
```

两层防御缺一不可：

| 层 | 谁 | 保证 |
|---|---|---|
| L3/L4 | MXC（seatbelt profile / bwrap netns+iptables） | 直连任何外部地址、其他本机服务、局域网 → **EPERM** |
| L7 | agentbox enforcing proxy | 只有白名单内的**域名**能通过 CONNECT 隧道；IP 直连、DNS 重绑、未列域名 → **403** |

不遵守 `HTTP_PROXY` 的客户端也逃不掉——它在第一层就已经没有出站路径了。

## 冒烟测试实录（2024-08，macOS 15.7 Intel 实测）

在沙箱内用 OpenRouter 免费模型跑通两个真实 agent：

```
$ agentbox run opencode --inherit-secret OPENROUTER_API_KEY --net-group packages-npm \
    -- run -m openrouter/cohere/north-mini-code:free 'Reply with exactly: SANDBOX-OPENCODE-OK'
SANDBOX-OPENCODE-OK        # 6 requests allowed, 0 denied

$ agentbox run claude-code --net-group telemetry,openrouter \
    -e ANTHROPIC_BASE_URL=https://openrouter.ai/api \
    -e "ANTHROPIC_AUTH_TOKEN=$OPENROUTER_API_KEY" -e 'ANTHROPIC_API_KEY=' \
    -e 'ANTHROPIC_DEFAULT_SONNET_MODEL=<free-model-id>' ... \
    -- -p 'Reply with exactly: SANDBOX-CLAUDE-OK'
SANDBOX-CLAUDE-OK          # 全部流量经代理，审计零拒绝
```

Claude Code 接 OpenRouter 的要点（官方教程）：`ANTHROPIC_BASE_URL=https://openrouter.ai/api`
（无 `/v1`）、`ANTHROPIC_AUTH_TOKEN` 放 OpenRouter key、**`ANTHROPIC_API_KEY` 必须显式置空**、
`ANTHROPIC_DEFAULT_*_MODEL` 指向实际模型 id。

冒烟过程中发现并修复的真实隔离问题：

1. **opencode 需要写 `/tmp/opencode`** → 沙箱内 `TMPDIR` 统一重定向到会话 scratch
   （比给 `/tmp` 开洞安全；pip/npm 等同样受益）
2. **claude-code 硬编码 `/tmp/claude-<uid>`**（不认 TMPDIR）→ profile 新增 `extra_rw`
   精确放行该子树（seatbelt 内核按解析后路径判定，符号链接无法绕过）
3. **审计即文档**：claude-code 首跑被拒的 `openrouter.ai` 直接暴露白名单缺口，
   `--net-group openrouter` 一条命令补齐

免费模型注意事项：`:free` 档有上游限流与"思考链吞噬回复"现象（ECONNRESET、空 result），
属模型侧问题——换模型即可；HTTP 层在沙箱内始终稳定。

## 快速开始

```bash
# 构建
cargo build --release

# 环境自检（mxc 二进制发现、平台依赖、profile 检查）
./target/release/agentbox doctor
./target/release/agentbox doctor claude-code

# 在沙箱里跑 Claude Code（工作区 = 当前目录）
./target/release/agentbox run claude-code -- --continue

# Codex CLI + 允许 npm 安装依赖
./target/release/agentbox run codex --net-group packages -- npm i

# 任意命令的逃生舱
./target/release/agentbox run shell --allow api.github.com -- -c 'gh pr list'
```

## e2e 验证结果（macOS 15.7 x86_64 实测，13 项）

`scripts/e2e-macos.sh` 全部通过：

1. ✅ 白名单域名经代理隧道 TLS 可达
2. ✅ 未列域名被代理拒绝（403，审计 denied×1）
3. ✅ raw socket 直连被内核拒绝（EPERM）
4. ✅ workspace 写边界（内可写 / 外 EPERM）
5. ✅ HOME 重定向 + 真实 ssh key 不可见
6. ✅ **schema 锁定**：生成的配置通过 mxc 自带 validator 校验（防上游漂移）
7. ✅ 直连 DNS/UDP :53 被内核拒绝
8. ✅ SSH_AUTH_SOCK / AWS 密钥等宿主环境零泄漏
9. ✅ 跨会话借用代理策略被 token 拒绝（407）

CI：`.github/workflows/ci.yml` —— clippy(-D warnings) + macos/ubuntu 矩阵测试，
macOS runner 额外构建 mxc 并跑完整 e2e。

> ⚠️ Seatbelt 不能嵌套：在已被文件沙箱包裹的环境里跑 e2e 会得到
> `sandbox_init failed: Operation not permitted`，请在普通 shell 中运行。

## Profile 组成

每个内置 profile（claude-code / codex / gemini / aider / opencode / shell）包含：

- **home 快照目录**：如 `~/.claude`、`~/.codex`，会话开始时复制进一次性 scratch HOME，
  沙箱内可写、宿主原件零风险（`--rw-config` 可改为直通真实目录）
- **凭证注入白名单**：如 `ANTHROPIC_API_KEY`、`OPENAI_API_KEY`，仅当宿主已设置才转发；
  其余环境变量一律不进沙箱（MXC 从清空环境启动子进程）
- **网络基线 + 命名组**：基线是各 agent 的核心 API 域名；`--net-group packages/git/telemetry/...`
  按需加包仓库、git 托管、遥测等组；`--allow '*.example.com'` 追加自定义规则；
  `--deny` 规则永远优先；`--offline` 完全断网

```bash
agentbox profiles --verbose        # 查看/校验所有 profile
agentbox allowlist claude-code     # 打印生效域名规则
agentbox match gemini accounts.google.com:443   # 单点测试
agentbox proxy --allow '*.internal' --audit a.jsonl  # 独立调试代理
```

通配符语义：`*.anthropic.com` 匹配任意深度子域但**不含裸域** `anthropic.com`
（需要时显式列出）。IP 字面量默认拒绝，显式 IP 规则（如 `10.0.2.2:443`）除外。

## 平台说明

### macOS（seatbelt，v1 主路径）
- 无需安装任何东西；`nestedPty` 默认开启以支持 TUI agent
- 代理 URL 带 per-session 随机 token（Proxy-Authorization），防止同机其他进程借用本会话策略
- `--keychain` 放开 Keychain 访问（keychain 登录态的 agent 需要）
- apple/container microVM 后端留作 v2 强隔离档（要求 macOS 26+ Apple Silicon）

### Linux（bubblewrap，免 root）
- 依赖：`bwrap`、`slirp4netns`、`iptables`/`ip6tables`（`doctor` 会检查）
- MXC 在私有 netns 内以 CAP_NET_ADMIN 下 iptables 规则实现同样的
  "仅代理端口可达"，全程无需 root，沙箱内无法撤销规则
- 平台限制：bwrap 经 argv 传代理 URL（`/proc/<pid>/cmdline` 全用户可见），
  MXC 因此拒绝带凭证的 URL —— Linux 上代理以无 token 模式运行
  （每会话随机高端口缓解）；这是上游已知权衡，见 mxc `bwrap_runner.rs`

## 安全模型与边界

**防什么**（对沙箱内进程）：数据外泄到任意域名/IP、绕过代理直连、访问宿主敏感
文件与 SSH/GPG 凭证、污染宿主 agent 配置、探测局域网/本机其他服务。

**不防什么**：
- 白名单域名本身的返回内容（agent 拿到的合法 API 响应仍可能含提示注入内容）
- 快照进沙箱的登录凭证在会话期间位于沙箱内（这是 agent 正常工作的前提）；
  会话结束即随 scratch 目录销毁
- macOS 上 GUI/Electron 应用的重拉起逃逸（Seatbelt 固有限制，coding agent 场景基本无关）
- MXC 官方声明其早期预览版策略生成"不应视为安全边界"——生产使用请跟进上游版本

## 目录结构

```
crates/ab-proxy      enforcing 代理：规则引擎/CONNECT 隧道/DNS 代解析/审计（含 wire 测试）
crates/ab-profiles   内置 agent profiles 与命名网络组
crates/ab-runtime    MXC 配置生成(0.8 schema)、二进制发现、会话编排、doctor
crates/ab-cli        agentbox CLI（run/doctor/profiles/allowlist/match/proxy）
scripts/e2e-macos.sh 可重复的端到端验证
../mxc/              microsoft/mxc 上游 checkout（构建产物被自动发现）
```

## 生产化状态

- [x] 权限加固：会话 scratch 目录 0700、审计日志 0600、extra_rw 目录 0700
- [x] clippy `-D warnings` 全清；测试套件连续多轮稳定（无 flake）
- [x] 对抗性 e2e：DNS/UDP 直连、env 泄漏、跨会话 token 隔离
- [x] schema 回归锁定（mxc validator 参与 CI）
- [x] CI 矩阵（macOS seatbelt 全量 e2e / Ubuntu 单测+doctor）
- [x] 真实 agent 冒烟：opencode 与 claude-code 经 OpenRouter 全链路跑通

## Roadmap

- [ ] v2: apple/container microVM 后端（强隔离档）
- [ ] v2: Landlock ABI6/seccomp 加固 Linux 非 netns 路径
- [ ] `--strict` 模式（有 deny 即非零退出码，供 CI 使用）与审计实时 tail
- [ ] MCP server 白名单编排（本地 stdio MCP 自动放行、SSE 远端按域名放行）
- [ ] 上游 PR：外部代理 host 列表转发接口（消除 Linux token 差异）
- [ ] Linux 实机 e2e（bwrap+slirp4netns 路径目前仅配置级验证）
