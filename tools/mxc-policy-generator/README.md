# MXC Policy Generator (Skeleton)

此目录包含一个最小化的 policy generator 骨架实现（Python）。目的：展示如何从简化的 agent 能力声明生成符合 MXC schema 的 JSON policy。

使用方法（示例）

1. 创建虚拟环境并安装依赖：

   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r tools/mxc-policy-generator/requirements.txt

2. 运行示例：

   python tools/mxc-policy-generator/main.py --input examples/mxc/sample_agent.yaml --output out/policy.json --schema-path /path/to/mxc-config.schema.0.8.0-alpha.json

说明：当前实现为骨架，重点在 I/O、schema 验证点位与模板输出。后续将补充完整的字段映射与模板。
