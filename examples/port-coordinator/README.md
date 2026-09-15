端口协调器示例与协议说明

目标：展示 agent 在运行时如何向 agentbox 报告其监听端口（随机或动态），并由 agentbox 在 host/proxy 侧创建相应的路由/转发以供外部访问或内网中其他 agent 访问。

MVP 协议草案（最小）
- 使用 Unix domain socket（路径示例：/tmp/agentbox_port.sock）
- agent 向 socket 发送 JSON 行：{"action":"register","port":12345,"proto":"tcp","purpose":"http-api"}
- agentbox 回应：{"status":"ok","proxy_endpoint":"127.0.0.1:16000"}

Demo 脚本：examples/port-coordinator/register_server.py
