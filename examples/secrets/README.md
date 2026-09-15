# Secret Broker 本地示例

这是一个非常简单的本地 secret broker 示例，用于演示如何在 agentbox 启动前创建临时凭证文件并在运行后清理。

实现要点：
- 在 provision 阶段创建临时文件（权限 600），写入短期凭证
- 在 policy 的 filesystem.readonlyPaths 中声明该路径
- 在 deprovision 阶段删除该文件并写审计日志

下面提供一个简单的 shell 脚本示例，供 demo 使用。
