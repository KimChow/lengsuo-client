# MCP启动配置Debug脱敏

2026-10-17：StdioServerCommand派生Debug会输出命令行参数和环境变量值；ClientConfig又包含该对象。
新增假凭据回归先失败，改为只输出program及参数/环境数量，不打印值，保持实际启动参数不变。
这不替代工具结果脱敏或第三方MCP安全验收；stdio行为验收由独立卡继续。
