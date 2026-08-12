# Verification-First Harness

一个面向 Agent 工作流的实验性可信控制层：**所有 Agent 输出默认都是不可信
Claim，只有经过独立验证的 Claim 才能向下游传播。**

项目优化的目标是错误隔离，而不是 Agent 数量。当前提供一个模型无关的 Python
核心，实现候选解提交、对抗性挑战、确定性验证、失败修复、重新验证和签名收据。

> 当前状态：Alpha / 研究原型。1.0 前协议和公共 API 可能调整。内置子进程执行器
> 不是恶意代码安全沙箱。

## 七条核心原则

1. 每个 Agent 都不可信。
2. 每个输出都是 Claim，而不是事实。
3. 未验证 Claim 不得传播到下游。
4. Critic 应尝试证伪前序工作，而不是盲目继承。
5. 优先使用确定性独立验证，而不是 LLM 自我判断。
6. 失败、修复、重新验证属于正常控制流。
7. 系统优化错误隔离能力，而不是 Agent 数量。

以上原则定义了项目的信任模型。0.1 版本只在一个范围明确的 Python 编码任务闭环中
强制执行这些原则：任务契约在系统外获得授权，Worker 输出不可信代码 `Claim`，
Critic 提议附加检查，只有完整且签名有效的 PASS 收据可以通过 `TrustGate`。

## 快速开始

需要 Python 3.10 或更高版本。

```bash
python -m venv .venv
python -m pip install -e .
python -m verification_harness.main
```

开发检查：

```bash
python -m pip install -e ".[dev]"
ruff check .
mypy src
pytest
python -m build
```

## 当前能力

- 为任务契约和候选 Claim 生成规范化 SHA-256 摘要；
- HMAC-SHA-256 收据绑定 Claim、Spec、Attempt、Obligation、Evidence 和协议版本；
- TrustGate 在传播前验证全部绑定关系；
- 每个测试用例使用新子进程并由父进程强制超时；
- Agent 接口与模型厂商解耦，可接入不同模型；
- 提供跨平台 CI、类型检查、测试、构建和标签发布流程。

## 必须理解的安全边界

普通 Python 子进程只能提供故障隔离，不是恶意代码安全边界。真正不可信的候选代码
必须运行在独立容器、microVM、虚拟机或操作系统沙箱中，并限制凭据、网络、文件系统、
CPU、内存、磁盘、输出量和进程数。签名密钥只能保存在可信控制器中。

生产使用前请阅读[威胁模型](docs/threat-model.md)、[架构说明](docs/architecture.md)
和[安全政策](SECURITY.md)。

## 当前限制

- Planner 生成的验收标准尚未经过独立授权；
- Planner 与 Critic 输出尚未统一封装成通用 Claim；
- 尚无容器或 microVM 执行后端；
- 尚无多 Worker 并行调度与 DAG 收据传播；
- 尚无持久化、追加式审计存储。

这些事项已列入[路线图](docs/roadmap.md)。项目使用 Apache-2.0 许可证。
