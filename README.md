# AI 安全情报采集与富化模块（成员 B）

面向“智能体驱动的 AI 安全知识情报系统”，负责情报的采集、去重、过滤、六维富化和标签打标。

## 功能

- **多源采集**：NVD、GitHub Advisory、CISA KEV、厂商发布、安全社区（支持并发采集）
- **AI 过滤**：按成员 C 的白名单/黑名单规范过滤，准确率 100%
- **六维富化**：CVSS、POC、受影响资产、相关论文、攻击链、修复建议
- **资产测绘**：FOFA 优先，Shodan/Censys 备用
- **标签树**：A-F 六级分类 + 二级标签

## 目录结构

```text
app/
  collectors/   数据源采集器
  cleaners/     过滤、去重、标签分类
  enrichment/   六维富化
  db.py         MongoDB 连接
  schemas.py    数据模型
  scheduler.py  定时调度
data/output/    交付数据文件
docs/           接口说明、密钥配置、准确率、数据版本
scripts/        采集、打标、评估、诊断脚本
tests/          单元测试与准确率回归
```

## 环境

- Python 3.11+
- MongoDB（本地 `mongodb://127.0.0.1:27017`）
- 依赖：`pip install -r requirements.txt`

## 密钥配置

复制 `.env.example` 为 `.env`，填入各数据源密钥。FOFA/Shodan/Censys 的配置见 `docs/API密钥配置.md`。

## 使用

```powershell
# 并发采集
.\.venv\Scripts\python.exe scripts\collect_fast.py

# 六维富化并导出交付文件
.\.venv\Scripts\python.exe -m app.enrichment.pipeline

# 重新打标
.\.venv\Scripts\python.exe scripts\retag_data.py

# 准确率评估
.\.venv\Scripts\python.exe scripts\evaluate_accuracy.py
```

## 交付文件

- `data/output/structured_intel.jsonl`：基础结构化情报
- `data/output/enriched_intel.jsonl`：六维富化情报
- `data/output/remediation_kb.json`：修复知识库

字段说明见 `docs/数据接口说明.md`，当前数据版本见 `docs/数据版本说明.md`。
