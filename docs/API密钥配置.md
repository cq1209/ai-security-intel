# API 密钥配置说明

本模块的“受影响资产（asset exposure）”维度支持三个资产测绘平台，按优先级依次尝试：

- **FOFA**：国产资产测绘平台（推荐，国内访问稳定）
- **Shodan**：互联网设备/服务搜索引擎
- **Censys**：互联网资产测绘平台

没有任何一个平台的有效密钥时，该维度会安全降级为空结果（`exposed_count: 0`），不会报错，也不影响其它五个富化维度。

## 1. FOFA（推荐）

### 获取密钥

1. 打开 https://fofa.info/ 并登录。
2. 进入“个人中心 → API 信息”，获取邮箱（Email）和 API Key。

### 重要限制

- 普通会员需要消耗 F 币进行查询；注册用户通常有少量免费额度。
- 详细计费见 https://fofa.info/ 的会员说明。

### 配置

在项目根目录的 `.env` 中填写：

```env
FOFA_EMAIL=你的FOFA邮箱
FOFA_API_KEY=你的FOFA密钥
```

## 2. Shodan

### 获取密钥

1. 打开 https://account.shodan.io/ 并登录。
2. 左侧选择 **API Key**。
3. 复制页面显示的 API Key。

### 重要限制

- 免费账号 **没有搜索查询额度**（0 query credits），只能调用 `api-info`，无法执行 `host/search`。
- 要启用资产搜索，需要在 https://account.shodan.io/billing 购买查询额度，或升级为会员。

### 配置

在项目根目录的 `.env` 中填写：

```env
SHODAN_API_KEY=你的Shodan密钥
```

## 3. Censys

### 获取令牌

新版 Censys 只提供 **Personal Access Token（PAT）**，不再提供旧的 API ID + Secret。

1. 打开 https://accounts.censys.io/settings/personal-access-tokens 并登录。
2. 点击 **Create Token**，权限选择只读（Read-only）。
3. 创建后立刻复制令牌，它只显示一次。

### 重要限制

- 免费账号 **只能做单条主机查询**，不能使用全局搜索（Global Search）。
- 要启用 `v3/global/search/query` 全局搜索，需要升级为带组织（Organization）的付费计划。

### 配置

在项目根目录的 `.env` 中填写：

```env
CENSYS_PAT=你的Censys令牌
```

## 4. 验证

填好后，在项目根目录执行：

```powershell
.\.venv\Scripts\python.exe -m app.enrichment.pipeline
```

查看输出 `coverage` 里的 `enrich_item_assets`：只有拿到真实暴露资产时，`affected_assets.exposed_count` 才会大于 0。

## 5. 无密钥时的降级行为

当前实现按以下顺序尝试：

1. FOFA `api/v1/search/all`
2. Shodan `host/search`
3. Censys `v3/global/search/query`
4. 三者都不可用时返回空结果

每一步失败都会记录日志并继续，不会中断情报采集和富化流程。
