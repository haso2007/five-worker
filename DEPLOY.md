# Cloudflare Workers 手工部署指引

本指引适用于已安装并登录 Wrangler CLI 的用户。

## 部署步骤

### 1. 创建 KV 命名空间

在项目根目录运行以下命令：

```powershell
wrangler kv namespace create "KV"
```

执行成功后会返回类似以下信息：

```
✨ Success!
{
  "kv_namespaces": [
    {
      "binding": "KV",
      "id": "71340f31ab07441280e9225b9be4dadd"
    }
  ]
}
```

**记下返回的 `id` 值**，下一步需要用到。

### 2. 创建配置文件

在项目根目录创建 `wrangler.toml` 文件，内容如下：

```toml
name = "five-worker"
main = "_worker.js"
compatibility_date = "2025-12-04"
compatibility_flags = ["nodejs_compat"]

[build]
command = ""

[[kv_namespaces]]
binding = "KV"
id = "你的KV命名空间ID"  # 替换为步骤1中获得的ID

[vars]
UUID = "你的UUID密钥"  # 可以是任意字符串，用于生成动态UUID和密码
```

**配置说明：**
- `id`: 填入步骤1中创建的 KV 命名空间 ID
- `UUID`: 自定义密钥，可以使用：
  - 随机字符串
  - 标准 UUID 格式（如：`a8f2c9e5-7b3d-4e61-9f8a-2c5d6b1e4a9f`）
  - 任意组合，这是生成动态 UUID 的 KEY，也是 Trojan/SS 的密码

### 3. 部署到 Cloudflare

运行部署命令（**重要：必须使用 `--no-bundle` 参数**）：

```powershell
wrangler deploy --no-bundle
```

> **注意**：由于 `_worker.js` 使用了代码混淆，必须添加 `--no-bundle` 参数跳过代码打包和验证，否则会报错。

部署成功后会显示：

```
✨ Success!
Total Upload: 391.89 KiB / gzip: 109.89 KiB
Worker Startup Time: 3 ms
Your Worker has access to the following bindings:
Binding     Resource
env.KV      KV Namespace
env.UUID    Environment Variable

Uploaded five-worker
```

### 4. 获取访问地址

运行以下命令查看部署信息：

```powershell
wrangler deployments list
```

你的 Worker 访问地址格式为：
```
https://five-worker.你的用户名.workers.dev
```

### 5. 首次配置

1. **访问 Worker 地址**
   - 在浏览器中打开上面的访问地址

2. **设置密码**
   - 首次访问会自动弹出设置密码界面
   - 设置主密码（用于生成动态 UUID、TROJAN 等密码）
   - 设置访问密码（用于保护节点配置页面）

3. **获取节点信息**
   - 配置完成后，页面会显示各协议的节点信息
   - 支持的协议：VLESS、TROJAN、XHTTP、Shadowsocks、Socks5

## 可选配置

### 添加更多环境变量

在 `wrangler.toml` 的 `[vars]` 部分可以添加更多配置：

```toml
[vars]
UUID = "你的UUID密钥"
PROXYIP = "出站代理IP"  # 解决CF脏IP问题，支持IPv4/IPv6，逗号分隔
REMOTE_CONFIG = "https://你的配置文件地址/config.json"  # 远程配置文件URL
```

### 绑定自定义域名

如果要使用 XHTTP 协议并绑定自定义域名：

1. 在 Cloudflare Dashboard 中进入你的域名
2. 左侧菜单选择 **网络**
3. 开启 **gRPC** 功能

否则 XHTTP 协议无法连通。

## 更新部署

当代码或配置有更新时：

1. **拉取最新代码**
   ```powershell
   git pull origin main
   ```

2. **重新部署**
   ```powershell
   wrangler deploy --no-bundle
   ```

## 常用命令

```powershell
# 查看部署列表
wrangler deployments list

# 查看 Worker 日志
wrangler tail

# 删除 Worker
wrangler delete

# 查看 KV 命名空间列表
wrangler kv namespace list

# 查看账号信息
wrangler whoami
```

## 注意事项

1. **免费版限制**
   - Workers 每日 10 万次请求限制
   - KV 每日 10 万次读取限制

2. **节点导入**
   - **Shadowsocks**：无法直接导入，需查看生成的节点信息后手动配置
   - **Socks5**：导入后信息可能不完整，需手动补充配置

3. **配置优先级**
   1. KV（键值存储）
   2. 远程配置（Remote Config）
   3. 环境变量（Environment Variables）

4. **必须使用 `--no-bundle` 参数部署**，否则混淆代码会导致编译错误

## 故障排查

### 部署失败（编译错误）

如果看到大量 "Cannot assign to constant" 错误，确保：
- 使用了 `--no-bundle` 参数
- `wrangler.toml` 中包含 `compatibility_flags = ["nodejs_compat"]`

### KV 无法读取

系统会自动退回到远程配置或环境变量，建议设置环境变量作为兜底方案。

### XHTTP 无法连通

如果使用了自定义域名，确保在 Cloudflare 域名设置中开启了 gRPC 功能。
