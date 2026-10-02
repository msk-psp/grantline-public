# Grantline

[English](../README.md) · [한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md)

**理清复杂权限，追溯授权路径。**

用于 **PostgreSQL、ClickHouse 和 S3 兼容存储**的开源权限管理与访问控制仪表板，
也支持 SeaweedFS。它可视化基于角色的访问控制（RBAC），通过角色、组和 IAM 策略
追溯访问路径，并在修改原生权限前检查实际权限与声明之间的差异。
权限执行仍由各个服务负责。

![Grantline 访问路径图](images/routes-map.png)

## 在本地试用

需要 Python 3.11 或更高版本及 [uv](https://docs.astral.sh/uv/)。
演示无需额外服务器或凭据。

```bash
git clone https://github.com/msk-psp/grantline-public.git
cd grantline-public
uv venv
uv pip install -e .
source .venv/bin/activate
grantline -c examples/demo/grantline.toml serve
```

打开 **http://127.0.0.1:8420/**。首页显示访问路径图；**服务**按服务列出资源，
**权限矩阵**用于比较权限，**变更**用于预览明确的授权和撤销命令。
选择账号后可查看其访问权限和路径。

界面支持 **英语、韩语、日语和简体中文**。在任何页面顶部选择语言后，
该选择会保存在 Cookie 中。首次访问时使用浏览器语言。
账号名称、资源路径和服务的原生命令保持原样。

## 使用 Docker

发布 GitHub Release 时，会在 GHCR 上发布 `linux/amd64` 和 `linux/arm64` 镜像。
稳定版本同时更新 `latest`；预发布版本仅使用独立的版本标签。

```bash
docker run --rm -p 127.0.0.1:8420:8420 ghcr.io/msk-psp/grantline-public:latest
```

打开 **http://127.0.0.1:8420/** 即可体验内置演示，无需凭据。
连接实际系统时，请挂载外部配置并持久保存运行记录。参阅
[容器配置](usage.md#containers)，部署时固定发布标签或 digest。
镜像已包含 PostgreSQL 驱动。

## 常用命令

```bash
grantline -c examples/demo/grantline.toml plan      # 检查权限差异和原生命令
grantline -c examples/demo/grantline.toml apply     # 仅预演，不进行修改
grantline -c examples/demo/grantline.toml history  # 比较已记录的观测结果
```

`apply --write` 会修改配置的系统，包括演示数据文件。
启用前请检查预览和管理范围。

## 连接实际系统

将实际配置保存在仓库外，例如 `~/.config/grantline/prod.toml`。
配置中指定用于保存凭据的环境变量名称；观测凭据与写入凭据分开使用。
PostgreSQL 还需要通过 `uv pip install 'grantline[postgres]'` 安装额外依赖。

以下详细文档以英语提供。

- [配置与运维](usage.md)：适配器、凭据、桥接、权限声明、访问检查、观测记录和审批。
- [安全](../SECURITY.md)：共享控制台与启用写入。内置服务器不进行用户认证，共享部署需要认证代理。
- [贡献指南](../CONTRIBUTING.md)：开发环境与检查方法。
- [产品范围](prd/003-scope.md)：需求与实现状态。

无法读取的范围表示 **未知**，不会被当作“没有访问权限”。
每次写入都会先预览原生操作，并记录执行尝试和结果。
基于声明的撤销仅限于受管理的账号，以及声明所描述的系统。

## 许可证

[Apache-2.0](../LICENSE)。
