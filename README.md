<div align="center">

# EasyAuth

**让一支 U 盘成为 ClassIsland 管理界面的钥匙**

ClassIsland 管理凭据的认证提供方插件 · 插盘即解锁，无需密码、无需重启

[![ClassIsland](https://img.shields.io/badge/ClassIsland-2.1.0.1-4B8BF7)](https://github.com/ClassIsland/ClassIsland)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

## 这是什么

给教室里的 ClassIsland 管理界面加一把**实体钥匙**：配对一次 U 盘（或移动硬盘）之后，
老师插上盘、点一下「验证」就能解锁，学生碰不到密码。

不像「把密码写进配置文件」的做法——EasyAuth 的密钥文件与**本机 + 这块盘 + 你的 Windows 账户**
三重绑定，拷走、换盘、克隆都没用。

## 功能特性

| 能力 | 说明 |
|---|---|
| 六层可插拔校验 | Windows 账户绑定(DPAPI)、token、磁盘序列号、卷标识、克隆计数、品牌提示，每层可单独开关 |
| 多分区同时校验 | 可切「设备模式」：选设备而非选分区，该设备所有合格分区全部通过才算通过 |
| 克隆计数 | 每次成功解锁计数 +1，今天拷走的 U 盘明天就作废 |
| 审计日志 | 每次配对/认证结果都记录（时间、盘符、序列号、失败层与原因），可事后追溯 |
| 免管理员 | 查询走 WMI 与 mountvol，无需管理员权限，无常驻进程 |
| 纯插件 | 单个 `.cipx`，不装服务、不写系统目录 |

## 安装

### 方式一：安装包（推荐）

1. 下载 `ClassIsland.EasyAuth.cipx`
2. ClassIsland → **设置** → **插件** → 从本地安装 `.cipx`
3. 重启 ClassIsland

### 方式二：手动安装

把插件文件夹整个放进 ClassIsland 的 `data\Plugins\cn.amengbro.easyauth\`：

```
data\Plugins\cn.amengbro.easyauth\
├── ClassIsland.EasyAuth.dll
├── manifest.yml
└── ...
```

> 仅支持 Windows（ClassIsland 本体为 Windows 部署场景）。

## 使用

### 配对（教师，一次性）

1. ClassIsland → 设置 → 管理凭据 → 在认证方式里添加「**U盘密钥**」
2. 插上要当钥匙的 U 盘，在下拉框里选中它
3. 点「**读取**」确认设备信息（序列号、卷标识都对得上）
4. 按需勾选验证层 → 点「**保存配对**」→ 确定保存凭据

配对会在该分区上创建一个隐藏目录：

```
<U盘>\.EasyAuth\key.bin     （目录带 隐藏 + 系统 属性，资源管理器里不可见）
```

### 解锁

1. 插入 U 盘 → 打开管理凭据 → 选择「U盘密钥」
2. 下拉框已自动预选配对分区（盘符变了也能认出，靠的是卷标识）
3. 点「**验证**」→ 进度条与逐项状态会显示当前校验到哪一层
4. 通过后按钮变成「**进入**」，点它解锁

拔掉 U 盘无需任何「还原」操作——插件无状态，下次验证自然失败。

## 各项校验层

| 层 | 防的是 | 建议 |
|---|---|---|
| Windows 账户绑定 | U 盘被别人拿到后在**别的 Windows 账户**下使用 | 教师独占账户的机器建议开；多账号共用时意义不大 |
| token 校验 | 直接复制密钥文件 | 必开 |
| 磁盘序列号绑定 | 把 U 盘克隆/换成另一块盘 | 必开 |
| 卷标识绑定 | 同一块盘的**其他分区**顶替 | 必开 |
| 克隆计数 | 用旧快照复活过期克隆盘 | 必开 |
| 品牌提示 | ——（仅界面提示，不参与判定） | 可选 |

硬绑定层（token / 序列号 / 卷标识）**至少要开一个**，全关会被护栏拦下。

## 多分区同时校验

编辑凭据时勾选「多分区同时校验」，下拉框就从**分区**切换成**设备**：

- 选中设备 → 该设备所有合格分区**全部**校验通过才算认证通过
- 总容量 <32MB 或可用空间 <16MB 的分区会被自动丢弃（系统保留/恢复分区）
- 每个分区各存一份独立密钥，缺任一份都无法通过

## 安全模型（诚实的边界）

**能防**：拿走 U 盘后拷贝密钥文件、克隆到别的盘、拷到同一块盘的其他分区、
用旧快照复活、把 U 盘拿到另一台电脑或另一个 Windows 账户下用。

**防不了**：能修改 ClassIsland 程序目录或 `data` 目录权限的人——他们可以直接改
`Credentials.json` 把认证方式删掉，这是 ClassIsland 本地模式本身的特性，任何插件都拦不住。
真正的边界在**文件系统权限**（目录 ACL 或集控模式）。

## 常见问题

**Q：提示「计数不符（密钥盘=x，本机=y）」？**
A：U 盘被整盘拷贝过导致计数落后。用原盘重新配对即可（计数会归零）。

**Q：提示「卷标识不匹配」？**
A：选错了分区，或密钥文件来自同一块盘的其他分区。选回配对时的分区即可。

**Q：换台电脑 U 盘还能用吗？**
A：不能。密钥与机器标识（MachineGuid）、磁盘序列号绑定，拷到别的电脑无法解密。

**Q：教师把 U 盘弄丢了怎么办？**
A：用凭据里的其他认证方式（建议保留密码方式作兜底）解锁后重新配对。

## 构建与开发

```powershell
git clone <本仓库>
cd ClassIsland.EasyAuth
dotnet build            # 产出 cipx/ClassIsland.EasyAuth.cipx
```

仓库自带控制台自测工具，不依赖 ClassIsland，直接在真实硬件上跑全部校验用例：

```powershell
cd tools\DeviceProbe
dotnet run
```

## 致谢

- [ClassIsland](https://github.com/ClassIsland/ClassIsland) 及其插件 SDK

## 许可证

[MIT](LICENSE) · 仅供教学与校园管理使用，请同时遵守 ClassIsland 本体及其插件的许可条款。