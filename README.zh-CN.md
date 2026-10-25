# Satochip-25519-Omni-Bridge (中文文档)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![WebHID](https://img.shields.io/badge/WebHID-Ledger%20Nano%20S-green.svg)](https://developer.mozilla.org/en-US/docs/Web/API/WebHID_API)
[![Windows USB/IP](https://img.shields.io/badge/Windows-usbip--win2-blueviolet.svg)](https://github.com/vadimgrn/usbip-win2)
[![License](https://img.shields.io/badge/License-LGPL--3.0-orange.svg)](https://www.gnu.org/licenses/lgpl-3.0.html)

> **专为 Satochip-25519 智能卡打造的 Windows 内核级免驱 WebHID 虚拟 Ledger Nano S 桥接器与多链驱动。**  
>
> 🌐 **文档语言**：[English](README.md) | [中文 (当前)](README.zh-CN.md)  
> 💳 **配套卡片固件**：[Satochip-25519-Applet](https://github.com/chx818/Satochip-25519-Applet)  
> 📄 **协议技术白皮书**：[开发者协议白皮书](https://github.com/chx818/Satochip-25519-Applet/blob/master/SPECIFICATION-Curve25519.zh-CN.md)  

---

## 项目概述

**`Satochip-25519-Omni-Bridge`** 是一套实验性、本机回环的 WebHID 兼容层。它通过 Windows USB/IP 协议在操作系统内核级模拟出一台免驱的标准 **Ledger Nano S** 硬件钱包（`VID: 0x2C97, PID: 0x0001`, UsagePage: `0xFFA0`），将主流 Web3 钱包发出的 WebHID 请求无缝转换为运行 [`Satochip-25519-Applet`](https://github.com/chx818/Satochip-25519-Applet) 的安全智能卡原生 APDU 命令。

原生支持 6 条主流 Ed25519 / SLIP-0010 公链：
* **Solana (SOL)**：BIP44 `501'`（Phantom、Solflare、OKX Wallet）
* **TON (The Open Network)**：BIP44 `607'`（Tonkeeper、MyTonWallet）
* **Sui (SUI)**：BIP44 `784'`（Sui Wallet、Suiet）
* **Aptos (APT)**：BIP44 `637'`（Petra、Pontem）
* **Polkadot (DOT / KSM)**：BIP44 `354'`（Polkadot.js、SubWallet）
* **Near Protocol (NEAR)**：BIP44 `397'`（Near Wallet、Meteor）

> [!NOTE]
> **兼容性说明**：本项目为实验性本地兼容桥，并非 Ledger 官方硬件，亦未获得 Ledger SAS 官方认证。各主流 Web3 钱包通过标准 WebHID 原生接口与虚拟设备交互，实际使用前请针对具体钱包版本、浏览器和网络环境进行测试。

---

## 架构分层原理

```
Web 浏览器钱包扩展 (Phantom / Tonkeeper / Sui / Polkadot.js)
                             │
                             ▼ (WebHID: VID 0x2C97, UsagePage 0xFFA0)
            [ Windows 系统内置 hidusb.sys 驱动 ]
                             │
            [ usbip-win2 虚拟 USB 控制器 (WHQL 微软签名) ]
                             │ (TCP: 127.0.0.1:3240, 仅限本机回环)
                             ▼
            [ virtual_ledger_usbip_daemon.py ]
              ├── HID 64 字节数据包解包与分片组装
              └── 本地回环 Socket 安全隔离
                             │
                             ▼
            [ ledger_ed25519_omni_translator.py ]
              ├── 万能多链路由引擎 (SOL/TON/SUI/APT/DOT/NEAR)
              ├── 硬派生路径核验与续包流状态隔离
              └── 签名释放前本地强制验签守卫 (Verify-Before-Release)
                             │
                             ▼ (PC/SC WinSCard + 强制 SecureChannel)
            [ pysatochip_25519.py ]
              ├── Authentikey ECDSA 响应防伪签名核验
              └── Montgomery-Edwards 双有理坐标反解
                             │
                             ▼ (ISO 7816-4)
            [ NXP J3R452 实体智能卡 (Satochip-25519-Applet) ]
```

---

## 安全模型与防护边界

1. **严格绑定 IPv4 回环地址**：守护进程仅监听 `127.0.0.1`，启动前强制校验目标地址，拒绝 IPv6 或非回环地址，彻底杜绝意外暴露至局域网（LAN）的风险。
2. **Fail-Closed 盲签策略**：由于虚拟桥接器没有物理硬件屏幕进行交易可视化确认，默认关闭盲签。未指定 `--allow-blind-sign` 时，签名请求将被直接拒绝并返回 `SW_SECURITY_STATUS` (`0x6982`)。
3. **签名释放前本地校验 (Verify-Before-Release)**：卡片生成 Ed25519 签名后，桥接器在释放给上位机前，强制在本地进行数学验签，防止硬件故障注入导致的错误签名泄露。
4. **多包流状态隔离**：流式续包（`P2_EXTEND`）严格绑定初始包的链路 Profile、派生路径与 P1 参数。任何乱序包或跨链请求均会导致会话中断并清空缓冲区。
5. **Authentikey 身份强校验**：卡片导出的所有公钥与链码均附带卡内 Authentikey ECDSA 签名，客户端全量验签，阻断中间人篡改。
6. **敏感内存主动清零**：交易明文缓冲区在签名完成后或遇到任何异常时，显式循环覆写为 0，防止堆内存残留敏感数据。

---

## 安装与快速上手

### 1. 安装 Python 依赖

```powershell
# 克隆仓库
git clone https://github.com/chx818/Satochip-25519-Omni-Bridge.git
cd Satochip-25519-Omni-Bridge

# 安装依赖与包
pip install -r requirements.txt
pip install -e .
```

### 2. 安装 `usbip-win2` 内核驱动（仅需一次）

虚拟 USB 控制器需要微软 WHQL 数字签名的 `usbip-win2`：

```powershell
# 通过 Windows 包管理器一键安装：
winget install -e --id vadimgrn.usbip-win2
```
或前往 [vadimgrn/usbip-win2 Releases](https://github.com/vadimgrn/usbip-win2/releases) 下载安装包。

---

## 使用指南

### 查看卡片状态与导出地址

```powershell
# 查看卡片状态与 Curve25519 硬件加速就绪情况：
python satochip_cli_25519.py --status

# 一键派生 Solana、TON 与 Sui 地址：
python satochip_cli_25519.py --derive-all
```
*(PIN 码将通过密码输入机制私密输入，不在终端明文显示)*

### 启动虚拟 Ledger 桥接器

运行一键批处理启动脚本：

```cmd
start_virtual_ledger.bat
```

1. 在独立的守护进程窗口中输入卡片 PIN 码（仅在宿主内存会话中保持激活）。
2. 启动脚本会自动通过 PowerShell 探针轮询 `127.0.0.1:3240`，确认卡片会话建立后才执行 `usbip attach`，彻底解决启动竞态。
3. 打开 Windows **【设备管理器】** $\to$ **【人体学输入设备】**，确认看到 `Ledger Nano S` 挂载就绪！
4. 打开 Chrome 浏览器，进入 **Phantom**、**Tonkeeper** 或 **Sui Wallet** 设置 $\to$ **「连接硬件钱包 $\to$ Ledger」**，即可原生调起硬件签名！

停止桥接并卸载虚拟设备：

```cmd
stop_virtual_ledger.bat
```

---

## 测试套件与验证

仓库内置了完备的离线与实机自动化测试套件：

```powershell
# 运行安全边界、USB/IP 协议分包与 Authentikey 防篡改单元测试：
python -m unittest -v test_security_boundaries.py test_usbip_protocol.py test_authentikey_response.py

# 运行万能 6 链路由与 RFC 8032 数学验签测试：
python test_omni_pipeline.py

# 运行单链流水线兼容性测试：
python test_bridge_pipeline.py

# 运行非破坏性真卡集成测试（需连接卡片）：
python test_live_card_full.py
```

---

## 文件清单说明

| 文件名 | 功能与用途 |
| :--- | :--- |
| [`ledger_ed25519_omni_translator.py`](ledger_ed25519_omni_translator.py) | 万能 6 链 Ledger APDU 路由器与流式签名状态机 |
| [`pysatochip_25519.py`](pysatochip_25519.py) | PC/SC 驱动、Authentikey 签名校验与 X25519 坐标反解辅助 |
| [`virtual_ledger_usbip_daemon.py`](virtual_ledger_usbip_daemon.py) | 仅回环 USB/IP 服务端与 WebHID 64 字节分包器 |
| [`satochip_cli_25519.py`](satochip_cli_25519.py) | 多链卡片管理与地址查询命令行工具 |
| [`start_virtual_ledger.bat`](start_virtual_ledger.bat) | 端口轮询挂载虚拟 Ledger 启动脚本 |
| [`stop_virtual_ledger.bat`](stop_virtual_ledger.bat) | 卸载虚拟设备与停止服务脚本 |
| [`test_security_boundaries.py`](test_security_boundaries.py) | 路径校验、盲签阻断、缓冲区越界等安全边界回归测试 |
| [`test_usbip_protocol.py`](test_usbip_protocol.py) | USB 描述符、IPv4 回环拦截与 URB 协议测试 |
| [`test_omni_pipeline.py`](test_omni_pipeline.py) | 6 条公链离线端到端模拟与数学真值验签测试 |
| [`test_live_card_full.py`](test_live_card_full.py) | 实体智能卡非破坏性只读与签名集成测试 |

---

## 开源许可证

本项目基于 **GNU Lesser General Public License v3.0 (LGPL-3.0)** 许可证开源。  
详情请参阅 [`LICENSE`](https://www.gnu.org/licenses/lgpl-3.0.html)。
