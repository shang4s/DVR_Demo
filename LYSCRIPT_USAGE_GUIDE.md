# 易飞工具密钥提取完整指南

## 📖 概述

本项目提供了基于 **LyScript x32dbg 远程调试** 的自动化密钥提取工具，可以直接从易飞工具程序的运行时内存中提取加密密钥表数据。

## 🎯 核心功能

| 功能 | 说明 |
|------|------|
| **远程连接** | 通过 LyScript 与 x32dbg 建立 HTTP 远程调试连接 |
| **表1提取** | 自动提取 16 字节主密钥表 (地址: 0x00511B30) |
| **表2提取** | 自动提取 96 字节轮密钥表 (地址: 0x00511B8A) |
| **数据验证** | 验证提取数据的完整性和合法性 |
| **格式导出** | 支持 JSON 和 C 语言头文件格式 |
| **函数识别** | 自动定位和识别关键加密函数 |

## 📋 安装步骤

### 1️⃣ 安装依赖

```bash
# 安装 LyScript Python 包
pip install x32dbg

# 验证安装
pip list | grep x32dbg
```

### 2️⃣ 下载 x32dbg 调试器

```bash
# 下载地址: https://x64dbg.com/
# 解压到本地目录，如: C:\x32dbg\
```

### 3️⃣ 安装 LyScript 插件

```bash
# 下载 LyScript32.dll 和 LyScript64.dll
# https://github.com/lyshark/LyScript

# 复制到 x32dbg 的 plugins 目录
# C:\x32dbg\x32\plugins\LyScript32.dll
# C:\x32dbg\x64\plugins\LyScript64.dll
```

### 4️⃣ 下载提取脚本

```bash
# 从 GitHub 下载
git clone https://github.com/shang4s/DVR_Demo.git
cd DVR_Demo

# 或直接复制 yifei_lyscript_extractor.py
```

## 🚀 快速开始 (5分钟)

### 步骤1: 启动x32dbg调试器

```bash
# 打开 x32dbg 调试器
# Windows 系统:
C:\x32dbg\x32dbg.exe

# 或右键点击易飞工具.exe → 在调试器中打开
```

### 步骤2: 附加到易飞工具进程

```
1. x32dbg 菜单: 文件 → 打开 → 选择 易飞工具.exe
2. 或 文件 → 附加 → 选择已运行的 易飞工具.exe 进程
3. 程序应该在入口点暂停
```

### 步骤3: 加载 LyScript 插件

```
1. x32dbg 菜单: 插件 → 加载插件 → LyScript32.dll
2. 等待插件加载完毕
3. LyScript 会自动启动 HTTP 服务 (默认 127.0.0.1:8000)
```

### 步骤4: 运行 Python 提取脚本

```bash
# 基础用法 (使用默认地址 127.0.0.1:8000)
python yifei_lyscript_extractor.py

# 指定服务器地址和端口
python yifei_lyscript_extractor.py 192.168.1.100 8000

# 或在 Python 中直接导入
python -c "
from yifei_lyscript_extractor import YiFeiExtractor
extractor = YiFeiExtractor()
if extractor.run():
    print('提取成功!')
"
```

### 步骤5: 查看结果

```bash
# 生成的输出文件
ls -la yifei_keys.*

# 查看 JSON 数据
cat yifei_keys.json

# 查看 C 头文件
cat yifei_keys.h
```

## 📊 输出文件格式

### JSON 格式 (yifei_keys.json)

```json
{
  "table_1": {
    "address": "0x00511b30",
    "size": 16,
    "hex": "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF",
    "raw": [0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255]
  },
  "table_2": {
    "address": "0x00511b8a",
    "size": 96,
    "total_rounds": 16,
    "bytes_per_round": 6,
    "hex": "12 34 56 78 9A BC ...",
    "raw": [...],
    "rounds": [
      {
        "round": 0,
        "hex": "12 34 56 78 9A BC",
        "raw": [18, 52, 86, 120, 154, 188]
      },
      ...
    ]
  },
  "metadata": {
    "timestamp": "2025-05-26 10:30:45",
    "source": "易飞工具.exe (LyScript远程提取)",
    "tool": "LyScript x32dbg Remote Debugger",
    "platform": "x86"
  }
}
```

### C 头文件 (yifei_keys.h)

```c
/*
 * 易飞工具密钥表数据
 * 自动从运行时内存提取 (LyScript x32dbg)
 * 生成时间: 2025-05-26 10:30:45
 */

#ifndef YIFEI_KEYS_H
#define YIFEI_KEYS_H

#include <stdint.h>

/* 表1: 主密钥表 (16字节) */
/* 地址: 0x00511B30 */
static const uint8_t gvar_00511B30[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

/* 表2: 轮密钥表 (96字节 = 16轮 × 6字节) */
/* 地址: 0x00511B8A */
static const uint8_t gvar_00511B8A[96] = {
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, ... // 共96字节
};

#endif /* YIFEI_KEYS_H */
```

## 🔧 常见问题

### Q1: 连接失败 "服务不可用"

**原因**: LyScript 服务未启动

**解决方案**:
```
1. 检查 x32dbg 是否已启动
2. 检查 LyScript 插件是否已加载
3. 检查防火墙是否阻止 8000 端口
4. 尝试在 x32dbg 的插件管理器中重新加载 LyScript
```

### Q2: 内存读取失败

**原因**: 程序未初始化或内存不可访问

**解决方案**:
```
1. 确保程序已正常启动到主窗口
2. 在 x32dbg 中按 F5 继续执行
3. 点击易飞工具的查询按钮，触发内存初始化
4. 然后运行提取脚本
```

### Q3: 获取的是全 0xFF 或垃圾数据

**原因**: 内存地址未正确初始化

**解决方案**:
```
1. 在 x32dbg 中设置断点 0x0050CC98 (查询按钮处理函数)
2. 点击易飞工具的查询按钮
3. 程序暂停在断点处
4. 这时密钥表应已初始化，再运行提取脚本
```

### Q4: Python 包导入错误

**原因**: x32dbg 包版本不兼容

**解决方案**:
```bash
# 卸载并重新安装
pip uninstall -y x32dbg
pip install x32dbg==2.0.0

# 或升级到最新版本
pip install --upgrade x32dbg
```

### Q5: 生成的 C 头文件无法编译

**原因**: 数据格式错误或数据不完整

**解决方案**:
```
1. 检查 yifei_keys.json 中的数据是否完整
2. 确保表1 (16字节) 和表2 (96字节) 都已正确提取
3. 手动检查十六进制数据中是否有非 0x00-0xFF 的值
```

## 📝 使用场景

### 场景1: 简单数据提取

```python
from yifei_lyscript_extractor import YiFeiExtractor

# 创建提取器
extractor = YiFeiExtractor()

# 运行提取
if extractor.run():
    print("✓ 提取完成!")
```

### 场景2: 自定义处理

```python
from yifei_lyscript_extractor import YiFeiExtractor
import json

# 创建提取器
extractor = YiFeiExtractor("192.168.1.100", 8000)

# 连接调试器
if not extractor.connect():
    exit(1)

# 只提取表1
extractor.extract_table_1()

# 获取数据
table1_data = extractor.data["table_1"]["raw"]
print(f"Table1: {table1_data}")

# 自定义保存
with open("custom_output.json", "w") as f:
    json.dump(extractor.data, f)
```

### 场景3: 集成到解密工具

```python
from yifei_lyscript_extractor import YiFeiExtractor
import json

# 提取密钥
extractor = YiFeiExtractor()
extractor.run()

# 读取密钥
with open("yifei_keys.json") as f:
    keys = json.load(f)

# 使用密钥进行解密
table1 = bytes(keys["table_1"]["raw"])
table2 = bytes(keys["table_2"]["raw"])

# 调用您的解密函数
def decrypt_password(ciphertext, table1, table2):
    # 您的解密逻辑
    pass

plaintext = decrypt_password(ciphertext, table1, table2)
print(f"密码: {plaintext}")
```

## 🔍 故障排查

### 检查清单

```bash
# 1. 验证 Python 环境
python --version  # 3.7+

# 2. 验证 x32dbg 包
pip show x32dbg

# 3. 检查 x32dbg 进程
tasklist | grep x32dbg

# 4. 检查 LyScript 服务
# 在 x32dbg 中: View → Log window
# 查看是否有 "LyScript" 相关的加载信息

# 5. 测试 HTTP 连接
curl http://127.0.0.1:8000/
# 或在 Python 中:
import requests
requests.get("http://127.0.0.1:8000/")
```

## 📚 参考资源

- **LyScript 官方仓库**: https://github.com/lyshark/LyScript
- **x32dbg 官方网站**: https://x64dbg.com/
- **x32dbg Python API 文档**: https://pypi.org/project/x32dbg/

## ⚖️ 法律声明

本工具仅供学习和研究使用。使用者需遵守相关法律法规，对非法使用造成的后果自行承担责任。

## 📧 问题反馈

如有问题或建议，欢迎提交 Issue 或 Pull Request。

---

**最后更新**: 2025-05-26

**版本**: 1.0

**作者**: Security Researcher

**许可证**: MIT
