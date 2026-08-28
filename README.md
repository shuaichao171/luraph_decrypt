# Luraph Lua 恢复工具包

本目录汇总了本项目中已经验证的 Luraph 恢复方法和所需脚本。它针对的不是 AES 一类通用加密，而是以下组合：

1. LPH 自定义文本封装；
2. Luraph 变体 ASCII85 数据编码；
3. 序列化常量、opcode 和操作数；
4. Lua VM 虚拟化、控制流平坦化和完整性守卫；
5. 由运行环境决定的延迟 callback 和目标模组成功分支。

LPH 文本层可以无损解码，但解码结果不是原始 Lua。真正的还原工作是捕获虚拟机执行、恢复 opcode handler、生成指令级伪 Lua，再用窄夹具验证业务副作用并重写为高层业务 Lua。

完整案例、字段证据和精度边界见 [RECOVERY.md](RECOVERY.md)。

## 环境要求

- Windows PowerShell 5.1 或 PowerShell 7；
- Python 3.11 或更高版本；
- `uv`；
- 动态追踪依赖 `lupa`；
- AST 和可读化依赖 `luaparser`；
- 测试依赖 `pytest`，静态检查依赖 `ruff`。

脚本默认通过 `uv run --no-project --with ...` 临时提供依赖，不要求预先创建虚拟环境，也不会因本目录中的 `pyproject.toml` 创建持久 `.venv`。

## 目录内容

```text
luraph/
  README.md                 本文件：方法、逻辑和快速使用
  RECOVERY.md               当前项目的完整恢复记录
  run_recovery.ps1          恢复一个 Luraph Lua
  run_all.ps1               批量恢复一个目录中的 Lua
  run_probe.ps1             用 loaded-mod 夹具触发业务成功分支
  verify.ps1                运行工具测试和静态检查
  examples/
    fixture.example.json    loaded-mod 夹具结构示例
    environment.example.json 数据环境示例
  tools/
    luraph_recover.py       LPH 解码、隔离 Lua runtime、动态 VM trace
    luraph_devirtualize.py  VM 布局识别、opcode handler 静态裁剪
    recover_script.py       单文件完整恢复编排入口
    luraph_readable.py      基本块、CFG、局部传播和 focus 输出
    probe_business.py       可复现业务成功分支探针
    audit_recovery.py       解码、IR、handler、listing 强制审计
    audit_readable.py       CFG、goto、块覆盖和未知 handler 审计
    compact_programs.py     program IR 常量和指令行池化
    trace_modmain.py        非 LPH 单行 VM 的受限备用追踪器
  tests/
    test_luraph_recover.py
    test_trace_modmain.py
```

## 快速开始

恢复单个文件并生成 readable/CFG，再运行审计：

```powershell
cd C:\Users\shuaichao\Desktop\1111\3787391869\luraph
.\run_recovery.ps1 `
    -Source ..\scripts\Legion.lua `
    -OutputRoot ..\recovered
```

批量恢复目录内所有 `.lua`：

```powershell
.\run_all.ps1 `
    -SourceDirectory ..\scripts `
    -OutputRoot ..\recovered
```

复用已有 program IR，只重新生成 handler/listing：

```powershell
.\run_recovery.ps1 `
    -Source ..\scripts\Legion.lua `
    -OutputRoot ..\recovered `
    -ReuseTrace
```

运行工具测试：

```powershell
.\verify.ps1
```

## 还原步骤和核心逻辑

### 1. 提取 LPH payload

`extract_payload()` 从 Lua loader 中定位唯一的 `LPH?` 或 `LPH~` 长字符串。不要用简单正则截取任意长字符串；loader 中可能还有反调试数据或模板字符串。

提取后立即记录输入文件和解码结果的 SHA-256，后续 trace、handler 和 listing 都必须能回到同一份二进制输入。

### 2. 解码 Luraph ASCII85 变体

`decode_lph_base85()` 的逻辑：

1. 验证 `LPH` 头并跳过 4 字节头部；
2. 把 `z` 展开为 `!!!!!`；
3. 每 5 个字符组成一组；
4. 每个字符减 33，字符值必须在 `0..84`；
5. 按 85 进制累积为 32 位整数；
6. 按 32 位小端序输出 4 字节。

这一层只是可逆编码。输出仍是 Luraph loader 的序列化数据，不是源码文本。

### 3. 自动识别 VM 布局

去掉 loader 末尾对 payload 返回函数的调用，并修正 Lua 5.1 宽松转义后，由 `luaparser` 构造 AST。工具在匿名函数中寻找满足以下条件的循环：

- 循环是 `while` 或 `repeat`；
- local 初始化包含 `instruction_table[pc]`；
- 循环内有大型 opcode `if/elseif` 分派树；
- PC 在循环中推进。

据此推断：opcode 变量、指令表 upvalue、PC 变量、虚拟寄存器表、完整性状态表。不能把某个样本的随机变量名硬编码到算法里。

### 4. 动态追踪 VM fetch

`trace_vm_fetches()` 不替换真实操作数，而是把指令表换成转发代理。每次读取 `instructions[pc]` 时记录：

- program 和 closure context；
- PC、opcode、VM 嵌套深度；
- 当前 PC 能看到的操作数快照；
- 新创建的 VM closure 和注册 callback。

必须区分：

- code program：按底层指令表身份去重；
- closure context：同一 program 绑定不同 upvalue/常量时分别保存。

只按 program 去重会混合不同 closure 的常量，造成错误伪代码。

### 5. 在隔离 DST 环境中展开回调

未知 DST 全局使用惰性代理，记录索引、赋值和调用。`Add*PostInit` 的函数参数会作为 callback 保存并按预算执行，借此暴露延迟创建的 VM closure。

隔离 runtime 禁止文件、网络、进程、真实 `ffi/jit`、包加载和 Python builtins。不要为了“多走分支”把所有未知比较统一设为 true，这会进入互斥假路径并耗尽 fetch 预算。

### 6. 恢复 opcode handler

动态 trace 给出实际 opcode 集合。`luraph_devirtualize.py` 对 VM 分派树逐个代入 opcode，求值比较表达式并裁剪不可能分支。

选择 handler 时不能直接取循环内第一个 `if`，因为它可能是完整性守卫。工具会比较候选树的 opcode 覆盖量，并依据虚拟寄存器、操作数、PC/return、跨 opcode 重复和完整性特征排序。所有候选和最终选择都写入 handler JSON，便于复核。

### 7. 生成指令级伪 Lua

将随机操作数表访问替换成对应 PC 的真实值，将可确认的虚拟寄存器改名为 `rN`，保留 `::Lxxxx::`、opcode 和原始 context。这个阶段优先保持可审计性，不猜原变量名，也不强行把跳转重构成高层 `if/while`。

### 8. 生成 readable、focus 和 CFG

`luraph_readable.py` 继续进行保守变换：

- 删除不引用 PC/寄存器的重复完整性噪声；
- 展开可证明的完整性守卫；
- 把 PC 赋值改为 `goto Lxxxx`；
- 划分基本块并计算前驱、后继；
- 把越界目标标记为 `vm_integrity_trap()`；
- 只在基本块内做常量和复制传播；
- 按领域常量生成较小的 `focus.lua`。

`readable.lua` 仍是控制流伪 Lua，不是最终可维护源码。

### 9. 用窄夹具恢复业务语义

`probe_business.py` 为目标模组逐项提供 `KnownModIndex`、`ModManager`、registry、API、组件和 metatable 方法。一次只改变一个条件，并比较：

- API 调用参数和多返回值；
- `debug.getupvalue/setupvalue`；
- raw 字段、metatable `__index` 和最终函数身份；
- registry 字段修改前后；
- callback 类型、prefab/class 名和定时延迟；
- 首次修补与重复修补的差异。

证据优先级为：直接动态证据、静态 VM 证据、跨脚本旁证、明确的未触发边界。只有最终状态和调用行为被确认后，才写入 `*.business.lua`。字段名出现过不等于它一定被修改。

### 10. 强制审计

恢复完成后必须检查：

- decoded SHA-256 与 summary 一致；
- program/context 和常量池引用合法；
- 所有实际 opcode 都有非空 handler；
- listing 没有 `UNKNOWN_HANDLER`；
- CFG 块完整覆盖指令；
- 前驱、后继互相一致；
- 没有指向不存在标签的 `goto`。

审计脚本退出码必须为 0。

## loaded-mod 探针

复制并修改 `examples/fixture.example.json` 与 `environment.example.json`，然后执行：

```powershell
.\run_probe.ps1 `
    -Source ..\scripts\Xuaner_Myxl.lua `
    -Fixture .\examples\fixture.example.json `
    -Environment .\examples\environment.example.json `
    -InstructionUpvalue h `
    -EnvironmentUpvalue Z `
    -CallbackLimit 0
```

复杂 JSON 会由 `run_probe.ps1` 读取 UTF-8 字节并编码为 Base64，避免 PowerShell 改写引号或中文。

## 主要产物

```text
recovered/
  <name>.recovered.lua                    指令级伪 Lua
  artifacts/decoded/<name>.lph.bin        LPH 无损解码结果
  artifacts/decompiled/<name>.root.source.lua
  artifacts/programs/<name>.programs.json program/context IR
  artifacts/handlers/<name>.handlers.json opcode handler 及候选
  artifacts/summaries/<name>.json          哈希、计数和路径索引
  artifacts/readable/<name>.cfg.json       CFG 与可读化报告
  readable/<name>.readable.lua             完整可读控制流
  readable/<name>.focus.lua                领域相关 context 子集
  readable/<name>.observed.lua             已观察路径子集
  readable/<name>.business.lua             人工证据约束的业务重建
```

## 常见错误

- 认为 Base85 解码结果就是源码；
- 用结束态操作数代替 PC 第一次 fetch 快照；
- 只按 program 去重，不区分 closure context；
- 选择循环内第一个 `if` 当 opcode 分派树；
- 替换 `debug/load/loadstring` 后继续采信反调试路径；
- 给所有未知代理返回 true，制造互斥假路径；
- 只看到字段名就编写修改逻辑；
- 忽略 Lua 多返回值中的中间 `nil`；
- 只检查普通表字段，不检查 metatable `__index`；
- 把 `UNKNOWN_HANDLER = 0` 误解为原始变量名和高层结构已恢复。

## 精度边界

可以可靠恢复的是 LPH 数据、已观察 VM 指令、常量、handler 语义、注册点、参数、返回值和可观察副作用。原变量名、注释、格式、被编译消除的高层结构以及未创建的 closure 通常不可逆。最终 `business.lua` 是证据约束的语义重建，不是原作者逐字源码，也不应直接覆盖原模组文件。
