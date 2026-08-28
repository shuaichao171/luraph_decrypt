# Luraph business 业务语义还原手册

本文补充从指令级恢复产物到 `*.business.lua` 的完整过程。研究日期为
2026-08-28，DST 源码锚点以本机当前安装版本为准：

`D:\steam\steamapps\common\Don't Starve Together\data\scripts`

business 还原不是再次“解密”。LPH 解码和 VM 去虚拟化只能得到实际执行过的
指令、常量、分支、closure 和外部调用。business 阶段要用受控运行实验确认对象
身份、参数、返回值和最终副作用，再把这些证据重写成可读的高层 Lua。

在本仓库中，“解密/还原”默认包含这一阶段。除非任务明确限定只交付 VM/CFG
中间证据，否则每个输入都必须生成对应的 `*.business.lua` 并通过业务合同测试。

## 1. 输出的含义

各类产物代表不同层级：

| 产物 | 能证明什么 | 不能证明什么 |
|---|---|---|
| `*.recovered.lua` | 已观察 context 的指令级语义 | 原变量名和高层控制结构 |
| `*.readable.lua` | 基本块、跳转和局部传播结果 | 目标模组成功分支必然发生 |
| `*.focus.lua` | 含强领域常量的优先阅读子集 | 不在 focus 中的代码无关 |
| `*.observed.lua` | 当前夹具实际走过的路径 | 未触发路径的副作用 |
| `*.business.lua` | 证据约束下的高层业务重建 | 原作者逐字源码或可直接替换的模组文件 |

因此，`business.lua` 的完成标准不是“没有寄存器和 goto”，而是每个写操作、
wrapper、调度和返回行为都能回到可重复的动态证据或明确标注的静态边界。

## 2. 必需输入和脚本

开始 business 阶段前应先完成普通恢复：

```powershell
cd C:\Users\shuaichao\Desktop\ai-work\luraph_decrypt

.\run_recovery.ps1 `
    -Source .\run\code\Legion.lua `
    -OutputRoot .\run\recovered
```

需要保留的输入如下：

| 路径 | 用途 |
|---|---|
| 原始 Luraph Lua | 每轮探针的唯一执行输入 |
| `artifacts/programs/*.programs.json` | program/context IR、VM upvalue 名称和 first-fetch |
| `artifacts/handlers/*.handlers.json` | opcode handler 与静态分支证据 |
| `artifacts/readable/*.cfg.json` | 基本块、跳转目标和领域常量 |
| `readable/*.readable.lua` | 完整控制流证据 |
| `readable/*.focus.lua` | 优先定位 API、字段和字符串 |
| fixture JSON | 控制 loaded mod、目标对象和探针能力 |
| environment JSON | 控制全局 registry、API、玩家和库存对象 |
| 每次探针的 JSON 输出 | 保存直接动态证据 |

本轮 `business/` 按 `run/code/` 的输入集合提供 Main、Legion 和 Xuaner_Myxl
三份高层重建；`tests/test_business_lua.py` 会检查输入与 business 文件名集合
完全一致，并执行存在文件的对应合同测试。`run/recovered/` 仍用于本地生成
可审计的 VM 中间产物。

关键脚本：

- `run_probe.ps1`：安全传递 UTF-8 fixture/environment，并运行探针；
- `tools/probe_business.py`：调用 `trace_vm_fetches()` 并筛选报告；
- `tools/luraph_recover.py`：隔离 Lua runtime、DST 代理和全部 fixture 实现；
- `tools/luraph_readable.py`：生成 readable/focus/CFG；
- `tools/audit_recovery.py` 与 `tools/audit_readable.py`：检查 VM 层完整性。

## 3. 证据等级

结论按以下顺序采用，低等级不能覆盖高等级：

1. **直接动态证据**：调用参数、返回槽、`debug.setupvalue`、`rawset`、
   函数身份变化、最终表状态、注册 callback 和定时延迟。
2. **静态 VM 证据**：已切片 handler 中的常量、字段、比较和赋值，但夹具尚未
   进入该分支。
3. **跨脚本旁证**：Main 中的 workshop ID、配置键或相邻桥接脚本行为，只能
   帮助命名和构造夹具。
4. **证据边界**：真实依赖缺失或分支未触发时，只记录读取面、候选谓词和统计，
   不选择一个“看起来合理”的实现。

每条业务结论至少记录：

```text
结论:
证据等级:
输入 fixture/environment:
触发的 program/context/PC:
关键事件:
修改前状态:
修改后状态:
负向对照:
重复执行结果:
仍未知:
```

## 4. 完整流程

### 4.1 建立可审计基线

先运行普通恢复和两级审计。确认：

- `root_ok=true`；
- 没有因 fetch budget 中止；
- 实际 opcode 均有 handler；
- `UNKNOWN_HANDLER=0`；
- CFG 指令覆盖和 goto 目标正确。

VM 层不完整时不能直接开始写 business，因为缺失 handler 会让“没有副作用”
成为假阴性结果。

### 4.2 找业务锚点

优先搜索以下内容：

- `KnownModIndex`、`ModManager` 和 workshop ID；
- `AddSimPostInit`、`AddPrefabPostInit`、`AddPlayerPostInit`；
- `DoTaskInTime` 及延迟常量；
- registry、API、controller、component 和 metatable 字段；
- `debug.getupvalue/setupvalue`、`rawget/rawset/pairs`；
- 日志格式串和统计字段。

示例：

```powershell
rg -n "KnownModIndex|ModManager|Add.*PostInit|DoTaskInTime" `
    .\run\recovered\readable\Legion.focus.lua

rg -n "CU|oU|cU|qU|wfi7hy0ff_L|SetBuild" `
    .\run\recovered\Legion.recovered.lua
```

字符串或字段出现只表示它被读取、比较或写入过，不能单独证明修补行为。

### 4.3 确认 VM upvalue 名称

`run_probe.ps1` 需要 instruction 和 environment 两个 upvalue 名称。它们来自
`*.programs.json`，不要照抄其他脚本的随机名称：

```powershell
rg -n '"(instruction|environment)_upvalue_name"' `
    .\run\recovered\artifacts\programs\Legion.programs.json
```

本轮 Legion 的值为 `C` 和 `c`。不同 Luraph 文件通常不同。

### 4.4 运行最小基线探针

先使用最小 loaded-mod fixture，只观察脚本查询了什么：

```json
{
  "kind": "loaded_mods",
  "loaded_mods": ["workshop-target"],
  "probe_mod_values": true,
  "probe_known_mod_methods": true,
  "probe_known_mod_result_fields": true,
  "probe_mod_manager_result_fields": true,
  "mod_environment_missing_fields_are_nil": true
}
```

运行：

```powershell
.\run_probe.ps1 `
    -Source .\run\code\Legion.lua `
    -Fixture .\examples\business-baseline.fixture.json `
    -Environment .\examples\environment.example.json `
    -InstructionUpvalue C `
    -EnvironmentUpvalue c `
    -CallbackLimit 0 `
    -KeepDebugEvents
```

先设 `CallbackLimit 0` 能分开根 closure 与延迟 callback 的行为。随后再把它
提高到 1、目标 callback 数量和 20，比较新增 context 与事件。

上述命令已在 2026-08-28 对仓库中的 Legion 样本实测：`ok=true`、
`fetch_count=323835`、`stopped_by_budget=false`、捕获 2 个 callback 且展开 0
个。fixture 事件确认脚本调用 `GetModsToLoad(true)`、`GetModInfo` 并读取
`name`；全局事件记录了 Sim、world 和 cave 注册面。

### 4.5 一次只补一个分支条件

根据基线事件逐步增加 fixture 字段。例如脚本读取
`KnownModIndex:GetModInfo(...).name` 时，加入：

```json
{
  "probe_known_mod_methods": true,
  "probe_known_mod_result_fields": true,
  "known_mod_result_fields": {
    "name": "[DST] Legion"
  }
}
```

脚本调用 `ModManager:GetMod` 后读取目标对象时，再加入：

```json
{
  "probe_mod_manager_result_fields": true,
  "mod_environment_fields": {
    "postinitfns": {},
    "Registry": {}
  },
  "probe_mod_seed_tables": true,
  "record_fixture_mod_environment_final_state": true
}
```

每次只改变一个条件，并保留上一轮输出。若同时把所有未知比较设为 true，
可能进入原本互斥的递归、重试或完整性路径。fetch budget 耗尽只说明该夹具
无效，不能证明成功分支存在。

### 4.6 展开 callback 和调度

隔离环境会捕获 `Add*PostInit` 注册的函数。按以下顺序验证：

1. 根 closure，`CallbackLimit 0`；
2. 每次只展开一个 callback；
3. 记录 callback 类型、prefab/class 名和新建 context；
4. 给 `DoTaskInTime` 记录延迟、回调身份和去重行为；
5. 最后才展开完整 callback 集。

同一业务函数可能在根入口、Sim、world、cave 和 player 路径重复调用。业务版
必须保留观察到的立即调用和重试组，同时用对象身份保证包装或调度幂等。

### 4.7 给目标对象播种并记录最终状态

fixture 与 environment 的职责不同：

- fixture 定义 loaded mod、`ModManager:GetMod` 返回对象、函数/upvalue 形状和
  记录开关；
- environment 定义全局 `PREFAB_SKINS`、registry、`TheInventory`、玩家、
  controller 和其他 DST 数据对象。

常用能力：

| 目的 | fixture 字段 |
|---|---|
| 观察全局表 | `probe_global_tables` |
| 观察目标 mod 表 | `probe_mod_seed_tables` |
| 给嵌套表播种方法 | `fixture_probe_table_function_fields` |
| 给目标 mod 嵌套表播种方法 | `mod_environment_table_function_fields` |
| 模拟 metatable `__index` 方法 | `global_table_index_function_fields` |
| 观察 `rawget/rawset` | `probe_fixture_raw_access`、`probe_mod_environment_raw_access` |
| 避免根 VM 完整性污染 | `defer_raw_access_probe_until_callbacks` |
| 配置函数返回对象 | `global_function_return_globals`、`global_table_function_return_globals` |
| 主动调用最终函数 | `invoke_fixture_functions` |
| 保留全部返回槽 | `record_fixture_function_all_results` |
| 保存最终表状态 | `record_fixture_probe_final_state` |
| 保存目标 mod 状态 | `record_fixture_mod_environment_final_state` |
| 探查某个 VM PC | `vm_probe_program`、`vm_probe_pc` 或 `vm_probe_pcs` |

字段全集以 `tools/luraph_recover.py` 和对应测试为准，可用下列命令枚举：

```powershell
rg -n -o 'runtime_fixture\.[A-Za-z0-9_]+' `
    .\tools\luraph_recover.py | Sort-Object -Unique
```

### 4.8 验证函数身份、参数和多返回值

仅看到字段从 function 变成 function 不足以证明 wrapper。至少要验证：

1. 修改前函数对象和修改后函数对象是否相同；
2. 第二次修补后函数身份是否保持不变；
3. wrapper 向旧函数传递了多少参数；
4. 中间 `nil` 返回槽是否保留；
5. 目标输入和非目标输入是否走不同路径；
6. raw 字段与 metatable `__index` 方法是否分别验证；
7. 未命中的同名函数是否保持原身份。

推荐原函数返回：

```lua
return "first", nil, "tail"
```

调用结果使用 `select("#", ...)` 记录数量。否则 Lua 表会丢掉中间 nil，看起来
像只有一个或两个返回值。

### 4.9 验证 upvalue 修补

对 `debug.setupvalue` 路径记录：

- 被扫描函数的稳定角色，而不是 `tostring(fn)` 地址；
- upvalue 名称、索引和修改前值类型；
- 替换 closure 的身份和返回行为；
- 同一函数是否因对象身份去重；
- 嵌套 upvalue 扫描的深度与停止条件。

探针本身也会改变函数 upvalue 数量、来源和环境。依赖特定 upvalue 形状的
实验应使用普通种子函数；只有验证 wrapper 调用时才启用直接日志种子函数。

### 4.10 用 A/B 矩阵确定真正副作用

每个候选行为至少执行以下矩阵：

| 组别 | 输入 | 目的 |
|---|---|---|
| A | 目标缺失 | 验证缺失路径、日志和无写操作 |
| B | 只满足模组匹配 | 确认进入目标环境扫描 |
| C | 只增加一个候选字段/函数 | 确认该对象是否被读取或写入 |
| D | 目标记录与无关记录并存 | 验证选择谓词 |
| E | 第二次执行相同 callback | 验证幂等性 |
| F | 改变一个参数或返回槽 | 还原 wrapper 参数与返回语义 |

比较的不只是事件数量，还包括对象身份、最终表快照、callback 数量、program/
context 增量和 `stopped_by_budget`。

## 5. PATCH_SURFACE 如何继续还原

`PATCH_SURFACE` 表示已经知道“扫描或候选修补面”，但还不知道最终改写。它不是
可执行实现。按以下规则升级：

| 观察结果 | business.lua 处理 |
|---|---|
| 只读字段或签名，没有最终状态变化 | 保留证据注释或诊断计数 |
| 明确 `rawset` 或最终标量变化 | 写入对应字段修改 |
| 函数身份变化，调用行为已验证 | 写成幂等 wrapper 或替换 closure |
| 只知道函数名，没有参数/返回证据 | 仍保留边界，不实现 |
| 成功 fixture 和负向 fixture 都符合 | 可提升为已确认业务行为 |
| 只有宽夹具触发或耗尽 budget | 丢弃该实验结论 |

不要保留空的 `Unresolved()`，也不要把候选字段写成猜测逻辑。未解决项应说明：
已读取什么、哪一条件未触发、最终状态是否变化、需要什么下一轮实验。

## 6. Legion 实例

Legion 展示了如何把 PATCH_SURFACE 分成已确认修补和只读签名。

### 6.1 已确认事实

动态事件、最终状态和定向 fixture 共同确认：

- 通过 `KnownModIndex:GetModsToLoad(true)` 遍历模组；
- 通过 `GetModInfo(mod_name).name == "[DST] Legion"` 匹配目标；
- 使用 `ModManager:GetMod(mod_name)` 取得目标对象；
- 递归扫描表、函数和函数 upvalue，并按对象身份去重；
- upvalue `CU` 和 `oU` 分别替换为返回 false 的独立 closure；
- upvalue `cU` 替换为返回 true 的 closure；
- `wfi7hy0ff_L` 从 `"Kick"` 改为 `"GetUserID"`；
- `LS_C_Set`、`LS_C_Init`、`LS_C_Reskin` 被扫描但不会被主动调用；
- 成功后写入 `PRISM_TERRA_BRIDGE_LEGION_ENABLED = true`；
- 根入口立即尝试一次，并注册 Sim、world、cave 重试。

观察到的统计为：

```text
identity=0 kick=1 skin=1 integrity=1 crash=1
buildgate=0 functions=9 set=1 init=1 reskin=1
```

### 6.2 没有被提升为修补的内容

扫描器读取了：

- `qU` 的嵌套 upvalue；
- 表的数字键 `306`；
- `dataname == "AnimState"` 且 `fnname == "SetBuild"` 的描述表。

但多个身份 fixture 都没有增加 `identity`，完整 SetBuild 描述表也没有发生
修改，`buildgate` 始终为 0。因此这些内容只能保留为签名计数，不能写成
“绕过 SetBuild”。这正是从旧 `Unresolved` 或 `PATCH_SURFACE` 走向可读代码
时必须保留的证据边界。

### 6.3 高层重构映射

仓库中的 [Legion 业务版](business/Legion.business.lua) 按以下职责组织：

```text
is_legion_mod
  -> try_apply_prism_bridge
      -> patch_legion_environment
          -> scan_value / scan_table / scan_function
  -> schedule_prism_bridge_attempts
  -> on_sim_post_init
  -> reconstructed_root
```

VM 的寄存器复制、PC 跳转和完整性噪声不进入业务版；目标谓词、已确认写操作、
统计字段、重试延迟和未解决边界必须保留。

## 7. 编写 business.lua

推荐结构：

1. 目标 ID、显示名、字段名和延迟表；
2. 小型纯函数和替换 closure；
3. registry/controller/upvalue 扫描函数；
4. 单次 `patch_target_environment()`；
5. 模组发现和成功/缺失分支；
6. 幂等调度函数；
7. DST PostInit 注册；
8. 返回 `reconstructed_root`。

业务版应满足：

- 不含 VM PC、虚拟寄存器和 `UNKNOWN_HANDLER`；
- 不伪造原变量名和注释；
- 不调用只被观察到“存在”的导出函数；
- wrapper 保留已验证的参数数量和多返回值；
- 重复执行不会形成 wrapper 套 wrapper；
- 对未验证的主机、客机、分片、RPC、所有权和皮肤校验语义保持边界；
- 文件头明确说明它是语义重建而非 drop-in 源码。

## 8. business 合同测试

VM 审计不能代替业务测试。每个 `*.business.lua` 应有项目专属的 Lupa 测试，
至少覆盖：

- 目标模组存在和不存在；
- 目标记录和无关记录并存；
- registry 修改前后；
- raw 字段与 metatable `__index`；
- wrapper 参数数和中间 nil 返回槽；
- 替换函数返回行为；
- callback 类型、prefab 名和延迟顺序；
- 第二次修补的对象身份；
- 未确认字段保持原样；
- 统计输出与原 VM 成功 fixture 一致。

推荐命令：

```powershell
uv run --no-project --with pytest --with lupa python -m pytest `
    -q -p no:cacheprovider tests\test_business_lua.py
```

测试中应保留原函数引用，并在第二轮修补后比较 `rawequal` 或 Lua 函数对象身份。
不要比较打印出来的 `function: 0x...` 文本。

## 9. 报告判读

`tools/probe_business.py` 默认输出以下核心字段：

| 字段 | 判读 |
|---|---|
| `ok` / `error` | 根执行是否正常完成 |
| `fetch_count` / `fetch_budget` | 是否接近预算 |
| `stopped_by_budget` | 为 true 时该轮不能作为成功证据 |
| `callbacks_captured/invoked` | 注册与展开数量 |
| `callback_results` | callback 错误和返回 |
| `fixture_events` | loaded-mod、upvalue、raw access、调用和最终状态 |
| `global_events` | DST API 注册及未知全局使用 |
| `program_summaries/context_summaries` | 仅在指定 `-Program` 时输出的 VM 明细 |

`-Full` 保留完整报告，`-Program` 只选择目标动态 program，`-KeepDebugEvents`
保留 `debug.getupvalue/setupvalue` 和函数环境事件。定位业务分支时先使用默认精简
报告，确认 program 后再加 `-Program`，避免把整份 IR 当作业务证据。

被分析脚本自己的 `print` 会直接出现在标准输出中，可能位于最终 JSON 之前。
因此保存报告时要同时保留这些日志，若要交给 JSON 解析器则只提取最后的 JSON
对象，不能假设整段 stdout 都是纯 JSON。

## 10. 当前 DST 源码锚点

以下是 2026-08-28 本机安装版的已验证事实：

| 接口 | 当前源码位置 | 已验证语义 |
|---|---|---|
| `KnownModIndex:GetModsToLoad` | `modindex.lua:267` | true 参数走 cached known mods 分支 |
| `KnownModIndex:GetModInfo` | `modindex.lua:317` | 从 `savedata.known_mods[modname].modinfo` 返回信息 |
| `ModManager:GetMod` | `mods.lua:267` | 从 `self.mods` 返回 modname 匹配的 mod 对象 |
| `AddSimPostInit` | `modutil.lua:341` | callback 写入 `postinitfns.SimPostInit` |
| `AddPlayerPostInit` | `modutil.lua:586` | 通过任意 prefab PostInit 和 player tag 调用 |
| `AddPrefabPostInit` | `modutil.lua:593` | callback 按 prefab 写入列表 |
| `EntityScript:DoTaskInTime` | `entityscript.lua:1522` | 交给 scheduler 延迟执行并登记 pending task |

这些源码锚点用于校验 fixture 是否模拟了真实接口形状，不表示隔离探针证明了
主机、客机、洞穴分片或前端环境中的全部行为。游戏更新后应重新核对行号和实现。

## 11. 常见错误

- 把 `readable.lua` 当作 business 源码；
- 字段出现过就认定它被修改；
- 把所有未知代理设为 true；
- 只看最终状态，不保存修改前基线；
- 只比较函数地址字符串；
- 忽略 Lua 多返回值中的中间 nil；
- 只测试普通表字段，不测试 metatable `__index`；
- 在根 VM 前替换 `rawget/rawset/getfenv/setfenv`，触发完整性分支；
- 用日志型种子函数改变待扫描函数的 upvalue 形状；
- fetch budget 耗尽后仍采信部分事件；
- 用相邻脚本的 workshop ID 或行为替代当前脚本自己的成功证据；
- 把只读签名计数写成真实修补。

## 12. 完成判定

一个 business 分支只有同时满足以下条件才算完成：

1. 根 closure 和所需 callback 均正常结束；
2. 使用窄 fixture 唯一触发目标路径；
3. 修改前后对象身份或表状态已有记录；
4. 参数数量、nil 槽和返回值已验证；
5. 目标与非目标输入已有负向对照；
6. 第二次执行已验证幂等；
7. 调度类型、prefab 和延迟已验证；
8. business 合同测试通过；
9. 仍未知的比较或副作用被明确标注，没有 `Unresolved` 空实现；
10. 每个结论能回到 fixture、环境、探针报告和当前 DST 源码锚点。

如果缺少其中任一项，应把结果描述为“已识别修补面”或“部分语义恢复”，而不是
“原始业务源码已完整恢复”。
