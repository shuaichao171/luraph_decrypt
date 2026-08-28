# Luraph 模组脚本还原记录

## 结论

`scripts/` 中的 10 个脚本不是用 AES 等通用密码算法加密，而是使用了 Luraph 的自定义封装、数据序列化和 Lua 虚拟机虚拟化。LPH 文本层可以无损解码；VM 中已经创建并实际执行到的 closure，则可以恢复为包含精确常量、虚拟寄存器、PC 标签、opcode 和 handler 语义的指令级伪 Lua。

恢复结果在 `recovered/*.recovered.lua`。这些文件是惰性的分析清单，不能直接替代原模组运行，也不等于原作者的逐字源码。原局部变量名、注释、空白以及大部分高层块结构在虚拟化编译时已经被丢弃，无法从现有数据唯一反推。

## 混淆层次

1. 外层是经过控制流平坦化和标识符随机化的 Lua loader。
2. loader 的长字符串中只有一个以 `LPH?` 或 `LPH~` 开头的 payload。
3. payload 使用 Luraph 变体的 ASCII85 编码；解码结果仍是 loader 使用的序列化数据，不是原始 Lua 文本。
4. loader 从数据中建立常量表、opcode 表和操作数表，再构造多个 VM closure。
5. VM 使用随机变量名、嵌套比较分派树以及 `while`/`repeat` 解释循环执行虚拟指令。
6. 外部 DST API、注册回调和目标模组是否存在，会决定运行时创建哪些 closure 和经过哪些分支。

因此，单独解开 LPH 层只能得到中间数据。源码还原的主体是捕获 VM、追踪虚拟指令并对 opcode 分派树做静态裁剪。

## LPH 解码算法

实现位于 `tools/luraph_recover.py` 的 `decode_lph_base85()`：

1. 验证字符串以 `LPH` 开头，跳过前 4 个字符的头部。
2. 将每个 `z` 展开成 `!!!!!`，即一个值为零的 32 位组。
3. 展开后的正文长度必须是 5 的倍数。
4. 对每组 5 个字符计算：

   ```text
   value = ((((c0 - 33) * 85 + (c1 - 33)) * 85
             + (c2 - 33)) * 85 + (c3 - 33)) * 85 + (c4 - 33)
   ```

5. 每个字符值必须在 `0..84`。
6. 将 `value & 0xffffffff` 按 32 位小端序写出 4 字节。

这一层是可逆编码，不提供现代密码学意义上的保密性。测试同时覆盖了小端字序、`z` 零组和非法输入。

## 还原流程

### 1. 提取和固定输入

`extract_payload()` 从每个脚本中提取唯一的 LPH 长字符串。解码后的二进制写入 `recovered/artifacts/decoded/`，并在 summary 中保存 SHA-256，用来确认后续分析使用的是同一份数据。

### 2. 提取 VM 根函数

工具仅去掉最末尾对 payload 返回函数的调用，并修正 Luraph 所依赖的宽松 Lua 5.1 字符串转义。随后使用 `luaparser` 构造 AST，从匿名函数中寻找 VM 循环：

- 循环可以是 `while` 或 `repeat`；
- 循环开头的 local 初始化中存在一次 `instruction_table[pc]` 读取；
- 循环内存在大型 `if/elseif` opcode 分派树；
- PC 在循环中递增。

由此自动推断五元 VM 布局：opcode 变量、指令表 upvalue、PC 变量、虚拟寄存器表和完整性状态表，不依赖某一份脚本的随机标识符。裁出的 VM 根函数位于 `recovered/artifacts/decompiled/`。

### 3. 动态追踪虚拟指令

`trace_vm_fetches()` 先遍历 root closure 可达的函数和表，找出所有持有同一类指令 upvalue 的 VM closure。它只把指令表替换成转发代理：读取 `instructions[pc]` 时记录 PC 和 opcode，实际返回值仍来自原表；其他操作数表保持原值。

追踪模型区分两种身份：

- code program：以底层指令表身份去重，同一份虚拟代码只保存一次；
- closure context：同一 code program 每次绑定不同 upvalue/常量表时单独记录。

这个区分很关键。只按指令表去重会把共享代码的不同 closure 常量混在一起，产生看似合理但实际错误的操作数。

每次 fetch 会记录当前 context、program、PC、opcode、VM 深度及该 PC 上所有可见操作数。追踪器还会在新 closure 被创建或调用时继续安装代理，从而覆盖嵌套 VM 程序。

### 4. 隔离 DST 环境并展开回调

真实游戏环境不在分析机上，因此未知全局和 DST API 使用惰性代理。代理记录取字段、赋值和调用；函数参数会被登记为回调，再用独立的惰性参数调用，以暴露注册函数内部创建的 VM closure。

隔离边界如下：

- `io`、`os`、`package`、`require`、`dofile`、`loadfile`、`module`、`ffi`、`jit` 和 `python` 均不可用；
- Lupa 禁止 Python builtins 和 `eval` 注册；
- 每个 Lua runtime 有 512 MiB 内存上限；
- 环境覆盖只允许数据，危险名称会被拒绝；
- 辅助 API 事件追踪器 `trace_payload()` 只允许 `loadstring` 编译 Luraph 已知的 forwarder 模板，其他动态源码会被记录但不执行；
- opcode fetch 和外部事件均有预算限制。

VM fetch 追踪器不能粗暴替换 VM 所见的 `load`、`loadstring` 或 `debug`，因为 Luraph 会把这种修改识别为篡改并进入反调试路径。它保留解释器需要的局部引用和动态编译能力，但这些代码仍在上述无文件、网络、进程、包和 Python 能力的隔离 Lua runtime 内执行。

### 5. 静态裁剪 opcode handler

动态追踪得到脚本实际出现的 opcode 集合。`tools/luraph_devirtualize.py` 对根 VM 的 AST 分派树逐个代入具体 opcode，求值 `==`、`~=`、`<`、`<=`、`>`、`>=` 及部分布尔组合，只保留可能到达的分派叶。

根循环中可能在真实 opcode 分派树之前出现独立的完整性守卫，所以不能简单选择循环内第一个 `if`。工具会比较候选树包含的 opcode 测试数量，选择覆盖最多实际 opcode 的分派树。若控制流混淆留下多个候选叶，则根据虚拟寄存器操作、操作数读取、PC/return 操作、跨 opcode 重复频率和完整性叶特征排序，并在 handler JSON 中同时保存选中项和所有候选项，便于人工复核。Xuaner 的 opcode `179` 确认为空分派叶，按 no-op 输出，不是漏提取。

### 6. 实例化为指令级伪 Lua

每个 context 的指令行会把 `h[B]`、`O[B]`、`W[B]` 等随机操作数表读取替换为该 PC 的精确值，并把可识别的 `z[n]` 虚拟寄存器改写为 `rN`。每条指令保留 `::Lxxxx::` PC 标签和原 opcode，方便从 listing 回查 IR 与 handler 证据。

输出刻意保持惰性，不尝试猜测已经丢失的变量名或强行重构 `if`、`for`、函数声明等高层语法，以免把猜测混入可验证结果。

### 7. 生成可读控制流版本

`tools/luraph_readable.py` 在指令级 listing 上继续做保守变换：

- 删除多个 handler 重复出现、且不引用 PC 或虚拟寄存器的完整性噪声语句；
- 展开能够确定有效语义分支的完整性守卫；
- 将 PC 赋值改写为 `goto Lxxxx`，按 leader 划分基本块并计算前驱、后继；
- 将超出当前 closure PC 范围的目标显示为 `vm_integrity_trap("Lxxxx")`，同时保留在 CFG 报告中；
- 仅在基本块内部做常量和复制传播，遇到分支、调用式复杂语句或多行结构即停止传播；
- 将可确认的 VM closure 构造折叠为 `vm_closure(opaque_table)`；
- 按 DST API、workshop ID、skin/prefab/mod 等强领域常量生成较小的 `focus.lua` 阅读入口。

这一步输出的是“已观察 closure 的可读控制流伪 Lua”。它改善导航和局部表达，但不会猜测原变量名，也不会把不可证明的跳转强行重构成 `if`、`while` 或业务函数。

### 8. 池化与审计

不同 context 往往共享大量字符串和指令行。`compact_trace()` 将字符串常量放入 `constant_pool`，将唯一指令行放入 `instruction_rows`，program/context 只保存一基索引，格式标记为 `luraph-context-ir-v2`。读取时可由 `expand_compact_trace()` 无损展开。

`tools/audit_recovery.py` 检查：

- 解码文件 SHA-256；
- program/context 指令引用范围；
- 常量池引用范围；
- 实际 opcode 是否都有非空 handler；
- listing 中是否仍有 `UNKNOWN_HANDLER`。

`tools/audit_readable.py` 另外检查 context/基本块计数、指令覆盖、前后继互反、未知 opcode，以及源码中是否仍存在没有对应标签的 `goto`。

## 第二阶段：业务语义重建

指令级 `readable.lua` 仍保留虚拟寄存器、PC 标签和大量 VM 控制流，因此不能直接视为可维护 Lua。第二阶段以这些文件和动态 trace 为证据，将代码重新组织成 `*.business.lua`。历史研究曾覆盖 10 份脚本；当前 `business/` 只保存与本轮 `run/code/` 输入集合一致的可复核副本，并用 `tests/test_business_lua.py` 验证。本地自动恢复产物仍留在 `run/recovered`。但“存在业务版”不表示目标模组成功分支已经完整；每份文件都必须以已触发的副作用和最终对象身份为完成标准。

这一阶段遵循四级证据：

1. **直接动态证据**：外部 API 调用、参数、定时延迟、`debug.getupvalue/setupvalue`、函数环境、`rawget/rawset` 和最终表状态。
2. **静态 VM 证据**：已经选定 handler 的常量、字段名、分支和赋值，但当前夹具没有经过该分支。
3. **跨脚本旁证**：例如九个 workshop ID 和版本来自 Main，只用于标识目标，不冒充各兼容脚本自己的原始谓词。
4. **证据边界**：真实目标模组未加载，多个返回值或副作用都符合现有控制流时，只列出修补面和统计字段，不选择其中一个“看起来合理”的实现。

### 从 VM 代码到业务代码的流程

1. 对每个 context 保存 PC 第一次 fetch 时的完整操作数快照。handler 可能在运行中改写操作数表，使用结束态会把真实跳转目标替换成后来的值。
2. 合并 first-fetch、operand variant 和静态 handler 结果，先恢复外部调用、字符串常量、表字段与 closure 创建。
3. 在隔离 DST 代理环境中展开 `Add*PostInit` 回调，记录注册类型、prefab/class 名称和 `DoTaskInTime` 延迟。
4. 构造窄的 loaded-mod 夹具，逐项提供 `KnownModIndex`、`ModManager` 和目标环境字段。一次只改变一个条件，比较新创建的 context 和外部事件。
5. 对 upvalue 修补路径记录函数对象身份、upvalue 名称/索引、替换 closure 身份和去重次数；不能只比较打印出来的函数地址文本。
6. 对扫描表使用 `rawget/rawset/pairs` 探针，并在回调结束后保存最终状态快照，用“修改前/修改后”确认真实副作用。
7. 将确认过的循环、注册点、重试列表、目标字段和统计项命名为业务函数；删除 VM 完整性噪声和寄存器搬运。
8. 未唯一确定的成功路径写成证据边界注释或声明式修补面。业务版不保留空的 `Unresolved` 实现，也不虚构会影响联机所有权、RPC 或皮肤校验的返回值。

loaded-mod 夹具必须足够窄。把所有未知字段和判断统一设为 true，会进入原本互斥的递归/重试分支；Book、Deng、HMR 和 Niaoniao 的宽泛实验均出现了这种假路径，并耗尽 200 万 fetch。这类结果只说明夹具无效，不能用作业务证据。

### 可复现 loaded-mod 探针

`tools/probe_business.py` 将单个脚本、VM upvalue 布局、loaded-mod 夹具和数据环境固定为一条可复现命令。PowerShell 会改写复杂 JSON 的引号，夹具中还可能含中文显示名，因此实际使用时优先把 UTF-8 JSON 编码为 Base64：

```powershell
uv run --with lupa --with luaparser python -m tools.probe_business `
    scripts\Niaoniao_Character.lua `
    --fixture <FIXTURE_JSON_BASE64> `
    --environment <ENVIRONMENT_JSON_BASE64> `
    --instruction-upvalue J `
    --environment-upvalue C `
    --callback-limit 20 `
    --keep-debug-events
```

夹具能力按证据目标组合使用：

- `probe_global_tables` 递归记录种子表的普通索引、`pairs`、`rawget/rawset` 和最终状态；
- `fixture_probe_table_function_fields` 按已记录路径给嵌套表播种函数，例如玩家组件中的 skin controller；
- `mod_environment_table_function_fields` 在 `GetMod` 创建目标环境后给其嵌套表播种函数，避免早于目标表创建的夹具时序错误；
- `probe_mod_environment_raw_access` 单独记录 `ModManager:GetMod` 返回环境上的 `rawget/rawset`；与 `defer_raw_access_probe_until_callbacks` 组合时，只在根 VM 完成后安装，避免污染 Luraph 完整性检查；
- `mod_environment_function_sources` 用指定 chunk source 构造含 16 个显式 upvalue 的 Lua 函数，可对照 `debug.getinfo(...).source`、upvalue 数量和目标路径的联合筛选；
- `global_table_function_return_globals` 为记录型 API 种子函数配置单个或多个返回对象，可观察包装器的返回后处理；
- `global_function_return_globals` 为顶层种子函数配置多返回值，用于验证全局 wrapper 是否完整保留返回槽；
- `global_table_index_function_fields` 把指定方法播种到全局表 metatable 的 `__index` 表中，并注册 `GLOBAL.<name>.__index` 探针路径；这用于还原对象没有 raw 方法字段时的真实调用面；
- `fixture_probe_table_function_return_globals` 为玩家组件等嵌套路径上的种子函数配置多返回值；
- `invoke_fixture_functions` 在回调展开后调用最终函数；参数项使用 `{"fixture_probe": true, "path": "...", "value": {...}}` 时会记录参数表读写和结束态，使用 `{"fixture_nil": true}` 可在参数序列中保留显式 nil 槽；
- `record_fixture_table_seed_function_calls` 记录表内种子函数收到的参数，`record_fixture_table_argument_entries` 额外保存未知表参数的一层标量快照；
- `record_fixture_function_all_results` 记录返回值数量和每个返回槽，能区分 `first, nil, tail` 与单返回值；
- `record_fixture_probe_final_state`、`record_fixture_mod_environment_final_state` 和 `record_fixture_global_fields` 用于比较函数角色和字段最终身份。

`record_fixture_table_seed_function_calls` 会用直接日志函数替换种子函数，只适合验证 controller/API 包装器。Deng 等依赖特定 upvalue 索引和布局的扫描必须使用普通种子函数，并单独记录 `debug.getupvalue`；否则夹具自身会改变待识别签名。函数环境记录也是可选项：Xuaner 在替换 `getfenv/setfenv` 后会进入完整性路径，Shugo 在根 VM 前替换 `rawget/rawset` 也会耗尽预算。这类结果只能说明探针侵入性过强，不能解释成业务分支；Shugo 的 raw-access 结果只采用延迟到回调阶段且根 closure 正常完成的实验。

### 非 LPH 目标模组探针

`tools/trace_modmain.py` 用于本轮遇到的另一类单行 VM。它把真实 `modmain.lua` 包进 Lua 5.1 closure，以实际模组环境语义执行，并记录 DST API 回调、环境导出和未知全局。文件、网络、进程、包加载及真实 FFI 均不可用；`require("ffi")`、`require("jit")` 只返回不能访问本机的常量桩。

已安装的 `workshop-3014076942` 真实 `modmain.lua` 在该沙箱中执行到约 866.9 万条指令，越过 bit 解码和随机全局完整性哨兵，随后因缺少其外部授权 JSON 数据而在目标 VM 内停止。停止前没有产生业务回调或皮肤注册导出，因此这次真实模组执行只确认了依赖边界，未用于补写 Xuaner 成功分支。

本轮通过这个流程确认了几个此前只有“修补面”的分支：CCS 幂等包装 `CCSAPI.MakeCharacterSkin`，不读写可观察实参/返回表并保留多返回值；Niaoniao 生成 `prefab_name -> skin record` 映射、调用 controller 的 `UnlockSkin` 并只替换 `HasSkin`；Book 完成 registry、库存、验证器和 controller 修补；Deng 修补库存函数的命名 upvalue registry；Shugo 完成 registry、注册函数和校验函数修补；Xuaner 完成目标 registry、注册 API、库存 metatable 和三个全局 wrapper 修补。Xuaner 的其他顶层或嵌套同名安全函数不会仅因名字匹配而被替换。

### Book 的已确认 registry 与 wrapper 分支

Book 先通过 `KnownModIndex:GetModInfo` 确认 `workshop-3544387985`，再从 `ModManager:GetMod` 取得目标环境。成功夹具确认：

- 扫描目标环境的 `characterskins`、`itemskins`、`CHARACTERSKINS`、`ITEMSKINS`，并调用 `GetAllSkin()` 取得另外两个 registry；每条唯一记录只写 `checkfn = true closure`、`checkclientfn = true closure`、`unlock = true`，不会写 `is_restricted`；
- `MakeCharacterSkin`、`MakeItemSkin`、目标环境及全局的 `ValidateRecipeSkinRequest`、三个 `TheInventory.Check*Ownership` 都安装幂等透传 wrapper，完整保留四个测试实参及 `first, nil, tail` 多返回值；
- 目标环境和全局的 `TbatSkinCheckFn`、`TbatSkinCheckClientFn` 以及 `TheInventory.HasSupportForOfflineSkins` 改为恒真函数；
- `AllPlayers` 与 `ThePlayer` 的 `components`、`replica`、`replica._` 三种 `tbat_com_skins_controller` 路径只包装 `HasSkin`；`UnlockSkin` 保持原身份且修补阶段不调用；
- `GetSkin`、`GetSkinMap`、目标/全局 `TBAT.SKIN`、`postinitfns`、`BOOKOFALLTHINGS`、`PREFAB_SKINS`、`Sim` 和世界对象属于递归扫描/计数面，最终状态探针没有观察到修改；
- 根入口立即修补一次；世界延迟为 `0, 0.25, 1, 3, 8, 15, 30, 120`，玩家延迟为 `0.5, 2, 5`。

六条独立 registry 记录的首轮输出为：

```text
skins=6 data=18 upvalues=0 inventory=3 validators=2
```

`data=18` 对应六条记录各三个字段；第二次处理相同记录时 `skins` 仍为 6，而 `data` 降为 0。`functions` 是递归扫描到的唯一函数数量，不是被替换函数数量。

### Deng 的已确认 registry 分支

Deng 的三个 `TheInventory` 所有权函数使用 `namemaps`、`characterskins`、`itemskins`、`oldTheInventoryCheckOwnership` 四个命名 upvalue。成功夹具确认：

- `characterskins` 和 `itemskins` 中每条记录都写入 `checkfn = true closure`、`checkclientfn = true closure`、`unlock = true`、`is_restricted = false`；
- `characterskins` 的记录计入角色皮肤；
- `itemskins` 的普通记录计入物品皮肤，`ischaracterskins == true` 的记录改计入角色皮肤；
- `namemaps` 和旧所有权函数保持不变；
- 现有 UI 标志夹具没有触发 `ui_skins`。

两个记录的基础夹具输出为 `item=1 character=1 patched_now=2`；把物品记录的 `ischaracterskins` 设为 true 后为 `item=0 character=2 patched_now=2`。

### Xuaner 的已确认 registry、注册与库存分支

Xuaner 通过 `KnownModIndex:GetModsToLoad(true)` 定位 `workshop-3014076942`，再从 `ModManager:GetMod` 取得目标环境。成功夹具确认：

- 目标集合来自 `PREFAB_SKINS.moyuxuanli`，registry 中名称以 `moyuxuanli` 开头的条目也会被识别；同一 registry 中的无关角色和物品记录保持原样；
- 每条目标记录写入 `checkfn = true closure`、`checkclientfn = true closure`、`unlock = true`、`is_restricted = false`，不会修改 `check`、`all`、`owned`；
- `MYXLAPI` 及目标环境的 `MakeCharacterSkin`、`MakeItemSkin` 安装幂等 wrapper。签名为 `(prefab, skin_name, data)`，先修改第三个 `data`，再以恰好三个参数调用旧函数，并完整保留多返回值；
- `MYXLPushPopupDialog`、`SetSkinnedOvalPortraitTexture`、`DoRestart` 都替换函数身份；已验证输入下参数原样透传，`first, second, third` 三返回值也原样保留；
- `TheInventory` 的修补只在 metatable `__index` 方法表上发生，普通 raw 字段夹具不会触发。`CheckOwnership` 对目标皮肤返回 `true`，否则透传；`CheckOwnershipGetLatest` 对目标返回 `true, 0`，否则透传；`CheckClientOwnership` 始终调用旧函数 `(self, skin_name, nil)`；`HasSupportForOfflineSkins` 改为恒真；`ShouldDisplayItemInCollection` 保持原身份；
- `MYXLAPI` 和目标环境已有的 `myxlSkinCheckFn`、`myxlSkinCheckClientFn`、`myxlGetAllSkinCheckFn` 保持原身份，它们只贡献扫描计数；
- 写入 `PRISM_TERRA_BRIDGE_XUANER_ENABLED = true`。根入口立即修补一次；世界延迟为 `0, 0.25, 1, 3, 8, 15, 30, 120`，目标 prefab 延迟为 `0, 0.5, 2`，玩家延迟为 `0.5, 2, 5`。

两条目标记录的基础输出为：

```text
skins=2 data=8 owner=0 hooks=0 ui=0 compat=0 security=0 functions=0
```

`owner/hooks/ui` 是原 VM 的特定分支计数，不是“安装了多少 wrapper”；即使库存方法已被替换，它们仍可为 0。给 `TheInventory.__index` 播种四个方法时，`functions` 上升为 15。九项 workshop 比较和 `KillBan/FuckYtr/Reset` 等安全方法仍未满足目标特定谓词，业务版不为它们虚构副作用。

### Legion 的剩余边界

Legion 是成功路径证据最完整的脚本。已确认：

- 目标显示名为 `[DST] Legion`；
- 递归扫描表、函数及其 upvalue，并按对象身份去重；
- `CU` 和 `oU` 分别替换为返回 false 的独立 closure；
- `cU` 替换为返回 true 的 closure；
- 表字段 `wfi7hy0ff_L` 从 `Kick` 改为 `GetUserID`；
- 探测 `LS_C_Set`、`LS_C_Init`、`LS_C_Reskin`，但不调用它们；
- 写入 `PRISM_TERRA_BRIDGE_LEGION_ENABLED = true`。

最终夹具与原 VM 的统计一致：

```text
identity=0 kick=1 skin=1 integrity=1 crash=1
buildgate=0 functions=9 set=1 init=1 reskin=1
```

`qU` 会继续扫描其 upvalue，扫描器也会读取表的数字键 `306`，并识别 `dataname == "AnimState"`、`fnname == "SetBuild"` 的描述表。但是现有多个 `qU` 身份夹具都没有增加 `identity`；完整 SetBuild 描述表也没有被修改，`buildgate` 仍为 0。因此这三者目前只能解释为诊断/签名证据，不能还原成“绕过 SetBuild”之类的修补。Legion 业务版已删除字面 `Unresolved` 分支，改为只统计这两类证据签名。

### 业务版覆盖范围

| 脚本 | 已重建的高层内容 |
|---|---|
| Main | 九项目标配置、检测表、全局状态和六个已启用桥接脚本导入 |
| Legion | 模组匹配、递归 upvalue 扫描、三类 closure 替换、Kick 字段修补和统计 |
| Book_of_All_Things | 六类 registry 三字段写入、Make/库存/验证器/controller 幂等透传、三个恒真入口、函数扫描统计、立即修补和世界/玩家分组重试 |
| Cardcaptor_Sakura | `CCSAPI.MakeCharacterSkin` 幂等纯透传包装、实参/含 nil 多返回值保留、registration/characters 统计和世界重试 |
| Deng_Xian | 中文显示名匹配、库存函数命名 upvalue 扫描、皮肤记录四字段写入、角色/物品分类和 Sim/世界重试 |
| Harvest_Mysterious_Realm | 同步 API、网络回调、角色/物品 registry 四字段写入、统计、缺失日志和五级重试 |
| Niaoniao_Character | 皮肤记录/默认索引统计、解锁映射、controller 定位、`UnlockSkin` 调用、`HasSkin` 包装和三类调度 |
| Shugo_Chara | `GetAllSkin` 角色/物品 registry 四字段写入、三个恒真校验函数、两个 Make 注册函数幂等透传、立即修补和 Game/世界/玩家分组调度 |
| Void_Realm | TrSkin/VR Gate API、库存修补、RPC 注册、目标皮肤头像替换与普通头像 fallback |
| Xuaner_Myxl | 目标 registry 四字段写入、两个三参数 Make wrapper、库存 `__index` 所有权分流、三个全局透传 wrapper、启用标志、立即修补和三组重试 |

这些文件是“证据约束下的高层语义重建”，不是反编译器能够证明的原作者逐字源码。仍未触发的目标特定分支（例如 Xuaner 的兼容/安全谓词和依赖真实授权数据的目标模组路径）在得到调用及最终状态证据之前不能安全补写。

当前完成度不能用“文件数”概括：Main、Legion、Void、HMR、Deng 和 Xuaner 具有较多已验证写操作；CCS、Niaoniao、Book 和 Shugo 已恢复主要 registry/wrapper 副作用。Shugo 的成功路径已由 `GetAllSkin` 返回 registry 触发，早期 1/4/16 槽签名和延迟 raw-access 阴性结果只用于排除错误假设。Xuaner 的 bridge 成功路径已由窄 loaded-mod 夹具触发；真实目标模组自身仍受外部授权数据限制。表中只列已经写入业务版的内容，不把未触发计数器解释成已恢复实现。

## 当前结果

| 脚本 | Fetch | Programs | Contexts | Opcodes | 回调 | Root |
|---|---:|---:|---:|---:|---:|:---:|
| Book_of_All_Things | 255691 | 149 | 153 | 210 | 4/4 | OK |
| Cardcaptor_Sakura | 253516 | 133 | 135 | 182 | 2/2 | OK |
| Deng_Xian | 247372 | 129 | 131 | 193 | 2/2 | OK |
| Harvest_Mysterious_Realm | 198980 | 137 | 139 | 200 | 2/2 | OK |
| Legion | 320493 | 149 | 151 | 208 | 3/3 | OK |
| Main | 154293 | 146 | 148 | 172 | 0/0 | OK |
| Niaoniao_Character | 239826 | 155 | 157 | 206 | 3/3 | OK |
| Shugo_Chara | 211229 | 139 | 141 | 192 | 3/3 | OK |
| Void_Realm | 235940 | 154 | 156 | 217 | 2/2 | OK |
| Xuaner_Myxl | 405450 | 161 | 163 | 214 | 6/6 | OK |

这里的 `Root=OK` 表示隔离环境下根 closure 完成，没有因 fetch 预算中止。10 份 listing 的 `UNKNOWN_HANDLER` 均为 0。

Main 中恢复出的九个目标 workshop ID 为：

```text
1392778117  2526778484  3014076942
3043439883  3235319974  3544387985
3573399040  3609964985  3626093627
```

对应配置键为 `prism`、`voidrealm`、`dengxian`、`hmr`、`niaoniao`、`xuaner`、`shugo`、`book`、`ccs`。

## 产物说明

| 路径 | 内容 |
|---|---|
| `business/*.business.lua` | 受版本控制、与当前输入集合一致的高层语义重建 |
| `business/README.md` | 当前业务文件索引、哈希失效规则和完成条件 |
| `recovered/*.recovered.lua` | 每个 closure context 的指令级伪 Lua |
| `recovered/readable/*.focus.lua` | 按强领域常量筛选的优先阅读子集 |
| `recovered/readable/*.readable.lua` | 标准化、分块并局部传播后的完整可读控制流伪 Lua |
| `recovered/artifacts/readable/*.cfg.json` | 基本块、前后继、操作类型、领域常量和陷阱目标报告 |
| `recovered/artifacts/decoded/*.lph.bin` | LPH 层无损解码结果 |
| `recovered/artifacts/decompiled/*.root.source.lua` | 从 loader AST 裁出的 VM 根函数 |
| `recovered/artifacts/programs/*.programs.json` | 池化后的 program/context IR 和追踪证据 |
| `recovered/artifacts/handlers/*.handlers.json` | 每个实际 opcode 的选中 handler 与候选路径 |
| `recovered/artifacts/pseudolua/*.all.pseudo.lua` | 与顶层 recovered listing 相同的归档副本 |
| `recovered/artifacts/summaries/*.json` | 输入摘要、计数、哈希和产物路径 |

`artifacts/bytecode/` 和 `artifacts/graphs/` 是早期分析保留的中间证据，不是生成最终 listing 的必要输入。

## 复现命令

要求本机已安装 `uv`。从项目根目录执行完整动态恢复：

```powershell
Get-ChildItem scripts\*.lua | ForEach-Object {
    uv run --with lupa --with luaparser python -m tools.recover_script `
        $_.FullName `
        --output-root recovered `
        --fetch-budget 2000000 `
        --callback-limit 200
}
```

若只想使用已有 program IR 重新生成 handler、listing 和 summary，可加 `--reuse-trace`：

```powershell
uv run --with lupa --with luaparser python -m tools.recover_script `
    scripts\Main.lua --output-root recovered --reuse-trace
```

运行测试、静态检查和全量审计：

```powershell
uv run --with pytest --with lupa --with luaparser python -m pytest -q
uv run --with ruff ruff check tools tests
uv run --with lupa --with luaparser python -m tools.audit_recovery `
    recovered\artifacts\summaries
$recoverySummaries = (Get-ChildItem recovered\artifacts\summaries\*.json `
    | Sort-Object Name).FullName
uv run --with lupa --with luaparser python -m tools.luraph_readable `
    @recoverySummaries --output-root recovered
uv run python -m tools.audit_readable recovered\artifacts\readable
```

审计命令退出码为 0 才表示所有强制检查通过。`unsliced_handlers` 是提示项：少量 handler 中仍可能出现 opcode 参与的反调试算术或二级语义条件，不代表 handler 缺失。

## 精度边界

当前结果可以称为“已观察 closure 的指令级语义完整恢复尝试”，不能称为“原始高层源码逐字恢复”。具体边界是：

- 原变量名、注释、格式和被编译消除的高层结构不可逆丢失；
- 真实 DST 和九个外部目标模组没有加载，代理环境只展开了可到达的注册逻辑；
- 环境相关条件、代理比较结果和代理长度可能让某些目标特定分支被跳过；
- 没有在本次运行中创建的 closure 不会出现在 context IR 中；
- handler 还原覆盖所有已记录 opcode，但不能证明所有潜在环境下的 opcode 都已出现；
- listing 保留 VM 语义证据，但未重构成可直接运行、可维护的手写 Lua。

要进一步接近可读高层源码，需要在受控的 DST 环境中为九个目标模组分别构造状态矩阵，多轮追踪并合并新 context，然后再做数据流分析、控制流结构化和 API 语义命名。这属于第二阶段重构，而不是当前证据能够无歧义自动完成的解码。
