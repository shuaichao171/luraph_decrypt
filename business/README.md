# business 业务重建

本目录保存与当前 `run/code/` 输入集合一一对应的高层业务语义重建。它们是本次
fresh LPH 解码、VM trace、handler/CFG 审计和窄业务夹具共同约束的结果，不是原
作者逐字源码，也不应直接覆盖目标模组文件。

| 输入 | business 产物 | 已确认业务范围 |
|---|---|---|
| `Main.lua` | `Main.business.lua` | 9 个目标检测、状态表、6 个启用桥接导入 |
| `Legion.lua` | `Legion.business.lua` | upvalue 扫描、三类 closure 替换、Kick 字段修补、分组重试 |
| `Xuaner_Myxl.lua` | `Xuaner_Myxl.business.lua` | registry、注册 wrapper、库存 metatable、全局 hook、三组调度 |

每份 Lua 文件头记录当前输入 SHA-256 和 decoded payload SHA-256。输入哈希变化时，
旧 business 只能作为待验证基线，必须重新执行完整恢复和业务合同，不能直接沿用。

默认完成条件：

1. `run/code/*.lua` 与 `business/*.business.lua` 文件名集合完全一致；
2. VM 恢复审计无缺失或空 handler，listing 无未知 opcode；
3. readable CFG 无 context 错误或未定义 goto 标签；
4. 对应 Lupa 业务合同通过；
5. 未触发分支保留为证据边界，不虚构会改变所有权、RPC 或皮肤校验的行为。

运行完整验证：

```powershell
.\verify.ps1
```
