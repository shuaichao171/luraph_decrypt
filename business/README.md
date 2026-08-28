# Business 业务重建索引

本目录保存源项目 10 份人工、证据约束的高层 Lua 重建。它们从
`recovered/readable/*.business.lua` 无损迁移而来，使发布仓库中的
`RECOVERY.md` 和 `BUSINESS_RECOVERY.md` 有实际可阅读、可测试的案例。

这些文件不是 Luraph 自动反编译输出，也不是原作者逐字源码或可直接覆盖模组的
drop-in 文件。每个实现只保留已经通过动态探针、最终状态或合同测试确认的业务
语义；未确认内容以证据边界注释保留。

## 文件

| 脚本 | 已重建内容 |
|---|---|
| [Main](Main.business.lua) | 九项目标配置、检测表、全局状态和已启用桥接导入 |
| [Legion](Legion.business.lua) | 模组匹配、递归 upvalue 扫描、三类 closure 替换、Kick 字段修补和统计 |
| [Book of All Things](Book_of_All_Things.business.lua) | registry 写入、注册/库存/验证器/controller wrapper 和分组重试 |
| [Cardcaptor Sakura](Cardcaptor_Sakura.business.lua) | `CCSAPI.MakeCharacterSkin` 幂等透传包装和世界重试 |
| [Deng Xian](Deng_Xian.business.lua) | 库存函数命名 upvalue 扫描、皮肤记录写入和分类 |
| [Harvest Mysterious Realm](Harvest_Mysterious_Realm.business.lua) | 同步 API、网络回调、registry 写入和五级重试 |
| [Niaoniao Character](Niaoniao_Character.business.lua) | 解锁映射、controller 定位、`UnlockSkin` 调用和 `HasSkin` 包装 |
| [Shugo Chara](Shugo_Chara.business.lua) | registry、恒真校验、注册函数透传和分组调度 |
| [Void Realm](Void_Realm.business.lua) | Gate API、库存修补、RPC 注册和头像分流 |
| [Xuaner Myxl](Xuaner_Myxl.business.lua) | registry、Make wrapper、库存 `__index` 分流、全局 wrapper 和重试 |

详细证据与完成边界见 [RECOVERY.md](../RECOVERY.md)，从 VM 产物重建这些文件的
操作方法见 [BUSINESS_RECOVERY.md](../BUSINESS_RECOVERY.md)。

## 验证

合同测试位于 `tests/test_business_lua.py`，覆盖 10 份文件的 Lua 解析、目标与
非目标输入、函数身份、幂等包装、参数数量、中间 nil 返回槽、registry 最终状态、
callback 类型和延迟顺序。

```powershell
uv run --no-project --with pytest --with lupa --with luaparser `
    python -m pytest -q -p no:cacheprovider tests\test_business_lua.py
```

原始 decoded、program/context IR、handler、CFG、完整 readable 和大体积实验
trace 属于可再生分析产物，继续由 `run_recovery.ps1` 写入本地
`run/recovered/`。该目录受 `.gitignore` 排除，不与高层人工重建混为一类。
