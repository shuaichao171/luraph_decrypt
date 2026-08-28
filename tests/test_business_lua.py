from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INPUT_ROOT = ROOT / 'run' / 'code'
BUSINESS_ROOT = ROOT / "business"


def _runtime():
    lupa = pytest.importorskip("lupa")
    return lupa.LuaRuntime(unpack_returned_tuples=True)


def _load_root(lua, name: str):
    path = BUSINESS_ROOT / name
    if not path.is_file():
        pytest.skip(f'{name} is not part of the current business recovery set')
    source = (BUSINESS_ROOT / name).read_text(encoding="utf-8")
    return lua.execute(source)


def test_all_business_reconstructions_parse() -> None:
    pytest.importorskip("luaparser")
    from luaparser import ast

    paths = sorted(BUSINESS_ROOT.glob("*.business.lua"))

    assert paths
    input_names = {path.stem for path in INPUT_ROOT.glob('*.lua')}
    business_names = {
        path.name.removesuffix('.business.lua') for path in paths
    }
    if input_names:
        assert business_names == input_names
    for path in paths:
        ast.parse(path.read_text(encoding="utf-8"))


def test_main_detects_all_targets_but_imports_only_enabled_bridges() -> None:
    lua = _runtime()
    lua.execute(
        """
        local loaded = {
            "workshop-1392778117",
            "workshop-2526778484",
            "workshop-3235319974",
            "workshop-3609964985",
            "workshop-3626093627",
            "workshop-3014076942",
            "workshop-3573399040",
            "workshop-3544387985",
            "workshop-3043439883",
        }
        info_calls = 0
        imported = {}
        KnownModIndex = {
            GetModsToLoad = function(self, include_all)
                assert(include_all == true)
                return loaded
            end,
            GetModInfo = function(self, mod_name)
                info_calls = info_calls + 1
                return { name = "target:" .. mod_name }
            end,
        }
        modimport = function(path)
            table.insert(imported, path)
        end
        """
    )

    _load_root(lua, "Main.business.lua")()

    assert lua.eval("info_calls") == 9
    assert lua.eval("table.concat(imported, ',')") == (
        "scripts/Legion.lua,"
        "scripts/Void_Realm.lua,"
        "scripts/Deng_Xian.lua,"
        "scripts/Harvest_Mysterious_Realm.lua,"
        "scripts/Xuaner_Myxl.lua,"
        "scripts/Shugo_Chara.lua"
    )
    assert lua.eval(
        """
        function()
            local state = PRISM_TERRA_SKIN_BRIDGE_ACTIVE
            return state.prism and state.voidrealm and state.dengxian
                and state.hmr and state.niaoniao and state.xuaner
                and state.shugo and state.book and state.ccs
        end
        """
    )()


def test_legion_restores_upvalue_table_patches_and_retry_groups() -> None:
    lua = _runtime()
    lua.execute(
        """
        kick_record = { wfi7hy0ff_L = "Kick" }
        original_integrity = function() return "integrity" end
        original_crash = function() return "crash" end
        original_skin = function() return "skin" end
        local function make_signature_function()
            local CU = original_integrity
            local oU = original_crash
            local cU = original_skin
            local qU = function() return kick_record end
            return function()
                return CU(), oU(), cU(), qU()
            end
        end

        set_calls = 0
        target_set = make_signature_function()
        local raw_target_set = target_set
        target_set = function(...)
            set_calls = set_calls + 1
            return raw_target_set(...)
        end
        -- Keep the signature closure directly reachable by the scanner.
        signature_function = raw_target_set
        init_calls = 0
        target_init = function(...)
            init_calls = init_calls + 1
        end
        reskin_calls = 0
        target_reskin = function(...)
            reskin_calls = reskin_calls + 1
        end
        indexed_signature = { [306] = "observed" }
        setbuild_descriptor = {
            dataname = "AnimState",
            fnname = "SetBuild",
        }
        target_environment = {
            LS_C_Set = signature_function,
            LS_C_Init = target_init,
            LS_C_Reskin = target_reskin,
            postinitfns = {
                signature_function,
                indexed_signature,
                setbuild_descriptor,
            },
        }
        loaded_mods = { "workshop-legion", "workshop-other" }
        KnownModIndex = {
            GetModsToLoad = function(self, include_all)
                assert(include_all == true)
                return loaded_mods
            end,
            GetModInfo = function(self, mod_name)
                if mod_name == "workshop-legion" then
                    return { name = "[DST] Legion" }
                end
                return { name = "Other" }
            end,
        }
        ModManager = {
            GetMod = function(self, mod_name)
                assert(mod_name == "workshop-legion")
                return target_environment
            end,
        }
        sim_post = nil
        prefab_posts = {}
        AddSimPostInit = function(callback)
            sim_post = callback
        end
        AddPrefabPostInit = function(prefab, callback)
            prefab_posts[prefab] = callback
        end
        printed = {}
        print = function(message)
            table.insert(printed, message)
        end
        """
    )

    _load_root(lua, "Legion.business.lua")()

    assert lua.eval(
        """
        function()
            assert(PRISM_TERRA_BRIDGE_LEGION_ENABLED == true)
            assert(kick_record.wfi7hy0ff_L == "GetUserID")
            assert(set_calls == 0)
            assert(init_calls == 0)
            assert(reskin_calls == 0)
            local integrity, crash, skin, identity = signature_function()
            assert(integrity == false)
            assert(crash == false)
            assert(skin == true)
            assert(identity == kick_record)
            assert(string.find(
                printed[1],
                "identity=0 kick=1 skin=1 integrity=1 crash=1 buildgate=0",
                1,
                true
            ))
            assert(string.find(
                printed[1],
                "set=1 init=1 reskin=1",
                1,
                true
            ))
            assert(indexed_signature[306] == "observed")
            assert(setbuild_descriptor.dataname == "AnimState")
            assert(setbuild_descriptor.fnname == "SetBuild")

            local world_tasks = {}
            local world = {
                DoTaskInTime = function(self, delay, callback)
                    table.insert(world_tasks, delay)
                end,
            }
            sim_post(world)
            assert(#world_tasks == 8)
            assert(world_tasks[1] == 0)
            assert(world_tasks[8] == 120)
            prefab_posts.world(world)
            assert(#world_tasks == 8)

            local cave_tasks = {}
            prefab_posts.cave({
                DoTaskInTime = function(self, delay, callback)
                    table.insert(cave_tasks, delay)
                end,
            })
            assert(#cave_tasks == 8)
            assert(cave_tasks[1] == 0)
            assert(cave_tasks[8] == 120)
            return true
        end
        """
    )()


def test_void_realm_restores_api_rpc_portrait_and_retry_behavior() -> None:
    lua = _runtime()
    lua.execute(
        """
        target_environment = { TrSkinAPI = {} }
        KnownModIndex = {
            GetModsToLoad = function(self, include_all)
                assert(include_all == true)
                return { "workshop-2526778484" }
            end,
            GetModInfo = function(self, mod_name)
                return { name = "Void Realm" }
            end,
        }
        ModManager = {
            GetMod = function(self, mod_name)
                return target_environment
            end,
        }

        original_portrait_calls = 0
        SetSkinnedOvalPortraitTexture = function(widget, character, skin_name)
            original_portrait_calls = original_portrait_calls + 1
            return "original:" .. skin_name
        end
        server_rpc = nil
        client_rpc = nil
        game_post = nil
        sim_post = nil
        prefab_posts = {}
        AddModRPCHandler = function(namespace, name, callback)
            server_rpc = {
                namespace = namespace,
                name = name,
                callback = callback,
            }
        end
        AddClientModRPCHandler = function(namespace, name, callback)
            client_rpc = {
                namespace = namespace,
                name = name,
                callback = callback,
            }
        end
        AddGamePostInit = function(callback)
            game_post = callback
        end
        AddSimPostInit = function(callback)
            sim_post = callback
        end
        AddPrefabPostInit = function(prefab, callback)
            prefab_posts[prefab] = callback
        end
        print = function() end
        """
    )

    _load_root(lua, "Void_Realm.business.lua")()

    assert lua.eval(
        """
        function()
            local fields = {
                "TrOwnershipCheckFntrzzff",
                "TrOwnershipIsReady",
                "TrSkinCheckClientFn",
                "TrSkinCheckFn",
                "VR_GateLocal_41",
                "VR_GatePeer_73",
                "VR_GateReady_58",
                "VR_GateServer_26",
            }
            for _, api in ipairs({
                target_environment,
                target_environment.TrSkinAPI,
            }) do
                for _, field in ipairs(fields) do
                    assert(api[field]("probe") == true)
                end
                assert(api.TrTryLoad("probe") == nil)
            end
            return true
        end
        """
    )()
    assert lua.eval(
        """
        function()
            assert(server_rpc.namespace == "tr_ygsts_skin")
            assert(server_rpc.name == "apply")
            assert(client_rpc.namespace == "tr_ygsts_skin")
            assert(client_rpc.name == "apply_visual")
            local result_count = select("#", server_rpc.callback(
                { components = { skinner = {} } },
                "ygsts_luo_skin"
            ))
            assert(result_count == 0)

            PREFAB_SKINS = { ygsts = { "ygsts_luo_skin" } }
            local skin_call
            ThePlayer = {
                AnimState = {
                    SetSkin = function(self, build, prefab)
                        skin_call = { build, prefab }
                    end,
                },
            }
            client_rpc.callback("ygsts_luo_skin", nil, nil)
            assert(skin_call[1] == "ygsts_luo")
            assert(skin_call[2] == "ygsts")

            local build_call
            ThePlayer.AnimState = {
                SetBuild = function(self, build)
                    build_call = build
                end,
            }
            client_rpc.callback("ygsts_luo_skin", nil, nil)
            assert(build_call == "ygsts_luo")

            build_call = nil
            client_rpc.callback("other_skin", nil, nil)
            assert(build_call == nil)
            return true
        end
        """
    )()
    assert lua.eval(
        """
        function()
            local texture_call
            local widget = {
                SetTexture = function(self, atlas, texture, default_texture)
                    texture_call = {
                        atlas,
                        texture,
                        default_texture,
                    }
                end,
            }
            assert(SetSkinnedOvalPortraitTexture(
                widget,
                "character",
                "ygsts_luo_skin"
            ) == true)
            assert(texture_call[1] == "bigportraits/ygsts_luo_none.xml")
            assert(texture_call[2] == "ygsts_luo_none_oval.tex")
            assert(texture_call[3] == "ygsts_luo_none_oval.tex")
            assert(SetSkinnedOvalPortraitTexture(
                widget,
                "character",
                "ordinary"
            ) == "original:ordinary")
            assert(original_portrait_calls == 1)
            return true
        end
        """
    )()
    assert lua.eval(
        """
        function()
            assert(type(game_post) == "function")
            assert(type(sim_post) == "function")
            assert(type(prefab_posts.world) == "function")
            assert(type(prefab_posts.cave) == "function")
            local tasks = {}
            local inst = {
                DoTaskInTime = function(self, delay, callback)
                    table.insert(tasks, { delay = delay, callback = callback })
                end,
            }
            sim_post(inst)
            assert(#tasks == 2)
            assert(tasks[1].delay == 0)
            assert(tasks[2].delay == 1)
            return true
        end
        """
    )()


def test_hmr_restores_registry_api_callback_and_retry_behavior() -> None:
    lua = _runtime()
    lua.execute(
        """
        character_record = { checkfn = "old", is_restricted = true }
        item_record = { checkclientfn = "old", unlock = false }
        local characterskins = { hero = character_record }
        local itemskins = { item = item_record }
        local function check_characters()
            return characterskins
        end
        local function check_items()
            return itemskins
        end
        local function check_both()
            return characterskins, itemskins
        end
        TheInventory = {
            CheckOwnership = check_characters,
            CheckOwnershipGetLatest = check_items,
            CheckClientOwnership = check_both,
        }
        HMR_SKIN_SYNC_API = {}
        KnownModIndex = {
            GetModsToLoad = function(self, include_all)
                assert(include_all == true)
                return { "workshop-3609964985" }
            end,
            GetModInfo = function(self, mod_name)
                return { name = "Harvest Mysterious Realm" }
            end,
        }
        sim_post = nil
        prefab_posts = {}
        AddSimPostInit = function(callback)
            sim_post = callback
        end
        AddPrefabPostInit = function(prefab, callback)
            prefab_posts[prefab] = callback
        end
        print = function() end
        """
    )

    _load_root(lua, "Harvest_Mysterious_Realm.business.lua")()

    assert lua.eval(
        """
        function()
            for _, record in ipairs({ character_record, item_record }) do
                assert(record.checkfn("skin") == true)
                assert(record.checkclientfn("skin") == true)
                assert(record.unlock == true)
                assert(record.is_restricted == false)
            end
            assert(HMR_SKIN_SYNC_API.CheckOwnership("skin") == true)
            assert(HMR_SKIN_SYNC_API.CheckClientOwnership("skin") == true)
            assert(HMR_SKIN_SYNC_API.HasSkin("skin") == true)
            assert(HMRIsSkinOwned("skin") == true)
            assert(HMRIsClientSkinOwned("skin") == true)
            local received
            HMRGetSkinDataFromNet("skin", function(owned, data, reason)
                received = { owned = owned, data = data, reason = reason }
            end)
            assert(received.owned == true)
            assert(type(received.data) == "table")
            assert(next(received.data) == nil)
            assert(received.reason == nil)
            return true
        end
        """
    )()
    assert lua.eval(
        """
        function()
            assert(type(sim_post) == "function")
            sim_post()
            local tasks = {}
            local inst = {
                DoTaskInTime = function(self, delay, callback)
                    table.insert(tasks, { delay = delay, callback = callback })
                end,
            }
            prefab_posts.world(inst)
            assert(#tasks == 5)
            assert(tasks[1].delay == 0)
            assert(tasks[2].delay == 0.25)
            assert(tasks[3].delay == 1)
            assert(tasks[4].delay == 3)
            assert(tasks[5].delay == 8)
            return true
        end
        """
    )()


def test_deng_restores_inventory_registries_and_classifies_character_items() -> None:
    lua = _runtime()
    lua.execute(
        r"""
        name_record = { untouched = true }
        local namemaps = { hero = name_record }
        character_record = { checkfn = "old", is_restricted = true }
        item_record = { checkclientfn = "old", unlock = false }
        character_item_record = {
            ischaracterskins = true,
            unlock = false,
        }
        local characterskins = { hero = character_record }
        local itemskins = {
            item = item_record,
            character_item = character_item_record,
        }
        local oldTheInventoryCheckOwnership = function()
            return false
        end
        local function make_inventory_method()
            return function()
                return namemaps, characterskins, itemskins,
                    oldTheInventoryCheckOwnership
            end
        end
        TheInventory = {
            CheckOwnership = make_inventory_method(),
            CheckOwnershipGetLatest = make_inventory_method(),
            CheckClientOwnership = make_inventory_method(),
        }

        target_environment = {}
        KnownModIndex = {
            GetModsToLoad = function(self, include_all)
                assert(include_all == true)
                return { "workshop-3235319974" }
            end,
            GetModInfo = function(self, mod_name)
                return {
                    name = string.char(
                        227, 128, 144, 231, 153, 187,
                        228, 187, 153, 227, 128, 145
                    ),
                }
            end,
        }
        ModManager = {
            GetMod = function(self, mod_name)
                return target_environment
            end,
        }
        sim_post = nil
        prefab_posts = {}
        AddSimPostInit = function(callback)
            sim_post = callback
        end
        AddPrefabPostInit = function(prefab, callback)
            prefab_posts[prefab] = callback
        end
        TheNet = { IsDedicated = function(self) return false end }
        printed = {}
        print = function(message)
            table.insert(printed, message)
        end
        """
    )

    _load_root(lua, "Deng_Xian.business.lua")()
    lua.eval("sim_post")()

    assert lua.eval(
        """
        function()
            for _, record in ipairs({
                character_record,
                item_record,
                character_item_record,
            }) do
                assert(record.checkfn("skin") == true)
                assert(record.checkclientfn("skin") == true)
                assert(record.unlock == true)
                assert(record.is_restricted == false)
            end
            assert(name_record.untouched == true)
            assert(name_record.checkfn == nil)
            assert(string.find(printed[#printed], "item=1", 1, true))
            assert(string.find(printed[#printed], "character=2", 1, true))
            assert(string.find(printed[#printed], "patched_now=3", 1, true))
            return true
        end
        """
    )()


def test_ccs_wraps_registration_idempotently_and_preserves_results() -> None:
    lua = _runtime()
    lua.execute(
        """
        original_calls = 0
        original_arguments = nil
        CCSAPI = {
            MakeCharacterSkin = function(...)
                original_calls = original_calls + 1
                original_arguments = {
                    n = select("#", ...),
                    ...
                }
                return "first", nil, "third"
            end,
        }
        sim_post = nil
        prefab_posts = {}
        AddSimPostInit = function(callback)
            sim_post = callback
        end
        AddPrefabPostInit = function(prefab, callback)
            prefab_posts[prefab] = callback
        end
        print = function() end
        """
    )

    _load_root(lua, "Cardcaptor_Sakura.business.lua")()

    assert lua.eval(
        """
        function()
            local tasks = {}
            local inst = {
                DoTaskInTime = function(self, delay, callback)
                    table.insert(tasks, { delay = delay, callback = callback })
                end,
            }
            sim_post(inst)
            assert(#tasks == 2)
            assert(tasks[1].delay == 0)
            assert(tasks[2].delay == 1)
            tasks[1].callback()
            local wrapped = CCSAPI.MakeCharacterSkin
            tasks[2].callback()
            assert(CCSAPI.MakeCharacterSkin == wrapped)

            local results = {
                n = select(
                    "#",
                    CCSAPI.MakeCharacterSkin("one", "two", nil, "four")
                ),
                CCSAPI.MakeCharacterSkin("one", "two", nil, "four"),
            }
            assert(results.n == 3)
            assert(results[1] == "first")
            assert(results[2] == nil)
            assert(results[3] == "third")
            assert(original_calls == 2)
            assert(original_arguments.n == 4)
            assert(original_arguments[1] == "one")
            assert(original_arguments[2] == "two")
            assert(original_arguments[3] == nil)
            assert(original_arguments[4] == "four")
            return true
        end
        """
    )()
    assert lua.eval(
        """
        function()
            local tasks = {}
            local inst = {
                DoTaskInTime = function(self, delay, callback)
                    table.insert(tasks, { delay = delay, callback = callback })
                end,
            }
            prefab_posts.world(inst)
            assert(#tasks == 2)
            assert(tasks[1].delay == 0)
            assert(tasks[2].delay == 1)
            return true
        end
        """
    )()


def test_xuaner_restores_skin_inventory_wrappers_and_retry_groups() -> None:
    lua = _runtime()
    lua.execute(
        """
        character_record = {
            checkfn = "old",
            checkclientfn = "old",
            unlock = false,
            is_restricted = true,
            check = "keep",
            all = "keep",
            owned = "keep",
        }
        item_record = {
            checkfn = "old",
            checkclientfn = "old",
            unlock = false,
            is_restricted = true,
        }
        unrelated_character_record = {
            checkfn = "old",
            checkclientfn = "old",
            unlock = false,
            is_restricted = true,
        }
        unrelated_item_record = {
            checkfn = "old",
            checkclientfn = "old",
            unlock = false,
            is_restricted = true,
        }
        PREFAB_SKINS = {
            moyuxuanli = { "moyuxuanli_test_skin" },
            unrelated = { "unrelated_skin" },
        }
        CHARACTERSKINS = {
            moyuxuanli_test_skin = character_record,
            unrelated_skin = unrelated_character_record,
        }
        ITEMSKINS = {
            moyuxuanli_item_skin = item_record,
            unrelated_item_skin = unrelated_item_record,
        }

        make_character_calls = 0
        original_make_character = function(...)
            make_character_calls = make_character_calls + 1
            make_character_arguments = { n = select("#", ...), ... }
            return "character", nil, "tail"
        end
        make_item_calls = 0
        original_make_item = function(...)
            make_item_calls = make_item_calls + 1
            make_item_arguments = { n = select("#", ...), ... }
            return "item", nil, "tail"
        end
        MYXLAPI = {
            MakeCharacterSkin = original_make_character,
            MakeItemSkin = original_make_item,
        }

        direct_make_character = function(...) return "direct-character" end
        direct_make_item = function(...) return "direct-item" end
        target_environment = {
            MYXLAPI = MYXLAPI,
            MakeCharacterSkin = direct_make_character,
            MakeItemSkin = direct_make_item,
        }
        KnownModIndex = {
            GetModsToLoad = function(self, include_all)
                assert(include_all == true)
                return { "workshop-3014076942" }
            end,
        }
        ModManager = {
            GetMod = function(self, mod_name)
                return target_environment
            end,
        }

        ownership_calls = 0
        original_check_ownership = function(...)
            ownership_calls = ownership_calls + 1
            ownership_arguments = { n = select("#", ...), ... }
            return "ownership", nil, "tail"
        end
        latest_calls = 0
        original_check_latest = function(...)
            latest_calls = latest_calls + 1
            latest_arguments = { n = select("#", ...), ... }
            return "latest", nil, "tail"
        end
        client_calls = 0
        original_check_client = function(...)
            client_calls = client_calls + 1
            client_arguments = { n = select("#", ...), ... }
            return "client", nil, "tail"
        end
        original_should_display = function(...) return "display" end
        inventory_methods = {
            CheckOwnership = original_check_ownership,
            CheckOwnershipGetLatest = original_check_latest,
            CheckClientOwnership = original_check_client,
            ShouldDisplayItemInCollection = original_should_display,
        }
        TheInventory = setmetatable({}, { __index = inventory_methods })

        popup_calls = 0
        original_popup = function(...)
            popup_calls = popup_calls + 1
            popup_arguments = { n = select("#", ...), ... }
            return "popup", nil, "tail"
        end
        portrait_calls = 0
        original_portrait = function(...)
            portrait_calls = portrait_calls + 1
            portrait_arguments = { n = select("#", ...), ... }
            return "portrait", nil, "tail"
        end
        restart_calls = 0
        original_restart = function(...)
            restart_calls = restart_calls + 1
            restart_arguments = { n = select("#", ...), ... }
            return "restart", nil, "tail"
        end
        MYXLPushPopupDialog = original_popup
        SetSkinnedOvalPortraitTexture = original_portrait
        DoRestart = original_restart

        class_post = nil
        sim_post = nil
        player_post = nil
        prefab_posts = {}
        AddClassPostConstruct = function(path, callback)
            assert(path == "widgets/controls")
            class_post = callback
        end
        AddSimPostInit = function(callback)
            sim_post = callback
        end
        AddPlayerPostInit = function(callback)
            player_post = callback
        end
        AddPrefabPostInit = function(prefab, callback)
            prefab_posts[prefab] = callback
        end
        printed = {}
        print = function(message)
            table.insert(printed, message)
        end
        """
    )

    _load_root(lua, "Xuaner_Myxl.business.lua")()

    assert lua.eval(
        """
        function()
            assert(PRISM_TERRA_BRIDGE_XUANER_ENABLED == true)
            assert(type(character_record.checkfn) == "function")
            assert(character_record.checkfn() == true)
            assert(type(character_record.checkclientfn) == "function")
            assert(character_record.checkclientfn() == true)
            assert(character_record.unlock == true)
            assert(character_record.is_restricted == false)
            assert(character_record.check == "keep")
            assert(character_record.all == "keep")
            assert(character_record.owned == "keep")
            assert(type(item_record.checkfn) == "function")
            assert(item_record.unlock == true)
            assert(item_record.is_restricted == false)
            assert(unrelated_character_record.checkfn == "old")
            assert(unrelated_character_record.unlock == false)
            assert(unrelated_item_record.checkfn == "old")
            assert(unrelated_item_record.unlock == false)

            assert(MYXLAPI.MakeCharacterSkin ~= original_make_character)
            assert(MYXLAPI.MakeItemSkin ~= original_make_item)
            assert(target_environment.MakeCharacterSkin ~= direct_make_character)
            assert(target_environment.MakeItemSkin ~= direct_make_item)
            local new_character = {
                checkfn = "old",
                checkclientfn = "old",
                unlock = false,
                is_restricted = true,
                check = "keep",
            }
            local c1, c2, c3 = MYXLAPI.MakeCharacterSkin(
                "moyuxuanli", "moyuxuanli_new_skin", new_character
            )
            assert(c1 == "character" and c2 == nil and c3 == "tail")
            assert(make_character_calls == 1)
            assert(make_character_arguments.n == 3)
            assert(make_character_arguments[1] == "moyuxuanli")
            assert(make_character_arguments[2] == "moyuxuanli_new_skin")
            assert(make_character_arguments[3] == new_character)
            assert(new_character.checkfn() == true)
            assert(new_character.checkclientfn() == true)
            assert(new_character.unlock == true)
            assert(new_character.is_restricted == false)
            assert(new_character.check == "keep")

            local new_item = {}
            local i1, i2, i3 = MYXLAPI.MakeItemSkin(
                "moyuxuanli", "moyuxuanli_new_item_skin", new_item
            )
            assert(i1 == "item" and i2 == nil and i3 == "tail")
            assert(make_item_calls == 1)
            assert(make_item_arguments.n == 3)
            assert(make_item_arguments[3] == new_item)
            assert(new_item.checkfn() == true)
            assert(new_item.checkclientfn() == true)
            assert(new_item.unlock == true)
            assert(new_item.is_restricted == false)

            assert(inventory_methods.CheckOwnership ~= original_check_ownership)
            assert(inventory_methods.CheckOwnership(
                TheInventory, "moyuxuanli_test_skin") == true)
            assert(ownership_calls == 0)
            local o1, o2, o3 = inventory_methods.CheckOwnership(
                TheInventory, "unrelated_skin"
            )
            assert(o1 == "ownership" and o2 == nil and o3 == "tail")
            assert(ownership_calls == 1)
            assert(ownership_arguments.n == 2)

            assert(select("#", inventory_methods.CheckOwnershipGetLatest(
                TheInventory, "moyuxuanli_item_skin")) == 2)
            local owns_latest, latest_timestamp =
                inventory_methods.CheckOwnershipGetLatest(
                    TheInventory, "moyuxuanli_item_skin"
                )
            assert(owns_latest == true and latest_timestamp == 0)
            assert(latest_calls == 0)
            local l1, l2, l3 = inventory_methods.CheckOwnershipGetLatest(
                TheInventory, "unrelated_item_skin"
            )
            assert(l1 == "latest" and l2 == nil and l3 == "tail")
            assert(latest_calls == 1)

            local cl1, cl2, cl3 = inventory_methods.CheckClientOwnership(
                TheInventory, "moyuxuanli_test_skin", "discarded"
            )
            assert(cl1 == "client" and cl2 == nil and cl3 == "tail")
            assert(client_calls == 1)
            assert(client_arguments.n == 3)
            assert(client_arguments[1] == TheInventory)
            assert(client_arguments[2] == "moyuxuanli_test_skin")
            assert(client_arguments[3] == nil)
            assert(inventory_methods.HasSupportForOfflineSkins() == true)
            assert(inventory_methods.ShouldDisplayItemInCollection
                == original_should_display)
            assert(rawget(TheInventory, "CheckOwnership") == nil)

            assert(MYXLPushPopupDialog ~= original_popup)
            local p1, p2, p3 = MYXLPushPopupDialog("title", "body", 7)
            assert(p1 == "popup" and p2 == nil and p3 == "tail")
            assert(popup_calls == 1 and popup_arguments.n == 3)
            assert(SetSkinnedOvalPortraitTexture ~= original_portrait)
            local t1, t2, t3 = SetSkinnedOvalPortraitTexture(
                "widget", "skin", 9
            )
            assert(t1 == "portrait" and t2 == nil and t3 == "tail")
            assert(portrait_calls == 1 and portrait_arguments.n == 3)
            assert(DoRestart ~= original_restart)
            local r1, r2, r3 = DoRestart("reason", 11)
            assert(r1 == "restart" and r2 == nil and r3 == "tail")
            assert(restart_calls == 1 and restart_arguments.n == 2)

            assert(string.find(
                printed[1],
                "mod=workshop-3014076942 skins=2 data=8 owner=0",
                1,
                true
            ))
            assert(string.find(
                printed[1],
                "hooks=0 ui=0 compat=0 security=0 functions=",
                1,
                true
            ))

            local make_wrapper = MYXLAPI.MakeCharacterSkin
            local owner_wrapper = inventory_methods.CheckOwnership
            class_post({ SetBuild = function() end })
            assert(MYXLAPI.MakeCharacterSkin == make_wrapper)
            assert(inventory_methods.CheckOwnership == owner_wrapper)

            local world_tasks = {}
            local world = {
                DoTaskInTime = function(self, delay, callback)
                    table.insert(world_tasks, delay)
                end,
            }
            sim_post(world)
            assert(#world_tasks == 8)
            assert(world_tasks[1] == 0)
            assert(world_tasks[8] == 120)

            local prefab_tasks = {}
            prefab_posts.moyuxuanli({
                DoTaskInTime = function(self, delay, callback)
                    table.insert(prefab_tasks, delay)
                end,
            })
            assert(#prefab_tasks == 3)
            assert(prefab_tasks[1] == 0)
            assert(prefab_tasks[2] == 0.5)
            assert(prefab_tasks[3] == 2)

            local player_tasks = {}
            player_post({
                DoTaskInTime = function(self, delay, callback)
                    table.insert(player_tasks, delay)
                end,
            })
            assert(#player_tasks == 3)
            assert(player_tasks[1] == 0.5)
            assert(player_tasks[2] == 2)
            assert(player_tasks[3] == 5)
            return true
        end
        """
    )()


def test_shugo_restores_registries_ownership_wrappers_and_retry_groups() -> None:
    lua = _runtime()
    lua.execute(
        """
        character_record = { checkfn = "old", is_restricted = true }
        item_record = { checkclientfn = "old", unlock = false }
        character_item_record = {
            ischaracterskins = true,
            unlock = false,
        }
        local character_skins = { hero = character_record }
        local item_skins = {
            item = item_record,
            character_item = character_item_record,
        }
        make_character_calls = 0
        make_item_calls = 0
        local function make_character(...)
            make_character_calls = make_character_calls + 1
            make_character_arguments = { n = select("#", ...), ... }
            return "character", nil, "tail"
        end
        local function make_item(...)
            make_item_calls = make_item_calls + 1
            make_item_arguments = { n = select("#", ...), ... }
            return "item", nil, "tail"
        end
        target_environment = {
            GetAllSkin = function()
                return character_skins, item_skins
            end,
            _SkinCheckFn = function() return false end,
            _SkinCheckClientFn = function() return false end,
            skdwdwswpp = function() return false end,
            MakeCharacterSkin = make_character,
            MakeItemSkin = make_item,
        }
        local inventory_check = function() return false end
        TheInventory = {
            CheckOwnership = inventory_check,
            CheckOwnershipGetLatest = inventory_check,
            CheckClientOwnership = inventory_check,
        }
        original_inventory_check = inventory_check

        KnownModIndex = {
            GetModsToLoad = function(self, include_all)
                assert(include_all == true)
                return { "workshop-3573399040" }
            end,
        }
        ModManager = {
            GetMod = function(self, mod_name)
                return target_environment
            end,
        }
        game_post = nil
        sim_post = nil
        player_post = nil
        prefab_posts = {}
        AddGamePostInit = function(callback)
            game_post = callback
        end
        AddSimPostInit = function(callback)
            sim_post = callback
        end
        AddPlayerPostInit = function(callback)
            player_post = callback
        end
        AddPrefabPostInit = function(prefab, callback)
            prefab_posts[prefab] = callback
        end
        printed = {}
        print = function(message)
            table.insert(printed, message)
        end
        """
    )

    _load_root(lua, "Shugo_Chara.business.lua")()

    assert lua.eval(
        """
        function()
            for _, record in ipairs({
                character_record,
                item_record,
                character_item_record,
            }) do
                assert(record.checkfn("skin") == true)
                assert(record.checkclientfn("skin") == true)
                assert(record.unlock == true)
                assert(record.is_restricted == false)
            end
            assert(target_environment._SkinCheckFn("skin") == true)
            assert(target_environment._SkinCheckClientFn("skin") == true)
            assert(target_environment.skdwdwswpp("skin") == true)

            local wrapped_character = target_environment.MakeCharacterSkin
            local wrapped_item = target_environment.MakeItemSkin
            game_post()
            assert(target_environment.MakeCharacterSkin == wrapped_character)
            assert(target_environment.MakeItemSkin == wrapped_item)

            local function pack(...)
                return { n = select("#", ...), ... }
            end
            local character_results = pack(
                target_environment.MakeCharacterSkin("hero", nil, "tail")
            )
            local item_results = pack(
                target_environment.MakeItemSkin("item", nil, "tail")
            )
            assert(character_results.n == 3)
            assert(character_results[1] == "character")
            assert(character_results[2] == nil)
            assert(character_results[3] == "tail")
            assert(item_results.n == 3)
            assert(item_results[1] == "item")
            assert(item_results[2] == nil)
            assert(item_results[3] == "tail")
            assert(make_character_calls == 1)
            assert(make_item_calls == 1)
            assert(make_character_arguments.n == 3)
            assert(make_item_arguments.n == 3)

            assert(TheInventory.CheckOwnership == original_inventory_check)
            assert(
                TheInventory.CheckOwnershipGetLatest
                    == original_inventory_check
            )
            assert(
                TheInventory.CheckClientOwnership
                    == original_inventory_check
            )
            assert(string.find(
                printed[1],
                "skins=3 character=2 item=1",
                1,
                true
            ))
            assert(string.find(
                printed[1],
                "registration=2 inventory=0 changed=5",
                1,
                true
            ))
            return true
        end
        """
    )()
    assert lua.eval(
        """
        function()
            local world_tasks = {}
            sim_post({
                DoTaskInTime = function(self, delay, callback)
                    table.insert(world_tasks, delay)
                end,
            })
            assert(#world_tasks == 6)
            assert(world_tasks[1] == 0)
            assert(world_tasks[6] == 30)

            local player_tasks = {}
            player_post({
                DoTaskInTime = function(self, delay, callback)
                    table.insert(player_tasks, delay)
                end,
            })
            assert(#player_tasks == 2)
            assert(player_tasks[1] == 0.5)
            assert(player_tasks[2] == 2)
            assert(type(prefab_posts.world) == "function")
            assert(type(prefab_posts.cave) == "function")
            return true
        end
        """
    )()


def test_book_restores_registries_wrappers_controllers_and_retries() -> None:
    lua = _runtime()
    lua.execute(
        """
        local function record(name)
            return { name = name, unlock = false, is_restricted = true }
        end
        lower_character = record("lower_character")
        lower_item = record("lower_item")
        upper_character = record("upper_character")
        upper_item = record("upper_item")
        all_character = record("all_character")
        all_item = record("all_item")

        original_calls = {}
        local function original(name)
            return function(...)
                original_calls[name] = { n = select("#", ...), ... }
                return name, nil, name .. "-tail"
            end
        end

        local first_controller = {
            HasSkin = original("first_has_skin"),
            UnlockSkin = original("first_unlock_skin"),
        }
        local second_controller = {
            HasSkin = original("second_has_skin"),
            UnlockSkin = original("second_unlock_skin"),
        }
        original_first_unlock = first_controller.UnlockSkin
        original_second_unlock = second_controller.UnlockSkin
        AllPlayers = {
            { components = { tbat_com_skins_controller = first_controller } },
        }
        ThePlayer = {
            replica = { tbat_com_skins_controller = second_controller },
        }

        target_environment = {
            characterskins = { lower_character = lower_character },
            itemskins = { lower_item = lower_item },
            CHARACTERSKINS = { upper_character = upper_character },
            ITEMSKINS = { upper_item = upper_item },
            GetAllSkin = function()
                return { all_character = all_character }, { all_item = all_item }
            end,
            GetSkin = original("get_skin"),
            GetSkinMap = original("get_skin_map"),
            MakeCharacterSkin = original("make_character"),
            MakeItemSkin = original("make_item"),
            ValidateRecipeSkinRequest = original("target_validator"),
            TbatSkinCheckFn = function() return false end,
            TbatSkinCheckClientFn = function() return false end,
            postinitfns = { Probe = original("postinit_probe") },
            TBAT = { SKIN = { untouched = { marker = "target" } } },
        }
        original_postinit_probe = target_environment.postinitfns.Probe

        TheInventory = {
            CheckOwnership = original("ownership"),
            CheckOwnershipGetLatest = original("ownership_latest"),
            CheckClientOwnership = original("client_ownership"),
            HasSupportForOfflineSkins = original("offline"),
        }
        ValidateRecipeSkinRequest = original("global_validator")
        BOOKOFALLTHINGS = {}
        PREFAB_SKINS = {}
        TBAT = { SKIN = { untouched = { marker = "global" } } }
        Sim = {}
        TheWorld = {}

        mod_info_calls = 0
        KnownModIndex = {
            GetModsToLoad = function(self, include_all)
                assert(include_all == true)
                return { "workshop-3544387985" }
            end,
            GetModInfo = function(self, mod_name)
                mod_info_calls = mod_info_calls + 1
                return { name = "Book" }
            end,
        }
        ModManager = {
            GetMod = function(self, mod_name)
                return target_environment
            end,
        }

        sim_post = nil
        player_post = nil
        prefab_posts = {}
        AddSimPostInit = function(callback) sim_post = callback end
        AddPrefabPostInit = function(prefab, callback)
            prefab_posts[prefab] = callback
        end
        AddPlayerPostInit = function(callback) player_post = callback end
        printed = {}
        print = function(message) table.insert(printed, message) end
        """
    )

    _load_root(lua, "Book_of_All_Things.business.lua")()

    assert lua.eval(
        """
        function()
            local records = {
                lower_character,
                lower_item,
                upper_character,
                upper_item,
                all_character,
                all_item,
            }
            for _, skin in ipairs(records) do
                assert(skin.checkfn("skin") == true)
                assert(skin.checkclientfn("skin") == true)
                assert(skin.unlock == true)
                assert(skin.is_restricted == true)
            end

            local function pack(...)
                return { n = select("#", ...), ... }
            end
            local function assert_results(results, name)
                assert(results.n == 3)
                assert(results[1] == name)
                assert(results[2] == nil)
                assert(results[3] == name .. "-tail")
            end

            assert_results(pack(target_environment.MakeCharacterSkin(
                "hero", nil, "skin", "tail"
            )), "make_character")
            assert(original_calls.make_character.n == 4)
            assert(original_calls.make_character[3] == "skin")
            assert(original_calls.make_character[4] == "tail")
            assert_results(pack(target_environment.MakeItemSkin(
                "item", nil, "skin", "tail"
            )), "make_item")
            assert_results(pack(target_environment.ValidateRecipeSkinRequest(
                "recipe", "skin", "user", "tail"
            )), "target_validator")
            assert_results(pack(ValidateRecipeSkinRequest(
                "recipe", "skin", "user", "tail"
            )), "global_validator")

            assert_results(pack(TheInventory.CheckOwnership(
                "a", "b", "c", "d"
            )), "ownership")
            assert_results(pack(TheInventory.CheckOwnershipGetLatest(
                "a", "b", "c", "d"
            )), "ownership_latest")
            assert_results(pack(TheInventory.CheckClientOwnership(
                "a", "b", "c", "d"
            )), "client_ownership")
            assert(TheInventory.HasSupportForOfflineSkins() == true)
            assert(original_calls.offline == nil)

            local first = AllPlayers[1].components.tbat_com_skins_controller
            local second = ThePlayer.replica.tbat_com_skins_controller
            assert_results(pack(first.HasSkin("a", "b", "c", "d")),
                "first_has_skin")
            assert_results(pack(second.HasSkin("a", "b", "c", "d")),
                "second_has_skin")
            assert(first.UnlockSkin == original_first_unlock)
            assert(second.UnlockSkin == original_second_unlock)

            assert(target_environment.TbatSkinCheckFn() == true)
            assert(target_environment.TbatSkinCheckClientFn() == true)
            assert(TbatSkinCheckFn() == true)
            assert(TbatSkinCheckClientFn() == true)
            assert(target_environment.postinitfns.Probe == original_postinit_probe)
            assert(target_environment.TBAT.SKIN.untouched.marker == "target")
            assert(TBAT.SKIN.untouched.marker == "global")
            assert(BOOKOFALLTHINGS.TbatSkinCheckFn == nil)
            assert(PRISM_TERRA_BRIDGE_BOOK_ENABLED == true)
            assert(mod_info_calls == 1)
            assert(string.find(printed[1], "skins=6 data=18", 1, true))
            assert(string.find(
                printed[1],
                "inventory=3 validators=2 components=2",
                1,
                true
            ))
            return true
        end
        """
    )()

    assert lua.eval(
        """
        function()
            local wrapped_character = target_environment.MakeCharacterSkin
            local wrapped_item = target_environment.MakeItemSkin
            local wrapped_target_validator =
                target_environment.ValidateRecipeSkinRequest
            local wrapped_global_validator = ValidateRecipeSkinRequest
            local wrapped_ownership = TheInventory.CheckOwnership
            local wrapped_has_skin =
                AllPlayers[1].components.tbat_com_skins_controller.HasSkin

            local world_tasks = {}
            local world = {
                DoTaskInTime = function(self, delay, callback)
                    table.insert(world_tasks, { delay = delay, callback = callback })
                end,
            }
            sim_post(world)
            prefab_posts.world(world)
            assert(#world_tasks == 8)
            assert(world_tasks[1].delay == 0)
            assert(world_tasks[8].delay == 120)
            world_tasks[1].callback()

            assert(target_environment.MakeCharacterSkin == wrapped_character)
            assert(target_environment.MakeItemSkin == wrapped_item)
            assert(target_environment.ValidateRecipeSkinRequest
                == wrapped_target_validator)
            assert(ValidateRecipeSkinRequest == wrapped_global_validator)
            assert(TheInventory.CheckOwnership == wrapped_ownership)
            assert(AllPlayers[1].components.tbat_com_skins_controller.HasSkin
                == wrapped_has_skin)

            local new_controller = {
                HasSkin = function(...) return "new", nil, "tail" end,
            }
            local player_tasks = {}
            player_post({
                components = { tbat_com_skins_controller = new_controller },
                DoTaskInTime = function(self, delay, callback)
                    table.insert(player_tasks, { delay = delay, callback = callback })
                end,
            })
            assert(new_controller.HasSkin ~= nil)
            assert(#player_tasks == 3)
            assert(player_tasks[1].delay == 0.5)
            assert(player_tasks[3].delay == 5)
            assert(type(prefab_posts.cave) == "function")
            return true
        end
        """
    )()


def test_niaoniao_restores_unlock_map_wrappers_and_retry_groups() -> None:
    lua = _runtime()
    lua.execute(
        """
        bird_record = { prefab_name = "bird", marker = "bird-record" }
        nest_record = { prefab_name = "nest", marker = "nest-record" }
        NIAO = {
            SKIN = {
                SKINS_DATA_SKINS = {
                    bird_skin = bird_record,
                    nest_skin = nest_record,
                },
                DATA_INIT = { "bird_skin", "nest_skin" },
                __default_unlock_list = { "bird_skin", "nest_skin" },
                __default_unlock_list_idx = 2,
            },
        }

        original_calls = {}
        local function original(name)
            return function(...)
                original_calls[name] = { n = select("#", ...), ... }
                return name, nil, name .. "-tail"
            end
        end
        local function controller(name)
            return {
                HasSkin = original(name .. "_has"),
                UnlockSkin = function(self, unlock_data)
                    original_calls[name .. "_unlock"] = {
                        self = self,
                        unlock_data = unlock_data,
                    }
                end,
                SetUnlockedData = original(name .. "_set"),
            }
        end

        component_controller = controller("component")
        replica_controller = controller("replica")
        nested_controller = controller("nested")
        original_component_set = component_controller.SetUnlockedData
        original_replica_set = replica_controller.SetUnlockedData
        original_nested_set = nested_controller.SetUnlockedData
        AllPlayers = {
            {
                components = {
                    niao_com_skins_controller = component_controller,
                },
                replica = {
                    niao_com_skins_controller = replica_controller,
                    _ = { niao_com_skins_controller = nested_controller },
                },
            },
        }
        inventory_marker = function() return false end
        TheInventory = { CheckOwnership = inventory_marker }

        enabled_calls = 0
        KnownModIndex = {
            IsModEnabled = function()
                enabled_calls = enabled_calls + 1
                return true
            end,
            savedata = {},
        }

        player_post = nil
        sim_post = nil
        prefab_posts = {}
        AddPlayerPostInit = function(callback) player_post = callback end
        AddSimPostInit = function(callback) sim_post = callback end
        AddPrefabPostInit = function(prefab, callback)
            prefab_posts[prefab] = callback
        end
        printed = {}
        print = function(message) table.insert(printed, message) end
        """
    )

    _load_root(lua, "Niaoniao_Character.business.lua")()
    lua.eval("sim_post")()

    assert lua.eval(
        """
        function()
            for name, controller in pairs({
                component = component_controller,
                replica = replica_controller,
                nested = nested_controller,
            }) do
                local unlock_call = original_calls[name .. "_unlock"]
                assert(unlock_call.self == controller)
                assert(unlock_call.unlock_data.bird == bird_record)
                assert(unlock_call.unlock_data.nest == nest_record)
            end

            local function pack(...)
                return { n = select("#", ...), ... }
            end
            local results = pack(component_controller.HasSkin(
                "a", nil, "c", "d"
            ))
            assert(results.n == 3)
            assert(results[1] == "component_has")
            assert(results[2] == nil)
            assert(results[3] == "component_has-tail")
            assert(original_calls.component_has.n == 4)
            assert(original_calls.component_has[3] == "c")
            assert(original_calls.component_has[4] == "d")

            assert(component_controller.SetUnlockedData
                == original_component_set)
            assert(replica_controller.SetUnlockedData == original_replica_set)
            assert(nested_controller.SetUnlockedData == original_nested_set)
            assert(TheInventory.CheckOwnership == inventory_marker)
            assert(enabled_calls == 0)
            assert(string.find(
                printed[1],
                "skins=2 default_unlocks=2",
                1,
                true
            ))
            return true
        end
        """
    )()

    assert lua.eval(
        """
        function()
            local wrapped = component_controller.HasSkin
            sim_post()
            assert(component_controller.HasSkin == wrapped)

            local world_tasks = {}
            local world = {
                DoTaskInTime = function(self, delay, callback)
                    table.insert(world_tasks, delay)
                end,
            }
            prefab_posts.world(world)
            prefab_posts.cave(world)
            assert(#world_tasks == 4)
            assert(world_tasks[1] == 0)
            assert(world_tasks[4] == 8)

            local player_tasks = {}
            player_post({
                DoTaskInTime = function(self, delay, callback)
                    table.insert(player_tasks, delay)
                end,
            })
            assert(#player_tasks == 2)
            assert(player_tasks[1] == 0.5)
            assert(player_tasks[2] == 2)
            return true
        end
        """
    )()
