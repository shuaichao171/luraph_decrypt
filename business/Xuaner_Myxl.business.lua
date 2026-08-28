-- High-level semantic reconstruction of scripts/Xuaner_Myxl.lua.
-- Registry writes, registration wrappers, inventory methods, and scheduling
-- below are constrained by completed loaded-mod probes.

local TARGET_WORKSHOP_ID = "3014076942"
local TARGET_PREFAB = "moyuxuanli"
local MISSING_MESSAGE =
    "[SKIN_BRIDGE_XUANER] target mod not loaded, skipped"
local WORLD_DELAYS = { 0, 0.25, 1, 3, 8, 15, 30, 120 }
local TARGET_PREFAB_DELAYS = { 0, 0.5, 2 }
local PLAYER_DELAYS = { 0.5, 2, 5 }

-- The VM constructs this comparison set. No controlled fixture reached the
-- compatibility branch that consumes it, so no side effect is inferred.
local COMPATIBILITY_WORKSHOP_IDS = {
    ["workshop-2494336473"] = true,
    ["workshop-2795779788"] = true,
    ["workshop-2804641749"] = true,
    ["workshop-2821661403"] = true,
    ["workshop-3050683705"] = true,
    ["workshop-3124619639"] = true,
    ["workshop-3244139639"] = true,
    ["workshop-3596861261"] = true,
    ["workshop-3612137133"] = true,
}

local unpack_results = unpack or table.unpack
local scheduled_worlds = setmetatable({}, { __mode = "k" })
local scheduled_target_prefabs = setmetatable({}, { __mode = "k" })
local scheduled_players = setmetatable({}, { __mode = "k" })
local registration_wrappers = setmetatable({}, { __mode = "k" })
local passthrough_wrappers = setmetatable({}, { __mode = "k" })
local ownership_wrappers = setmetatable({}, { __mode = "k" })
local latest_ownership_wrappers = setmetatable({}, { __mode = "k" })
local client_ownership_wrappers = setmetatable({}, { __mode = "k" })
local target_skin_names = {}
local missing_warning_latched = false

local function always_true()
    return true
end

local function pack_results(...)
    return { n = select("#", ...), ... }
end

local function locate_target_environment()
    if KnownModIndex == nil or ModManager == nil then
        return nil, nil
    end
    for _, mod_name in pairs(KnownModIndex:GetModsToLoad(true) or {}) do
        if string.find(tostring(mod_name), TARGET_WORKSHOP_ID, 1, true) then
            local environment = ModManager:GetMod(mod_name)
            if type(environment) == "table" then
                return environment, mod_name
            end
        end
    end
    return nil, nil
end

local function is_target_skin_name(skin_name)
    if type(skin_name) ~= "string" then
        return false
    end
    if target_skin_names[skin_name] then
        return true
    end
    return string.find(skin_name, TARGET_PREFAB, 1, true) == 1
end

local function collect_prefab_skin_names(registry)
    if type(registry) ~= "table" then
        return
    end
    local names = rawget(registry, TARGET_PREFAB)
    if type(names) ~= "table" then
        return
    end
    for _, skin_name in pairs(names) do
        if type(skin_name) == "string" then
            target_skin_names[skin_name] = true
        end
    end
end

local function patch_skin_record(record, stats)
    if type(record) ~= "table" then
        return false
    end

    local changed = 0
    if rawget(record, "checkfn") ~= always_true then
        record.checkfn = always_true
        changed = changed + 1
    end
    if rawget(record, "checkclientfn") ~= always_true then
        record.checkclientfn = always_true
        changed = changed + 1
    end
    if rawget(record, "unlock") ~= true then
        record.unlock = true
        changed = changed + 1
    end
    if rawget(record, "is_restricted") ~= false then
        record.is_restricted = false
        changed = changed + 1
    end

    if stats ~= nil then
        stats.data = stats.data + changed
    end
    return true
end

local function patch_registry(registry, seen_records, stats)
    if type(registry) ~= "table" then
        return
    end
    for skin_name, record in pairs(registry) do
        if is_target_skin_name(skin_name)
                and type(record) == "table"
                and not seen_records[record] then
            seen_records[record] = true
            stats.skins = stats.skins + 1
            patch_skin_record(record, stats)
        end
    end
end

local function patch_get_all_skin(owner, seen_functions, seen_records, stats)
    if type(owner) ~= "table" then
        return
    end
    local get_all_skin = rawget(owner, "GetAllSkin")
    if type(get_all_skin) ~= "function" or seen_functions[get_all_skin] then
        return
    end
    seen_functions[get_all_skin] = true
    local results = pack_results(get_all_skin())
    for index = 1, results.n do
        patch_registry(results[index], seen_records, stats)
    end
end

local function patch_registries(environment, stats)
    collect_prefab_skin_names(rawget(_G, "PREFAB_SKINS"))
    collect_prefab_skin_names(rawget(environment, "PREFAB_SKINS"))

    local seen_records = {}
    patch_registry(rawget(_G, "CHARACTERSKINS"), seen_records, stats)
    patch_registry(rawget(_G, "ITEMSKINS"), seen_records, stats)
    patch_registry(rawget(environment, "CHARACTERSKINS"), seen_records, stats)
    patch_registry(rawget(environment, "ITEMSKINS"), seen_records, stats)

    local seen_functions = {}
    patch_get_all_skin(environment, seen_functions, seen_records, stats)
    patch_get_all_skin(rawget(_G, "MYXLAPI"), seen_functions,
        seen_records, stats)
    patch_get_all_skin(rawget(environment, "MYXLAPI"), seen_functions,
        seen_records, stats)
end

local function wrap_registration(owner, field)
    if type(owner) ~= "table" then
        return false
    end
    local current = rawget(owner, field)
    if type(current) ~= "function" or registration_wrappers[current] then
        return false
    end

    local original = current
    local function wrapper(prefab, skin_name, data)
        patch_skin_record(data)
        return original(prefab, skin_name, data)
    end
    registration_wrappers[wrapper] = true
    owner[field] = wrapper
    return true
end

local function patch_registration_apis(environment)
    local global_api = rawget(_G, "MYXLAPI")
    local environment_api = rawget(environment, "MYXLAPI")
    for _, owner in pairs({ global_api, environment_api, environment }) do
        wrap_registration(owner, "MakeCharacterSkin")
        wrap_registration(owner, "MakeItemSkin")
    end
end

local function wrap_global_passthrough(field)
    local current = rawget(_G, field)
    if type(current) ~= "function" or passthrough_wrappers[current] then
        return false
    end

    local original = current
    local function wrapper(...)
        return original(...)
    end
    passthrough_wrappers[wrapper] = true
    rawset(_G, field, wrapper)
    return true
end

local function patch_global_hooks()
    wrap_global_passthrough("MYXLPushPopupDialog")
    wrap_global_passthrough("SetSkinnedOvalPortraitTexture")
    wrap_global_passthrough("DoRestart")
end

local function inventory_method_table()
    local inventory = rawget(_G, "TheInventory")
    if inventory == nil then
        return nil
    end
    local metatable = getmetatable(inventory)
    if type(metatable) ~= "table" then
        return nil
    end
    local methods = rawget(metatable, "__index")
    return type(methods) == "table" and methods or nil
end

local function wrap_check_ownership(methods)
    local current = rawget(methods, "CheckOwnership")
    if type(current) ~= "function" or ownership_wrappers[current] then
        return
    end
    local original = current
    local function wrapper(owner, skin_name, ...)
        if is_target_skin_name(skin_name) then
            return true
        end
        return original(owner, skin_name, ...)
    end
    ownership_wrappers[wrapper] = true
    methods.CheckOwnership = wrapper
end

local function wrap_check_ownership_latest(methods)
    local current = rawget(methods, "CheckOwnershipGetLatest")
    if type(current) ~= "function" or latest_ownership_wrappers[current] then
        return
    end
    local original = current
    local function wrapper(owner, skin_name, ...)
        if is_target_skin_name(skin_name) then
            return true, 0
        end
        return original(owner, skin_name, ...)
    end
    latest_ownership_wrappers[wrapper] = true
    methods.CheckOwnershipGetLatest = wrapper
end

local function wrap_check_client_ownership(methods)
    local current = rawget(methods, "CheckClientOwnership")
    if type(current) ~= "function" or client_ownership_wrappers[current] then
        return
    end
    local original = current
    local function wrapper(owner, skin_name)
        return original(owner, skin_name, nil)
    end
    client_ownership_wrappers[wrapper] = true
    methods.CheckClientOwnership = wrapper
end

local function patch_inventory()
    local methods = inventory_method_table()
    if methods == nil then
        return nil
    end
    wrap_check_ownership(methods)
    wrap_check_ownership_latest(methods)
    wrap_check_client_ownership(methods)
    methods.HasSupportForOfflineSkins = always_true
    return methods
end

local function count_functions(value, seen)
    local value_type = type(value)
    if (value_type ~= "table" and value_type ~= "function") or seen[value] then
        return 0
    end
    seen[value] = true
    if value_type == "function" then
        return 1
    end
    local count = 0
    for key, child in pairs(value) do
        count = count + count_functions(key, seen)
        count = count + count_functions(child, seen)
    end
    return count
end

local function patch_xuaner_environment(extra_root)
    local environment, mod_name = locate_target_environment()
    if environment == nil then
        if not missing_warning_latched then
            missing_warning_latched = true
            print(MISSING_MESSAGE)
        end
        return nil
    end

    local stats = {
        skins = 0,
        data = 0,
        owner = 0,
        hooks = 0,
        ui = 0,
        compat = 0,
        security = 0,
        functions = 0,
    }

    patch_registries(environment, stats)
    patch_registration_apis(environment)
    patch_global_hooks()
    local inventory_methods = patch_inventory()
    rawset(_G, "PRISM_TERRA_BRIDGE_XUANER_ENABLED", true)

    local seen_functions = {}
    stats.functions = stats.functions
        + count_functions(environment, seen_functions)
        + count_functions(extra_root, seen_functions)
        + count_functions(inventory_methods, seen_functions)

    -- Retain the confirmed comparison data without assigning behavior to its
    -- still-unreached compatibility and security branches.
    local _ = COMPATIBILITY_WORKSHOP_IDS
    print(string.format(
        "[SKIN_BRIDGE_XUANER] mod=%s skins=%d data=%d owner=%d "
            .. "hooks=%d ui=%d compat=%d security=%d functions=%d",
        tostring(mod_name),
        stats.skins,
        stats.data,
        stats.owner,
        stats.hooks,
        stats.ui,
        stats.compat,
        stats.security,
        stats.functions
    ))
    return environment
end

local function schedule(inst, delays, seen, callback)
    if inst == nil or type(inst.DoTaskInTime) ~= "function" or seen[inst] then
        return
    end
    seen[inst] = true
    for _, delay in ipairs(delays) do
        inst:DoTaskInTime(delay, callback)
    end
end

local function on_world_post_init(inst)
    -- The original reads DoPeriodicTask, but the completed trace did not call
    -- it. The eight one-shot retries below are observed.
    local _ = inst and inst.DoPeriodicTask
    schedule(inst, WORLD_DELAYS, scheduled_worlds, patch_xuaner_environment)
end

local function on_target_prefab(inst)
    schedule(inst, TARGET_PREFAB_DELAYS, scheduled_target_prefabs,
        patch_xuaner_environment)
end

local function on_player_post_init(inst)
    schedule(inst, PLAYER_DELAYS, scheduled_players,
        patch_xuaner_environment)
end

local function on_controls_post_construct(controls)
    patch_xuaner_environment(controls)
end

local function reconstructed_root()
    patch_xuaner_environment()
    AddClassPostConstruct("widgets/controls", on_controls_post_construct)
    AddSimPostInit(on_world_post_init)
    AddPrefabPostInit("world", on_world_post_init)
    AddPrefabPostInit("cave", on_world_post_init)
    AddPrefabPostInit(TARGET_PREFAB, on_target_prefab)
    AddPlayerPostInit(on_player_post_init)
end

return reconstructed_root
