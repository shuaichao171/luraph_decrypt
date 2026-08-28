-- High-level semantic reconstruction of scripts/Book_of_All_Things.lua.
-- Registry writes, wrappers, scan surfaces, and scheduling are probe-confirmed.

local TARGET_WORKSHOP_ID = "3544387985"
local CONTROLLER_NAME = "tbat_com_skins_controller"
local WORLD_DELAYS = { 0, 0.25, 1, 3, 8, 15, 30, 120 }
local PLAYER_DELAYS = { 0.5, 2, 5 }
local MISSING_MESSAGE =
    "[SKIN_BRIDGE_BOOK] target mod not loaded, skipped"

local scheduled_worlds = setmetatable({}, { __mode = "k" })
local scheduled_players = setmetatable({}, { __mode = "k" })
local wrapped_methods = setmetatable({}, { __mode = "k" })
local missing_warning_latched = false

local function allow_skin_access()
    return true
end

local function locate_target_environment()
    if KnownModIndex == nil
        or ModManager == nil
        or type(KnownModIndex.GetModsToLoad) ~= "function"
        or type(KnownModIndex.GetModInfo) ~= "function"
        or type(ModManager.GetMod) ~= "function"
    then
        return nil, nil
    end

    for _, mod_name in pairs(KnownModIndex:GetModsToLoad(true) or {}) do
        if string.find(tostring(mod_name), TARGET_WORKSHOP_ID, 1, true)
            and KnownModIndex:GetModInfo(mod_name) ~= nil
        then
            local environment = ModManager:GetMod(mod_name)
            if type(environment) == "table" then
                return environment, mod_name
            end
        end
    end
    return nil, nil
end

local function wrap_passthrough(owner, field)
    if type(owner) ~= "table" then
        return false
    end

    local owner_records = wrapped_methods[owner]
    if owner_records == nil then
        owner_records = {}
        wrapped_methods[owner] = owner_records
    end

    local current = rawget(owner, field)
    local previous = owner_records[field]
    if previous ~= nil and current == previous.wrapper then
        return false
    end
    if type(current) ~= "function" then
        return false
    end

    local original = current
    local function wrapper(...)
        return original(...)
    end
    owner_records[field] = { original = original, wrapper = wrapper }
    rawset(owner, field, wrapper)
    return true
end

local function patch_skin_record(record, seen_records, stats)
    if type(record) ~= "table" or seen_records[record] then
        return
    end
    seen_records[record] = true
    stats.skins = stats.skins + 1

    if rawget(record, "checkfn") ~= allow_skin_access then
        rawset(record, "checkfn", allow_skin_access)
        stats.data = stats.data + 1
    end
    if rawget(record, "checkclientfn") ~= allow_skin_access then
        rawset(record, "checkclientfn", allow_skin_access)
        stats.data = stats.data + 1
    end
    if rawget(record, "unlock") ~= true then
        rawset(record, "unlock", true)
        stats.data = stats.data + 1
    end
end

local function patch_registry(registry, seen_records, stats)
    if type(registry) ~= "table" then
        return
    end
    for _, record in pairs(registry) do
        patch_skin_record(record, seen_records, stats)
    end
end

local function patch_registries(environment, stats)
    local seen_records = {}
    patch_registry(rawget(environment, "characterskins"), seen_records, stats)
    patch_registry(rawget(environment, "itemskins"), seen_records, stats)
    patch_registry(rawget(environment, "CHARACTERSKINS"), seen_records, stats)
    patch_registry(rawget(environment, "ITEMSKINS"), seen_records, stats)

    local get_all_skin = rawget(environment, "GetAllSkin")
    if type(get_all_skin) == "function" then
        local character_skins, item_skins = get_all_skin()
        patch_registry(character_skins, seen_records, stats)
        patch_registry(item_skins, seen_records, stats)
    end
end

local function patch_inventory(stats)
    local inventory = rawget(_G, "TheInventory")
    if type(inventory) ~= "table" then
        return
    end

    for _, field in ipairs({
        "CheckOwnership",
        "CheckOwnershipGetLatest",
        "CheckClientOwnership",
    }) do
        if wrap_passthrough(inventory, field) then
            stats.inventory = stats.inventory + 1
        end
    end
    rawset(inventory, "HasSupportForOfflineSkins", allow_skin_access)
end

local function patch_controller(controller)
    if type(controller) ~= "table" then
        return 0
    end
    return wrap_passthrough(controller, "HasSkin") and 1 or 0
end

local function patch_player(player)
    if type(player) ~= "table" then
        return 0
    end

    local components = rawget(player, "components")
    local replica = rawget(player, "replica")
    local nested_replica = type(replica) == "table" and rawget(replica, "_")
        or nil
    local candidates = {
        type(components) == "table" and rawget(components, CONTROLLER_NAME)
            or nil,
        type(replica) == "table" and rawget(replica, CONTROLLER_NAME) or nil,
        type(nested_replica) == "table"
            and rawget(nested_replica, CONTROLLER_NAME)
            or nil,
    }

    local seen = {}
    local patched = 0
    for _, controller in pairs(candidates) do
        if type(controller) == "table" and not seen[controller] then
            seen[controller] = true
            patched = patched + patch_controller(controller)
        end
    end
    return patched
end

local function count_functions(value, seen, stats)
    local value_type = type(value)
    if (value_type ~= "table" and value_type ~= "function") or seen[value] then
        return
    end
    seen[value] = true

    if value_type == "function" then
        stats.functions = stats.functions + 1
        local getupvalue = debug and debug.getupvalue
        if type(getupvalue) == "function" then
            local index = 1
            while true do
                local name, upvalue = getupvalue(value, index)
                if name == nil then
                    break
                end
                count_functions(upvalue, seen, stats)
                index = index + 1
            end
        end
        return
    end

    for key, item in pairs(value) do
        count_functions(key, seen, stats)
        count_functions(item, seen, stats)
    end
end

local function count_scan_surfaces(environment, stats)
    local seen = {}
    count_functions(environment, seen, stats)
    count_functions(rawget(_G, "BOOKOFALLTHINGS"), seen, stats)
    count_functions(rawget(_G, "PREFAB_SKINS"), seen, stats)
    count_functions(rawget(_G, "TBAT"), seen, stats)
    count_functions(rawget(_G, "TheInventory"), seen, stats)
    count_functions(rawget(_G, "ValidateRecipeSkinRequest"), seen, stats)
    count_functions(rawget(_G, "Sim"), seen, stats)
    count_functions(rawget(_G, "AllPlayers"), seen, stats)
    count_functions(rawget(_G, "ThePlayer"), seen, stats)
    count_functions(rawget(_G, "TheWorld"), seen, stats)
end

local function patch_book_environment()
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
        upvalues = 0,
        inventory = 0,
        validators = 0,
        components = 0,
        functions = 0,
    }

    patch_registries(environment, stats)
    wrap_passthrough(environment, "MakeCharacterSkin")
    wrap_passthrough(environment, "MakeItemSkin")

    rawset(environment, "TbatSkinCheckFn", allow_skin_access)
    rawset(environment, "TbatSkinCheckClientFn", allow_skin_access)
    rawset(_G, "TbatSkinCheckFn", allow_skin_access)
    rawset(_G, "TbatSkinCheckClientFn", allow_skin_access)

    if wrap_passthrough(environment, "ValidateRecipeSkinRequest") then
        stats.validators = stats.validators + 1
    end
    if wrap_passthrough(_G, "ValidateRecipeSkinRequest") then
        stats.validators = stats.validators + 1
    end

    patch_inventory(stats)
    local players = rawget(_G, "AllPlayers")
    if type(players) == "table" then
        for _, player in pairs(players) do
            stats.components = stats.components + patch_player(player)
        end
    end
    stats.components = stats.components + patch_player(rawget(_G, "ThePlayer"))

    count_scan_surfaces(environment, stats)
    rawset(_G, "PRISM_TERRA_BRIDGE_BOOK_ENABLED", true)
    print(string.format(
        "[SKIN_BRIDGE_BOOK] mod=%s skins=%d data=%d upvalues=%d "
            .. "inventory=%d validators=%d components=%d functions=%d",
        tostring(mod_name),
        stats.skins,
        stats.data,
        stats.upvalues,
        stats.inventory,
        stats.validators,
        stats.components,
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
    local _ = inst and inst.DoPeriodicTask
    schedule(inst, WORLD_DELAYS, scheduled_worlds, patch_book_environment)
end

local function on_player_post_init(inst)
    patch_player(inst)
    local function retry_player()
        patch_book_environment()
        patch_player(inst)
    end
    schedule(inst, PLAYER_DELAYS, scheduled_players, retry_player)
end

local function reconstructed_root()
    patch_book_environment()
    AddSimPostInit(on_world_post_init)
    AddPrefabPostInit("world", on_world_post_init)
    AddPrefabPostInit("cave", on_world_post_init)
    AddPlayerPostInit(on_player_post_init)
end

return reconstructed_root
