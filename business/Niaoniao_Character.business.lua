-- High-level semantic reconstruction of scripts/Niaoniao_Character.lua.

local CONTROLLER_NAME = "niao_com_skins_controller"
local PLAYER_DELAYS = { 0.5, 2 }
local WORLD_DELAYS = { 0, 1, 3, 8 }
local MISSING_MESSAGE =
    "[SKIN_BRIDGE_NIAO] target mod not ready, skipped"

local scheduled_players = setmetatable({}, { __mode = "k" })
local scheduled_worlds = setmetatable({}, { __mode = "k" })
local controller_records = setmetatable({}, { __mode = "k" })
local missing_warning_latched = false

local function make_method_record(owner, method_name)
    local raw_value = rawget(owner, method_name)
    local original = owner[method_name]
    return {
        method_owner = owner,
        method_original = original,
        method_raw_value = raw_value,
        method_had_raw_value = raw_value ~= nil,
        restored = false,
    }
end

local function niao_skin_api()
    if KnownModIndex == nil then
        return nil
    end

    -- Both fields are read by the original readiness check. The available
    -- trace does not prove an IsModEnabled call or a workshop-id comparison.
    local is_mod_enabled = KnownModIndex.IsModEnabled
    local savedata = KnownModIndex.savedata
    if is_mod_enabled == nil or savedata == nil then
        return nil
    end

    local niao = rawget(_G, "NIAO")
    local skin = type(niao) == "table" and niao.SKIN or nil
    if type(skin) ~= "table" then
        return nil
    end
    return skin
end

local function collect_skin_data(skin_api)
    local unlock_data = {}
    local skin_count = 0
    local records = skin_api.SKINS_DATA_SKINS
    local data_init = skin_api.DATA_INIT
    if type(records) == "table" and type(data_init) == "table" then
        for _, skin_name in pairs(data_init) do
            local record = records[skin_name]
            local prefab_name = type(record) == "table"
                and record.prefab_name
            if prefab_name ~= nil then
                unlock_data[prefab_name] = record
                skin_count = skin_count + 1
            end
        end
    end

    local _ = skin_api.__default_unlock_list
    local default_unlock_count =
        tonumber(skin_api.__default_unlock_list_idx) or 0
    return unlock_data, skin_count, default_unlock_count
end

local function wrap_has_skin(controller)
    local previous = controller_records[controller]
    if previous ~= nil and controller.HasSkin == previous.wrapper then
        return previous
    end

    local record = make_method_record(controller, "HasSkin")
    if type(record.method_original) ~= "function" then
        return nil
    end

    local original = record.method_original
    local function wrapper(...)
        return original(...)
    end
    record.wrapper = wrapper
    controller_records[controller] = record
    rawset(controller, "HasSkin", wrapper)
    return record
end

local function patch_controller(controller, unlock_data)
    if type(controller) ~= "table" then
        return false
    end

    local has_skin = controller.HasSkin
    local unlock_skin = controller.UnlockSkin
    local _ = controller.SetUnlockedData
    if type(unlock_skin) == "function" then
        unlock_skin(controller, unlock_data)
    end
    if type(has_skin) == "function" then
        wrap_has_skin(controller)
        return true
    end
    return false
end

local function patch_player(player, unlock_data)
    if type(player) ~= "table" then
        return
    end
    local seen = {}
    local components = player.components
    local replica = player.replica
    local nested_replica = type(replica) == "table" and replica._ or nil
    local candidates = {
        type(components) == "table" and components[CONTROLLER_NAME] or nil,
        type(replica) == "table" and replica[CONTROLLER_NAME] or nil,
        type(nested_replica) == "table" and nested_replica[CONTROLLER_NAME]
            or nil,
    }
    for _, controller in pairs(candidates) do
        if type(controller) == "table" and not seen[controller] then
            seen[controller] = true
            patch_controller(controller, unlock_data)
        end
    end
end

local function patch_niaoniao()
    local skin_api = niao_skin_api()
    if skin_api == nil then
        if not missing_warning_latched then
            missing_warning_latched = true
            print(MISSING_MESSAGE)
        end
        return nil
    end

    local unlock_data, skin_count, default_unlock_count =
        collect_skin_data(skin_api)
    local _ = rawget(_G, "TheInventory")
    local players = rawget(_G, "AllPlayers")
    if type(players) == "table" then
        for _, player in pairs(players) do
            patch_player(player, unlock_data)
        end
    end

    print(string.format(
        "[SKIN_BRIDGE_NIAO] skins=%d default_unlocks=%d",
        skin_count,
        default_unlock_count
    ))
    return unlock_data
end

local function schedule(inst, delays, seen)
    if inst == nil or type(inst.DoTaskInTime) ~= "function" then
        return
    end
    if seen[inst] then
        return
    end
    seen[inst] = true
    for _, delay in ipairs(delays) do
        inst:DoTaskInTime(delay, patch_niaoniao)
    end
end

local function on_player_post_init(inst)
    schedule(inst, PLAYER_DELAYS, scheduled_players)
end

local function on_world_post_init(inst)
    schedule(inst, WORLD_DELAYS, scheduled_worlds)
end

local function reconstructed_root()
    AddPlayerPostInit(on_player_post_init)
    AddSimPostInit(patch_niaoniao)
    AddPrefabPostInit("world", on_world_post_init)
    AddPrefabPostInit("cave", on_world_post_init)
end

return reconstructed_root
