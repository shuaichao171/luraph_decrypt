-- High-level semantic reconstruction of scripts/Shugo_Chara.lua.

local TARGET_WORKSHOP_ID = "3573399040" -- Confirmed by loaded-mod probes.
local WORLD_DELAYS = { 0, 0.25, 1, 3, 8, 30 }
local PLAYER_DELAYS = { 0.5, 2 }
local unpack_results = table.unpack or unpack

local scheduled_worlds = setmetatable({}, { __mode = "k" })
local scheduled_players = setmetatable({}, { __mode = "k" })
local registration_wrappers = setmetatable({}, { __mode = "k" })
local registration_wrapper_count = 0

local function pack_results(...)
    return { n = select("#", ...), ... }
end

local function allow_skin_access()
    return true
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

local function patch_skin_record(record, registry_kind, stats)
    if type(record) ~= "table" then
        return
    end

    local changed = record.checkfn ~= allow_skin_access
        or record.checkclientfn ~= allow_skin_access
        or record.unlock ~= true
        or record.is_restricted ~= false

    rawset(record, "checkfn", allow_skin_access)
    rawset(record, "checkclientfn", allow_skin_access)
    rawset(record, "unlock", true)
    rawset(record, "is_restricted", false)

    stats.skins = stats.skins + 1
    if registry_kind == "characterskins"
        or record.ischaracterskins == true
    then
        stats.character_skins = stats.character_skins + 1
    else
        stats.item_skins = stats.item_skins + 1
    end
    if changed then
        stats.changed = stats.changed + 1
    end
end

local function patch_registry(registry, registry_kind, stats)
    if type(registry) ~= "table" then
        return
    end
    for _, record in pairs(registry) do
        patch_skin_record(record, registry_kind, stats)
    end
end

local function install_passthrough_wrapper(environment, field)
    local current = rawget(environment, field)
    local previous = registration_wrappers[current]
    if previous ~= nil and current == previous.wrapper then
        return false
    end
    if type(current) ~= "function" then
        return false
    end

    local original = current
    local function wrapper(...)
        local results = pack_results(original(...))
        return unpack_results(results, 1, results.n)
    end
    registration_wrappers[wrapper] = {
        original = original,
        wrapper = wrapper,
    }
    rawset(environment, field, wrapper)
    registration_wrapper_count = registration_wrapper_count + 1
    return true
end

local function replace_existing_function(environment, field)
    local current = rawget(environment, field)
    if type(current) ~= "function" or current == allow_skin_access then
        return false
    end
    rawset(environment, field, allow_skin_access)
    return true
end

local function patch_shugo_environment()
    local environment, mod_name = locate_target_environment()
    if environment == nil then
        return nil
    end

    local stats = {
        skins = 0,
        character_skins = 0,
        item_skins = 0,
        registration_wrappers = 0,
        inventory_wrappers = 0,
        changed = 0,
    }

    local get_all_skin = rawget(environment, "GetAllSkin")
    if type(get_all_skin) == "function" then
        local character_skins, item_skins = get_all_skin()
        patch_registry(character_skins, "characterskins", stats)
        patch_registry(item_skins, "itemskins", stats)
    end

    if replace_existing_function(environment, "_SkinCheckFn") then
        stats.changed = stats.changed + 1
    end
    if replace_existing_function(environment, "_SkinCheckClientFn") then
        stats.changed = stats.changed + 1
    end

    -- This target-local ownership entry is replaced with an unconditional
    -- allow function. The original statistics do not count it as an inventory
    -- wrapper or as a changed registry record.
    replace_existing_function(environment, "skdwdwswpp")

    install_passthrough_wrapper(environment, "MakeCharacterSkin")
    install_passthrough_wrapper(environment, "MakeItemSkin")
    stats.registration_wrappers = registration_wrapper_count

    -- The bridge checks for the global inventory object but does not replace
    -- CheckOwnership, CheckOwnershipGetLatest, or CheckClientOwnership.
    local _ = rawget(_G, "TheInventory")

    print(string.format(
        "[SKIN_BRIDGE_SHUGO] mod=%s skins=%d character=%d item=%d "
            .. "registration=%d inventory=%d changed=%d",
        tostring(mod_name),
        stats.character_skins + stats.item_skins,
        stats.character_skins,
        stats.item_skins,
        stats.registration_wrappers,
        stats.inventory_wrappers,
        stats.changed
    ))
    return environment
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
        inst:DoTaskInTime(delay, patch_shugo_environment)
    end
end

local function on_world_post_init(inst)
    schedule(inst, WORLD_DELAYS, scheduled_worlds)
end

local function on_player_post_init(inst)
    schedule(inst, PLAYER_DELAYS, scheduled_players)
end

local function reconstructed_root()
    patch_shugo_environment()
    AddGamePostInit(patch_shugo_environment)
    AddSimPostInit(on_world_post_init)
    AddPrefabPostInit("world", on_world_post_init)
    AddPrefabPostInit("cave", on_world_post_init)
    AddPlayerPostInit(on_player_post_init)
end

return reconstructed_root
