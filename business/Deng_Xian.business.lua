-- High-level semantic reconstruction of scripts/Deng_Xian.lua.
-- The named inventory upvalues, registry writes, and classification rules are
-- dynamically confirmed with the target function layout.

local TARGET_DISPLAY_NAME =
    "\227\128\144\231\153\187\228\187\153\227\128\145"
local RETRY_DELAYS = { 0, 1 }
local scheduled = setmetatable({}, { __mode = "k" })

local stats = {
    api_wrappers = 0,
    license_checks = 0,
    item_skins = 0,
    character_skins = 0,
    ui_skins = 0,
}

local patched_records = setmetatable({}, { __mode = "k" })

local function owns_skin()
    return true
end

local function locate_target_environment()
    if KnownModIndex == nil or ModManager == nil then
        return nil, nil
    end
    for _, mod_name in pairs(KnownModIndex:GetModsToLoad(true) or {}) do
        local mod_info = KnownModIndex:GetModInfo(mod_name)
        if type(mod_info) == "table" and mod_info.name == TARGET_DISPLAY_NAME then
            local environment = ModManager:GetMod(mod_name)
            if type(environment) == "table" then
                return environment, mod_name
            end
        end
    end
    return nil, nil
end

local function patch_skin_record(record, registry_kind)
    if type(record) ~= "table" then
        return 0
    end

    local changed = record.checkfn ~= owns_skin
        or record.checkclientfn ~= owns_skin
        or record.unlock ~= true
        or record.is_restricted ~= false

    rawset(record, "checkfn", owns_skin)
    rawset(record, "checkclientfn", owns_skin)
    rawset(record, "unlock", true)
    rawset(record, "is_restricted", false)

    if not patched_records[record] then
        patched_records[record] = true
        if registry_kind == "characterskins"
            or record.ischaracterskins == true
        then
            stats.character_skins = stats.character_skins + 1
        else
            stats.item_skins = stats.item_skins + 1
        end
    end
    return changed and 1 or 0
end

local function patch_registry(registry, registry_kind)
    if type(registry) ~= "table" then
        return 0
    end

    local patched_now = 0
    for _, record in pairs(registry) do
        patched_now = patched_now + patch_skin_record(record, registry_kind)
    end
    return patched_now
end

local function scan_value(value, seen)
    local value_type = type(value)
    if (value_type ~= "table" and value_type ~= "function") or seen[value] then
        return 0
    end
    seen[value] = true

    local patched_now = 0

    if value_type == "function" then
        if debug == nil or type(debug.getupvalue) ~= "function" then
            return 0
        end
        local index = 1
        while true do
            local name, upvalue = debug.getupvalue(value, index)
            if name == nil then
                break
            end
            if name == "characterskins" or name == "itemskins" then
                patched_now = patched_now
                    + patch_registry(upvalue, name)
            end
            patched_now = patched_now + scan_value(upvalue, seen)
            index = index + 1
        end
        return patched_now
    end

    for key, child in pairs(value) do
        patched_now = patched_now + scan_value(key, seen)
        patched_now = patched_now + scan_value(child, seen)
    end
    return patched_now
end

local function patch_dengxian()
    local environment = locate_target_environment()
    if environment == nil then
        return nil
    end

    local seen = {}
    local patched_now = scan_value(environment, seen)
    patched_now = patched_now
        + scan_value(rawget(_G, "skdwdwswpp"), seen)

    local inventory = rawget(_G, "TheInventory")
    if type(inventory) == "table" then
        patched_now = patched_now
            + scan_value(inventory.CheckOwnership, seen)
        patched_now = patched_now
            + scan_value(inventory.CheckOwnershipGetLatest, seen)
        patched_now = patched_now
            + scan_value(inventory.CheckClientOwnership, seen)
    end

    print(string.format(
        "[SKIN_BRIDGE_DENGXIAN] wrappers=%d license=%d item=%d "
            .. "character=%d ui=%d patched_now=%d",
        stats.api_wrappers,
        stats.license_checks,
        stats.item_skins,
        stats.character_skins,
        stats.ui_skins,
        patched_now
    ))
    return environment
end

local function schedule(inst)
    if inst == nil or type(inst.DoTaskInTime) ~= "function" then
        return
    end
    if scheduled[inst] then
        return
    end
    scheduled[inst] = true
    for _, delay in ipairs(RETRY_DELAYS) do
        inst:DoTaskInTime(delay, patch_dengxian)
    end
end

local function reconstructed_root()
    if TheNet ~= nil and type(TheNet.IsDedicated) == "function" then
        TheNet:IsDedicated()
    end
    AddSimPostInit(patch_dengxian)
    AddPrefabPostInit("world", schedule)
    AddPrefabPostInit("cave", schedule)
end

return reconstructed_root
