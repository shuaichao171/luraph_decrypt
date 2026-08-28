-- High-level semantic reconstruction of scripts/Harvest_Mysterious_Realm.lua.
-- The API exports, registry writes, and scheduling are dynamically confirmed.

local TARGET_WORKSHOP_ID = "3609964985"
local TARGET_VERSION = "1.1.1.3"
local RETRY_DELAYS = { 0, 0.25, 1, 3, 8 }
local MISSING_MESSAGE =
    "[SKIN_BRIDGE_HMR] target mod not loaded, skipped"

local scheduled = setmetatable({}, { __mode = "k" })
local missing_warning_latched = false

local stats = {
    api = 0,
    skins = 0,
    registries = 0,
    item_skins = 0,
    character_skins = 0,
}

local function target_is_loaded()
    if KnownModIndex == nil
        or type(KnownModIndex.GetModsToLoad) ~= "function"
        or type(KnownModIndex.GetModInfo) ~= "function"
    then
        return false
    end

    for _, mod_name in pairs(KnownModIndex:GetModsToLoad(true) or {}) do
        if string.find(tostring(mod_name), TARGET_WORKSHOP_ID, 1, true) then
            return KnownModIndex:GetModInfo(mod_name) ~= nil
        end
    end
    return false
end

local function owns_skin()
    return true
end

local function get_skin_data_from_net(_, callback)
    if type(callback) == "function" then
        callback(true, {}, nil)
    end
    return nil
end

local function patch_skin_record(record, registry_kind, seen_records)
    if type(record) ~= "table" or seen_records[record] then
        return
    end
    seen_records[record] = true

    rawset(record, "checkfn", owns_skin)
    rawset(record, "checkclientfn", owns_skin)
    rawset(record, "unlock", true)
    rawset(record, "is_restricted", false)

    stats.skins = stats.skins + 1
    if registry_kind == "itemskins" then
        stats.item_skins = stats.item_skins + 1
    else
        stats.character_skins = stats.character_skins + 1
    end
end

local function patch_registry(registry, registry_kind, seen_records)
    if type(registry) ~= "table" then
        return
    end
    stats.registries = stats.registries + 1
    for _, record in pairs(registry) do
        patch_skin_record(record, registry_kind, seen_records)
    end
end

local function scan_inventory_function(fn, seen_records)
    if type(fn) ~= "function"
        or debug == nil
        or type(debug.getupvalue) ~= "function"
    then
        return
    end

    local index = 1
    while true do
        local name, value = debug.getupvalue(fn, index)
        if name == nil then
            break
        end
        if name == "characterskins" or name == "itemskins" then
            patch_registry(value, name, seen_records)
        end
        index = index + 1
    end
end

local function patch_inventory_registries()
    local inventory = rawget(_G, "TheInventory")
    if inventory == nil then
        return
    end

    local seen_records = {}
    scan_inventory_function(inventory.CheckOwnership, seen_records)
    scan_inventory_function(
        inventory.CheckOwnershipGetLatest,
        seen_records
    )
    scan_inventory_function(inventory.CheckClientOwnership, seen_records)
end

local function patch_sync_api()
    local api = rawget(_G, "HMR_SKIN_SYNC_API")
    if type(api) == "table" then
        rawset(api, "CheckOwnership", owns_skin)
        rawset(api, "CheckClientOwnership", owns_skin)
        rawset(api, "HasSkin", owns_skin)
        stats.api = 1
    end

    rawset(_G, "HMRIsSkinOwned", owns_skin)
    rawset(_G, "HMRIsClientSkinOwned", owns_skin)
    rawset(_G, "HMRGetSkinDataFromNet", get_skin_data_from_net)
end

local function patch_hmr_bridge()
    if not target_is_loaded() then
        if not missing_warning_latched then
            missing_warning_latched = true
            print(MISSING_MESSAGE)
        end
        return nil
    end

    stats.api = 0
    stats.skins = 0
    stats.registries = 0
    stats.item_skins = 0
    stats.character_skins = 0

    patch_sync_api()
    patch_inventory_registries()

    print(string.format(
        "[SKIN_BRIDGE_HMR] api=%d skins=%d registries=%d",
        stats.api,
        stats.skins,
        stats.registries
    ))
    return stats
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
        inst:DoTaskInTime(delay, patch_hmr_bridge)
    end
end

local function reconstructed_root()
    patch_hmr_bridge()
    AddSimPostInit(patch_hmr_bridge)
    AddPrefabPostInit("world", schedule)
    AddPrefabPostInit("cave", schedule)
end

return reconstructed_root
