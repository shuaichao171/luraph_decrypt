-- High-level semantic reconstruction of scripts/Main.lua.
-- The target table and import decisions are confirmed by loaded-mod probes.

local STATE_KEY = "PRISM_TERRA_SKIN_BRIDGE_ACTIVE"

local TARGETS = {
    prism = {
        id = "1392778117",
        version = "7.6.5",
        enabled = true,
        script = "scripts/Legion.lua",
    },
    voidrealm = {
        id = "2526778484",
        version = "2.2.4",
        enabled = true,
        script = "scripts/Void_Realm.lua",
    },
    dengxian = {
        id = "3235319974",
        version = "19.6",
        enabled = true,
        script = "scripts/Deng_Xian.lua",
    },
    hmr = {
        id = "3609964985",
        version = "1.1.1.3",
        enabled = true,
        script = "scripts/Harvest_Mysterious_Realm.lua",
    },
    niaoniao = {
        id = "3626093627",
        version = "2026-08-23-1",
        enabled = false,
        script = "scripts/Niaoniao_Character.lua",
    },
    xuaner = {
        id = "3014076942",
        version = "6.1.8",
        enabled = true,
        script = "scripts/Xuaner_Myxl.lua",
    },
    shugo = {
        id = "3573399040",
        version = "3.9",
        enabled = true,
        script = "scripts/Shugo_Chara.lua",
    },
    book = {
        id = "3544387985",
        version = "2.4.2",
        enabled = false,
        script = "scripts/Book_of_All_Things.lua",
    },
    ccs = {
        id = "3043439883",
        version = "2.31043",
        enabled = false,
        script = "scripts/Cardcaptor_Sakura.lua",
    },
}

local TARGET_ORDER = {
    "prism",
    "voidrealm",
    "dengxian",
    "hmr",
    "niaoniao",
    "xuaner",
    "shugo",
    "book",
    "ccs",
}

local function detect_loaded_targets()
    local detected = {}
    for _, key in ipairs(TARGET_ORDER) do
        detected[key] = false
    end

    if KnownModIndex == nil
        or type(KnownModIndex.GetModsToLoad) ~= "function"
    then
        return detected
    end

    local get_mod_info = KnownModIndex.GetModInfo
    for _, mod_name in pairs(KnownModIndex:GetModsToLoad(true) or {}) do
        if type(get_mod_info) == "function" then
            local mod_info = KnownModIndex:GetModInfo(mod_name)
            if type(mod_info) == "table" then
                local _ = mod_info.name
            end
        end

        local loaded_name = tostring(mod_name)
        for _, key in ipairs(TARGET_ORDER) do
            local target = TARGETS[key]
            if string.find(loaded_name, target.id, 1, true) ~= nil then
                detected[key] = true
            end
        end
    end
    return detected
end

local function import_enabled_bridges(detected)
    if type(modimport) ~= "function" then
        return
    end
    for _, key in ipairs(TARGET_ORDER) do
        local target = TARGETS[key]
        if target.enabled and detected[key] then
            modimport(target.script)
        end
    end
end

local function reconstructed_root()
    local detected = detect_loaded_targets()
    rawset(_G, STATE_KEY, detected)
    import_enabled_bridges(detected)
end

return reconstructed_root
