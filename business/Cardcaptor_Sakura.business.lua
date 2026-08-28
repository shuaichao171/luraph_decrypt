-- High-level semantic reconstruction of scripts/Cardcaptor_Sakura.lua.

local RETRY_DELAYS = { 0, 1 }
local unpack_results = table.unpack or unpack
local scheduled = setmetatable({}, { __mode = "k" })
local wrappers = setmetatable({}, { __mode = "k" })
local stats = { registration = 0, characters = 0 }

local function pack_results(...)
    return { n = select("#", ...), ... }
end

local function wrap_make_character_skin(api)
    local current = rawget(api, "MakeCharacterSkin")
    local previous = wrappers[api]
    if previous ~= nil and current == previous.wrapper then
        return 0
    end
    if type(current) ~= "function" then
        return 0
    end

    local original = current
    local function wrapper(...)
        local results = pack_results(original(...))
        -- Observable argument and return tables remained untouched. The
        -- wrapper's confirmed behavior is the original call plus exact
        -- multiple-return preservation.
        return unpack_results(results, 1, results.n)
    end

    wrappers[api] = { original = original, wrapper = wrapper }
    rawset(api, "MakeCharacterSkin", wrapper)
    stats.registration = stats.registration + 1
    return 1
end

local function patch_ccs_api()
    local api = rawget(_G, "CCSAPI")
    local patched_now = 0
    if type(api) == "table" then
        patched_now = wrap_make_character_skin(api)
    end

    print(string.format(
        "[SKIN_BRIDGE_CCS] registration=%d characters=%d patched_now=%d",
        stats.registration,
        stats.characters,
        patched_now
    ))
    return api
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
        inst:DoTaskInTime(delay, patch_ccs_api)
    end
end

local function reconstructed_root()
    AddSimPostInit(schedule)
    AddPrefabPostInit("world", schedule)
    AddPrefabPostInit("cave", schedule)
end

return reconstructed_root
