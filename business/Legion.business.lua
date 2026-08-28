-- Structured semantic reconstruction of scripts/Legion.lua.
-- This is not the original source and is not a drop-in replacement.
-- Evidence: VM snapshots, instrumented debug APIs, and targeted fixtures.

local LEGION_DISPLAY_NAME = "[DST] Legion"
local BRIDGE_STATE_KEY = "PRISM_TERRA_BRIDGE_LEGION_ENABLED"
-- The scanner's observed recursion guard is approximately six levels deep.
local SCAN_DEPTH_LIMIT = 6
local PRISM_MISSING_MESSAGE = "[SKIN_BRIDGE_PRISM] "
    .. "\229\189\147\229\137\141\230\156\170\229\138\160"
    .. "\232\189\189\230\163\177\233\149\156\239\188\140"
    .. "\232\183\179\232\191\135\229\133\188\229\174\185"
    .. "\229\164\132\231\144\134"
-- UTF-8 meaning: the Prism mod is not loaded, so compatibility is skipped.
local RETRY_DELAYS = { 0, 0.25, 1, 3, 8, 15, 30, 120 }

-- The observed missing-mod path writes a closure state flag before logging.
-- Whether a later success clears this latch was not recovered.
local prism_missing_warning_latched = false
-- Context 150 writes per-instance state before scheduling. Table lifetime and
-- weak-reference behavior cannot be recovered from the executed path.
local scheduled_instances = {}

local function disable_integrity_check()
    return false
end

local function disable_crash_path()
    return false
end

local function enable_skin_path()
    return true
end

local function is_legion_mod(mod_name)
    local mod_info = KnownModIndex:GetModInfo(mod_name)
    return type(mod_info) == "table"
        and mod_info.name == LEGION_DISPLAY_NAME
end

local function patch_legion_environment(
    mod_environment,
    mod_name,
    getupvalue,
    setupvalue
)
    local stats = {
        identity = 0,
        kick = 0,
        skin = 0,
        integrity = 0,
        crash = 0,
        buildgate = 0,
        functions = 0,
        exported_set = 0,
        exported_init = 0,
        exported_reskin = 0,
        indexed_signatures = 0,
        setbuild_descriptors = 0,
    }
    local seen_tables = {}
    local seen_functions = {}

    local scan_value
    local scan_table
    local scan_function

    scan_function = function(fn, depth)
        if depth > SCAN_DEPTH_LIMIT or seen_functions[fn] then
            return
        end
        seen_functions[fn] = true
        stats.functions = stats.functions + 1

        local index = 1
        while true do
            local upvalue_name, upvalue_value = getupvalue(fn, index)
            if upvalue_name == nil then
                break
            end

            if upvalue_name == "CU" then
                setupvalue(fn, index, disable_integrity_check)
                upvalue_value = disable_integrity_check
                stats.integrity = stats.integrity + 1
            elseif upvalue_name == "oU" then
                setupvalue(fn, index, disable_crash_path)
                upvalue_value = disable_crash_path
                stats.crash = stats.crash + 1
            elseif upvalue_name == "cU" then
                setupvalue(fn, index, enable_skin_path)
                upvalue_value = enable_skin_path
                stats.skin = stats.skin + 1
            elseif upvalue_name == "qU" then
                -- The original performs an additional identity-signature walk
                -- over qU's upvalues. Its predicate is not fully recovered.
                -- Generic recursion below preserves the confirmed traversal.
            end

            scan_value(upvalue_value, depth + 1)
            index = index + 1
        end
    end

    scan_table = function(value, depth)
        if depth > SCAN_DEPTH_LIMIT or seen_tables[value] then
            return
        end
        seen_tables[value] = true

        if rawget(value, "wfi7hy0ff_L") == "Kick" then
            rawset(value, "wfi7hy0ff_L", "GetUserID")
            stats.kick = stats.kick + 1
        end

        -- Both signatures are confirmed reads. The SetBuild fixture produced
        -- no mutation and no buildgate increment, so they are retained only as
        -- evidence counters rather than being promoted to patch behavior.
        local indexed_signature = rawget(value, 306)
        local is_setbuild_descriptor =
            rawget(value, "dataname") == "AnimState"
            and rawget(value, "fnname") == "SetBuild"
        if indexed_signature ~= nil then
            stats.indexed_signatures = stats.indexed_signatures + 1
        end
        if is_setbuild_descriptor then
            stats.setbuild_descriptors = stats.setbuild_descriptors + 1
        end

        for _, child in pairs(value) do
            scan_value(child, depth + 1)
        end
    end

    scan_value = function(value, depth)
        local value_type = type(value)
        if value_type == "function" then
            scan_function(value, depth)
        elseif value_type == "table" then
            scan_table(value, depth)
        end
    end

    local exported_set = rawget(mod_environment, "LS_C_Set")
    local exported_init = rawget(mod_environment, "LS_C_Init")
    local exported_reskin = rawget(mod_environment, "LS_C_Reskin")
    if type(exported_set) == "function" then
        stats.exported_set = 1
        scan_function(exported_set, 0)
    end
    if type(exported_init) == "function" then
        stats.exported_init = 1
        scan_function(exported_init, 0)
    end
    if type(exported_reskin) == "function" then
        stats.exported_reskin = 1
        scan_function(exported_reskin, 0)
    end

    scan_value(rawget(mod_environment, "postinitfns"), 0)

    print(string.format(
        "[SKIN_BRIDGE_PRISM] mod=%s identity=%d kick=%d skin=%d "
            .. "integrity=%d crash=%d buildgate=%d functions=%d "
            .. "set=%d init=%d reskin=%d",
        tostring(mod_name),
        stats.identity,
        stats.kick,
        stats.skin,
        stats.integrity,
        stats.crash,
        stats.buildgate,
        stats.functions,
        stats.exported_set,
        stats.exported_init,
        stats.exported_reskin
    ))
end

local function try_apply_prism_bridge()
    local getupvalue = debug and debug.getupvalue
    local setupvalue = debug and debug.setupvalue
    if type(getupvalue) ~= "function" or type(setupvalue) ~= "function" then
        return
    end
    if KnownModIndex == nil or ModManager == nil then
        return
    end

    local loaded_mods = KnownModIndex:GetModsToLoad(true)
    local legion_match_count = 0
    for _, mod_name in pairs(loaded_mods) do
        if is_legion_mod(mod_name) then
            legion_match_count = legion_match_count + 1
            local mod_environment = ModManager:GetMod(mod_name)
            if type(mod_environment) == "table" then
                patch_legion_environment(
                    mod_environment,
                    mod_name,
                    getupvalue,
                    setupvalue
                )
                rawset(_G, BRIDGE_STATE_KEY, true)
            end
        end
    end

    if legion_match_count == 0 then
        if not prism_missing_warning_latched then
            prism_missing_warning_latched = true
            print(PRISM_MISSING_MESSAGE)
        end
        return
    end
end

local function scheduled_retry_callback()
    -- The timer receives a distinct wrapper closure which reaches the check.
    -- Its exact internal return behavior was not recovered.
    try_apply_prism_bridge()
end

local function schedule_prism_bridge_attempts(inst)
    if inst == nil or type(inst.DoTaskInTime) ~= "function" then
        return
    end
    if scheduled_instances[inst] then
        return
    end
    scheduled_instances[inst] = true

    for _, delay in ipairs(RETRY_DELAYS) do
        inst:DoTaskInTime(delay, scheduled_retry_callback)
    end
end

local function on_sim_post_init(inst)
    -- The trace shows this wrapper checking once before shared scheduling.
    try_apply_prism_bridge()
    schedule_prism_bridge_attempts(inst)
end

local function reconstructed_root()
    -- The root chunk performs one immediate compatibility check.
    try_apply_prism_bridge()

    AddSimPostInit(on_sim_post_init)
    AddPrefabPostInit("world", schedule_prism_bridge_attempts)
    AddPrefabPostInit("cave", schedule_prism_bridge_attempts)

    -- The root references AddClassPostConstruct and AddPlayerPostInit, but
    -- their registration branches were not executed, so they are not invented.
end

return reconstructed_root
