-- High-level semantic reconstruction of scripts/Void_Realm.lua.
-- Every mutation below was observed through a loaded-mod fixture.

local TARGET_WORKSHOP_ID = "2526778484"
local RETRY_DELAYS = { 0, 1 }
local RPC_NAMESPACE = "tr_ygsts_skin"
local CUSTOM_SKIN_PATTERN = "^ygsts_.+_skin$"
local PORTRAIT_FALLBACK = "ygsts_luo_none"
local MISSING_MESSAGE = "[SKIN_BRIDGE_TERRA] "
    .. "\229\189\147\229\137\141\230\156\170\229\138\160"
    .. "\232\189\189\232\153\154\231\169\186\229\188\130"
    .. "\231\149\140\239\188\140\232\183\179\232\191\135"
    .. "\229\164\132\231\144\134"

local scheduled = setmetatable({}, { __mode = "k" })
local missing_warning_latched = false
local portrait_wrapper_installed = false
local original_portrait_setter

local function allow_skin_access()
    return true
end

local function skip_target_loader()
    return nil
end

local API_REPLACEMENTS = {
    TrOwnershipCheckFntrzzff = allow_skin_access,
    TrOwnershipIsReady = allow_skin_access,
    TrSkinCheckClientFn = allow_skin_access,
    TrSkinCheckFn = allow_skin_access,
    TrTryLoad = skip_target_loader,
    VR_GateLocal_41 = allow_skin_access,
    VR_GatePeer_73 = allow_skin_access,
    VR_GateReady_58 = allow_skin_access,
    VR_GateServer_26 = allow_skin_access,
}

local function locate_target_environment()
    if KnownModIndex == nil or ModManager == nil then
        return nil
    end
    if type(KnownModIndex.GetModsToLoad) ~= "function"
        or type(KnownModIndex.GetModInfo) ~= "function"
        or type(ModManager.GetMod) ~= "function"
    then
        return nil
    end

    for _, mod_name in pairs(KnownModIndex:GetModsToLoad(true) or {}) do
        if string.find(tostring(mod_name), TARGET_WORKSHOP_ID, 1, true) then
            local mod_info = KnownModIndex:GetModInfo(mod_name)
            if mod_info ~= nil then
                local environment = ModManager:GetMod(mod_name)
                if type(environment) == "table" then
                    return environment
                end
            end
        end
    end
    return nil
end

local function patch_api_table(api)
    if type(api) ~= "table" then
        return 0
    end
    local patched = 0
    for field, replacement in pairs(API_REPLACEMENTS) do
        rawset(api, field, replacement)
        patched = patched + 1
    end
    return patched
end

local function install_portrait_wrapper()
    if portrait_wrapper_installed then
        return false
    end

    local setter = rawget(_G, "SetSkinnedOvalPortraitTexture")
    if type(setter) ~= "function" then
        return false
    end
    original_portrait_setter = setter

    rawset(_G, "SetSkinnedOvalPortraitTexture", function(
        image_widget, character, skin_name
    )
        if type(skin_name) == "string"
            and string.find(skin_name, CUSTOM_SKIN_PATTERN) ~= nil
        then
            local atlas = "bigportraits/" .. PORTRAIT_FALLBACK .. ".xml"
            local texture = PORTRAIT_FALLBACK .. "_oval.tex"
            image_widget:SetTexture(atlas, texture, texture)
            print(
                "[SKIN_BRIDGE_TERRA] portrait_fallback="
                    .. PORTRAIT_FALLBACK
            )
            return true
        end
        return original_portrait_setter(image_widget, character, skin_name)
    end)

    portrait_wrapper_installed = true
    return true
end

local function patch_void_environment()
    local environment = locate_target_environment()
    if environment == nil then
        if not missing_warning_latched then
            missing_warning_latched = true
            print(MISSING_MESSAGE)
        end
        return nil
    end

    patch_api_table(environment)
    patch_api_table(rawget(environment, "TrSkinAPI"))
    install_portrait_wrapper()
    return environment
end

local function apply_skin_rpc(player, _skin_name)
    if type(player) ~= "table" then
        return
    end
    local components = player.components
    if type(components) ~= "table" then
        return
    end
    if type(components.skinner) ~= "table" then
        return
    end
    -- This is a server-side readiness gate. The original callback only checks
    -- that the player exposes a skinner component; it returns no values and
    -- does not apply the visual itself.
    return
end

local function apply_visual_rpc(skin_name, _unused_a, _unused_b)
    if type(skin_name) ~= "string" then
        return
    end
    if string.find(skin_name, CUSTOM_SKIN_PATTERN) == nil then
        return
    end

    local build = string.gsub(skin_name, "_skin$", "")
    local prefab = string.match(build, "^([^_]+)")
    local prefab_skins = rawget(_G, "PREFAB_SKINS")
    if type(prefab_skins) ~= "table"
        or prefab == nil
        or prefab_skins[prefab] == nil
    then
        return
    end

    local player = rawget(_G, "ThePlayer")
    local anim_state = type(player) == "table" and player.AnimState or nil
    if anim_state == nil then
        return
    end

    local applied = false
    if type(anim_state.SetSkin) == "function" then
        anim_state:SetSkin(build, prefab)
        applied = true
    elseif type(anim_state.SetBuild) == "function" then
        anim_state:SetBuild(build)
        applied = true
    end

    print(string.format(
        "[SKIN_BRIDGE_TERRA] visual_apply skin=%s build=%s applied=%d",
        skin_name,
        build,
        applied and 1 or 0
    ))
end

local function register_rpc_handlers()
    if type(AddModRPCHandler) == "function" then
        AddModRPCHandler(RPC_NAMESPACE, "apply", apply_skin_rpc)
    end
    if type(AddClientModRPCHandler) == "function" then
        AddClientModRPCHandler(
            RPC_NAMESPACE,
            "apply_visual",
            apply_visual_rpc
        )
    end
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
        inst:DoTaskInTime(delay, patch_void_environment)
    end
end

local function reconstructed_root()
    patch_void_environment()
    register_rpc_handlers()
    AddGamePostInit(patch_void_environment)
    AddSimPostInit(schedule)
    AddPrefabPostInit("world", schedule)
    AddPrefabPostInit("cave", schedule)
end

return reconstructed_root
