const fs = require('fs');
const { exec } = require('child_process');
const path = require('path');

function execAsync(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) return reject(`Exec error: ${error.message}`);
            if (stderr) return reject(`Stderr: ${stderr}`);
            resolve(stdout);
        });
    });
}

function toForwardSlashes(p) {
    return p.replace(/\\/g, '/');
}

async function obfuscateWithPrometheus(infile, configPath) {
    const quotedConfig = `"${toForwardSlashes(configPath)}"`;
    const quotedInfile = `"${toForwardSlashes(infile)}"`;
    const command = `.\\lua_bin\\lua5.1.exe ./prometheus/cli.lua --config ${quotedConfig} ${quotedInfile}`;
    


    if (!fs.existsSync(infile)) {
        throw new Error("Prometheus input file not found at path: " + infile);
    }

    await execAsync(command);
    return infile.replace(/\.lua$/, '.obfuscated.lua');
}

function toForwardSlashes(p) {
    return p.replace(/\\/g, '/');
}

function randomString(length = 10) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

module.exports = {
    obfuscate: async (original_path, metadata = null) => {
        let loader_tag = "-- obfuscated by bannisters";
        let filepath = original_path;
        fs.copyFileSync(original_path, filepath);

        if (metadata != null) {
            console.log("Script being processed:", metadata);
            const cacheDir = path.join(__dirname, 'protected-script-cache');
            if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });
            const ext = path.extname(original_path);
            const randName = `${randomString(10)}${ext}`;
            filepath = path.join(cacheDir, randName);
            fs.copyFileSync(original_path, filepath);

            const { hwid, unix_expiration: expiration, username, unix_expiration, lifetime, usageCount, last_reset, userId } = metadata;


            const unix_time_in_seconds_now = Math.floor(Date.now() / 1000);


            const checkerCode = `
                _G.AuthDiscordUsername = "${username || "N/A"}"
                _G.AuthDiscordId       = "${userId || "N/A"}"
                _G.AuthDays            = "${lifetime || "N/A"}"
                _G.AuthTimeLeftUnix    = "${parseInt(unix_expiration - unix_time_in_seconds_now) || "N/A"}"
                _G.AuthUsageCount      = "${usageCount || "N/A"}"
                _G.LastHwidResetUnix   = "${last_reset || "N/A"}"

                local execute = true
                local function punish(code) 
                    execute = false
                    local player = game.Players.LocalPlayer
                    if player then
                        player:Kick("[9AUTH] TAMPER DETECTED! CODE: " .. code)
                    end

                    error("[9AUTH LOADER] Execution aborted due to tamper.")
                end

                local unix_time_in_seconds_now = os.time()
                if unix_time_in_seconds_now > ${unix_time_in_seconds_now} + 15 then
                    punish("ERR-101")
                end

                local LogService = game:GetService("LogService")

                local oldsetclipboard = setclipboard
                setclipboard = function(text)
                                if string.find(text, "BANNISTERS") then
                                    punish("ERR-201") 
                                elseif #text > 50 then
                                    punish("ERR-201") 
                                end

                                oldsetclipboard(text)
                            end

                local oldwritefile = writefile
                writefile = function(path, data) 
                                if string.find(data, "BANNISTERS") then
                                    punish("ERR-202") 
                                end

                                oldwritefile(path, data)
                            end

                local oldappendfile = appendfile
                appendfile = function(path, data)
                                if string.find(data, "BANNISTERS") then
                                    punish("ERR-203") 
                                end

                                oldappendfile(path,data)
                end


                local NotificationLibrary = loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()

                local function is_getinfo_tampered()
                    local function dummy()
                        return 123
                    end

                    local info = debug.getinfo(dummy, "nS")

                    if not info then
                        return true
                    end

                    for key, piece in pairs(info) do
                        if (string.find(identifyexecutor(), "SirHurt")) then
                            if key == "what" and piece ~= "Lua" then
                                return true
                            end
                            if key == "numparams" and piece ~= 0 then
                                return true
                            end
                            if key == "name" and piece ~= "dummy" then
                                return true
                            end
                        end

                        if (string.find(identifyexecutor(), "Swift")) then
                            return false
                        end

                        if (string.find(identifyexecutor(), "Solara")) then
                            if key == "source" and not string.find(piece, "@[string") then
                                return true
                            end
                            if key == "short_src" and not string.find(piece, "[string") then
                                return true
                            end
                            if key == "what" and piece ~= "Lua" then
                                return true
                            end
                            if key == "name" and piece ~= "dummy" then
                                return true
                            end
                        end
                    end

                    return false
                end

                local function is_loadstring_tampered()
                    local tampered = false
                    local info = debug.getinfo(loadstring)
                    for key, piece in pairs(info) do
                        if (string.find(identifyexecutor(), "Xeno")) then
                            if key == "what" and piece ~= "Lua" then
                                return true
                            end
                            if key == "short_src" and piece ~= "CorePackages.Packages._Index.UIBlox.UIBlox.App.Text.StyledTextLabel" then
                                return true
                            end
                            if key == "source" and piece ~= "=CorePackages.Packages._Index.UIBlox.UIBlox.App.Text.StyledTextLabel" then
                                return true
                            end
                            if key == "numparams" and piece ~= 2 then
                                return true
                            end
                        end

                        if (string.find(identifyexecutor(), "Solara")) then
                            if key == "what" and piece ~= "Lua" then
                                return true
                            end
                            if key == "short_src" and piece ~= "CoreGui.RobloxGui.Modules.PlayerList.PlayerListManager" then
                                return true
                            end
                            if key == "source" and piece ~= "@CoreGui.RobloxGui.Modules.PlayerList.PlayerListManager" then
                                return true
                            end
                            if key == "numparams" and piece ~= 2 then
                                return true
                            end
                        end

                        if (string.find(identifyexecutor(), "SirHurt")) or (string.find(identifyexecutor(), "Swift")) then
                            if key == "what" and piece ~= "C" then
                                return true
                            end
                            if key == "currentline" and piece ~= -1 then
                                return true
                            end
                            if key == "short_src" and piece ~= "[C]" then
                                return true
                            end
                            if key == "source" and piece ~= "=[C]" then
                                return true
                            end
                            if key == "numparams" and piece ~= 0 then
                                return true
                            end
                        end
                    end
                    return tampered
                end

                local curr_line = debug.getinfo(2, "l").currentline
                if curr_line ~= 2 then
                    punish("ERR-301")
                end

                local lastCheck = 0
                local interval = 1 

                game:GetService("RunService").Heartbeat:Connect(function(dt)
                        lastCheck = lastCheck + dt
                        if lastCheck >= interval then
                            lastCheck = 0

                            
                            if is_getinfo_tampered() then
                                punish("ERR-302 (Executor may not be supported)")
                            end
                            if is_loadstring_tampered() then
                                punish("ERR-303 (Executor may not be supported)")
                            end

                            if isfunctionhooked then
                                if isfunctionhooked(loadstring) then
                                    punish("ERR-305 (Executor may not be supported)")
                                end
                                if isfunctionhooked(print) then
                                    punish("ERR-306 (Executor may not be supported)")
                                end
                                if isfunctionhooked(setclipboard) then
                                    punish("ERR-307 (Executor may not be supported)")
                                end
                            end
                        end
                end)  

                function get_exwid()
                    if syn and syn.gethwid then return syn.gethwid() end
                    if krnl and krnl.gethwid then return krnl.gethwid() end
                    if gethwid then return gethwid() end
                    return "NONE"
                end

                local clientId = (pcall(function() return game:GetService("RbxAnalyticsService"):GetClientId() end)
                    and game:GetService("RbxAnalyticsService"):GetClientId() or "Unavailable")

                local exwidtest = get_exwid() or "NONE"

                if exwidtest ~= "NONE" then
                    if clientId .. "_" .. get_exwid() ~= "${hwid}" then
                        NotificationLibrary:Notify("Error", "[9AUTH] HWID MISMATCH", 5)
                        error("[9AUTH] - KEY EXPIRED")
                    end
                else
                    if clientId ~= "${hwid.split("_")[0]}" then
                        NotificationLibrary:Notify("Error", "[9AUTH] HWID MISMATCH", 5)
                        error("[9AUTH] - KEY EXPIRED")
                    end
                end

                if os.time() > ${expiration} then
                    NotificationLibrary:Notify("Error", "[9AUTH] KEY EXPIRED", 5)
                    error("[9AUTH] - KEY EXPIRED")
                end
            `;

            const originalCode = fs.readFileSync(filepath, 'utf-8');
            const codeWithChecks =
                checkerCode +
                `\nNotificationLibrary:Notify("Success", "[9AUTH] SUCCESSFULLY EXECUTED!", 5)\n` +
                originalCode 

            fs.writeFileSync(filepath, codeWithChecks, 'utf-8');

            loader_tag = "-- obfuscated by bannisters";
        }

        const obfFile = await obfuscateWithPrometheus(filepath, path.join(__dirname, 'config.lua'));

        const obfuscated = fs.readFileSync(obfFile);
        const with_tag = `${loader_tag}\n${obfuscated}`;

        fs.writeFileSync(obfFile, with_tag);
        return obfFile;
    }
};
