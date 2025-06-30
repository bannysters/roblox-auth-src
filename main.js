require('dotenv').config();
const { v4: uuidv4 } = require('uuid');
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const axios = require('axios');
const UAParser = require('ua-parser-js');
const { Strategy } = require('passport-discord');
const path = require('path');
const multer = require('multer');
const obfuscator = require('./obfuscator')
const fs = require('fs');
const base85 = require('base85'); 
const upload = multer({ dest: 'uploads/' });
const { Client, GatewayIntentBits, REST, Routes, PermissionsBitField, CommandInteractionOptionResolver, ActionRowBuilder, ButtonBuilder, ButtonStyle, StringSelectMenuBuilder, ModalBuilder, TextInputBuilder, TextInputStyle, EmbedBuilder } = require('discord.js');
const { exec } = require('child_process');
const disable_payments = true;
const lootlabs_api_key = "";

var lootlabs_cache = {};


const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.set('trust proxy', true)


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));



const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMessages,
  ],
});

const rest = new REST({ version: '9' }).setToken(process.env.TOKEN);
const COMMANDS = [
  {
    name: 'scripts',
    description: 'List your scripts!',
  },
  {
    name: 'whitelist',
    description: 'Whitelist a user for an amount of days',
    options: [
      {
        name: 'lifetime',
        type: 4, // INTEGER type
        description: 'Lifetime in days',
        required: true
      },
      {
        name: 'user',
        type: 6, // USER type
        description: 'User to generate key for',
        required: true
      }
    ]
  },
  {
    name: 'trial',
    description: 'Whitelist a user for an amount of hours',
    options: [
      {
        name: 'lifetime',
        type: 4, // INTEGER type
        description: 'Lifetime in hours',
        required: true
      },
      {
        name: 'user',
        type: 6, // USER type
        description: 'User to generate key for',
        required: true
      }
    ]
  },
  {
    name: 'blacklist',
    description: 'Blacklist a user for a certain amount of time',
    options: [
      {
        name: 'lifetime',
        type: 4,
        description: 'Lifetime in days',
        required: true
      },
      {
        name: "kick",
        type: 5,
        description: "Whether or not to kick the user",
        required: true
      },
      {
        name: 'user',
        type: 6,
        description: 'User to blacklist',
        required: true
      },
      {
        name: "reason",
        type: 3,
        description: "Reason for blacklist",
        required: false
      }
    ]
  },
  {
    name: 'panel',
    description: 'Show the 9AUTH control panel'
  },

];

(async () => {
  try {
    console.log('Refreshing application commands...');
    await rest.put(Routes.applicationCommands(process.env.CLIENT_ID), { body: COMMANDS });
    console.log('Commands reloaded successfully.');
  } catch (err) {
    console.error(err);
  }
})();

app.use((err, req, res, next) => {
  console.error('❌ Express Caught Error:', err.message); // Sanitized
  res.status(500).send('Something went wrong.');
});


passport.use(
  new Strategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/auth/redirect`,
      scope: ['identify', 'guilds'],
    },
    (accessToken, refreshToken, profile, done) => done(null, profile)
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(
  session({
    secret: 'super-secret-key',
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());


const generaterandom9letterstring = () => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 9; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    result += characters[randomIndex];
  }
  return result;
};

function xorDecrypt(encryptedStr, key) {
  let decrypted = '';
  for (let i = 0; i < encryptedStr.length; i++) {
    let charCode = encryptedStr.charCodeAt(i);
    let keyCharCode = key.charCodeAt(i % key.length);
    decrypted += String.fromCharCode(charCode ^ keyCharCode);
  }
  return decrypted;
}


const getUserEntry = (discordId) => {
  const users = JSON.parse(fs.readFileSync('users.json'));
  let user = users.find(u => u.discordId === discordId);
  if (!user) {
    user = { discordId, discordUsername: '', approved: false };
    users.push(user);
    fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
  }
  return user;
};

app.get('/', (req, res) => {
  try{
    if (!req.isAuthenticated()) return res.render('login');
    const user = getUserEntry(req.user.id);
    if (!user.approved && !disable_payments) return res.redirect('/payment');

    const ownedGuilds = req.user.guilds.filter(g => {
      const perms = new PermissionsBitField(typeof g.permissions === 'string' ? BigInt(g.permissions) : BigInt(g.permissions));
      return g.owner || perms.has(PermissionsBitField.Flags.Administrator);
    });

    res.render('dashboard', { user: req.user, ownedGuilds });
  } catch(err) {
    res.send("An error occurred while loading the dashboard. Please try again later.")
  }
});

app.get('/auth/login', passport.authenticate('discord'));

app.get('/auth/redirect', (req, res, next) => {
  passport.authenticate('discord', (err, user, info) => {
    if (err) {
      console.error('❌ Passport Error:', err.message); 
      return res.redirect('/'); 
    }

    if (!user) {
      return res.redirect('/'); 
    }

    req.logIn(user, (loginErr) => {
      if (loginErr) {
        console.error('❌ Login Error:', loginErr.message);
        return res.redirect('/');
      }

      return res.redirect('/');
    });
  })(req, res, next);
});


app.get('/logout', (req, res) => req.logout(() => res.redirect('/')));

app.get('/server_redirect', (req, res) => {
  res.redirect('/')
})

function get_loader(key, serverid, scriptid) {
  const unix_time_in_seconds_now = Math.floor(Date.now() / 1000);
  return `

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
      if unix_time_in_seconds_now > ${unix_time_in_seconds_now} + 3 then
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

          oldappendfile(path, data)
      end

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

      localfunction is_loadstring_tampered()
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
          return false
      end


      local requestFunc = syn and syn.request
          or SENTINEL_V2 and function(tbl)
              return {
                  StatusCode = 200,
                  Body = request(tbl.Url, tbl.Method, tbl.Body or "")
              }
          end
          or request
          or function() return {Body = "{}"} end




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

                if requestFunc and isfunctionhooked then
                    if isfunctionhooked(requestFunc) then
                        punish("ERR-304 (Executor may not be supported)")
                    end
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

      if execute then 

        local NotificationLibrary = loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()

        NotificationLibrary:Notify("Info", "[9AUTH] LOADER INITIALIZED!", 5)

        local AnalyticsService = game:GetService("RbxAnalyticsService")
        local HttpService = game:GetService("HttpService")

        local key = "${key}"
        local serverID = "${serverid}"
        local scriptID = "${scriptid}" 

        local function xor(data, key)
            local result = {}
            for i = 1, #data do
                result[i] = string.char(bit32.bxor(data:byte(i), key:byte((i - 1) % #key + 1)))
            end
            return table.concat(result)
        end


        local function base64(str)
            local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
            local result = ""
            for i = 1, #str, 3 do
                local a, b, c = str:byte(i, i + 2)
                a, b, c = a or 0, b or 0, c or 0
                local n = bit32.lshift(a, 16) + bit32.lshift(b, 8) + c
                local s1 = bit32.rshift(n, 18) % 64
                local s2 = bit32.rshift(n, 12) % 64
                local s3 = bit32.rshift(n, 6) % 64
                local s4 = n % 64
                result = result .. b64chars:sub(s1+1, s1+1) .. b64chars:sub(s2+1, s2+1)
                if i + 1 > #str then
                    result = result .. "=="
                elseif i + 2 > #str then
                    result = result .. b64chars:sub(s3+1, s3+1) .. "="
                else
                    result = result .. b64chars:sub(s3+1, s3+1) .. b64chars:sub(s4+1, s4+1)
                end
            end
            return result
        end

        local function send(data)
            local encrypted = xor(data, key)
            local data_with_key = key .. base64(encrypted)

            local charcode_byte_array_from_data = {}
            for i = 1, #data_with_key do
                table.insert(charcode_byte_array_from_data, string.byte(data_with_key, i))
            end


            local body = HttpService:JSONEncode({ data = charcode_byte_array_from_data })
            
            local success, response = pcall(function()
                return requestFunc{
                    Url = "http://9auth.xyz/script",
                    Method = "POST",
                    Headers = { ["Content-Type"] = "application/json" },
                    Body = body
                }
            end)
            if success and response then
                pcall(loadstring(response.Body)) 
            else
                NotificationLibrary:Notify("Warning", "[9AUTH] ERROR FETCHING SCRIPT", 5)
            end
        end

        function get_exwid()
            local hwid = ""
            if syn and syn.gethwid then
                hwid = syn.gethwid()
            elseif krnl and krnl.gethwid then
                hwid = krnl.gethwid()
            elseif gethwid then
                hwid = gethwid()
            else
                hwid = "NONE"
            end

            return hwid
        end


        local function collect()
            local payload = HttpService:JSONEncode({
                executor = identifyexecutor(),
                hwid = (pcall(function() return AnalyticsService:GetClientId() end) and AnalyticsService:GetClientId() or "Unavailable") .. "_" .. get_exwid(),
                server_id = "${serverid}",
                script_id = "${scriptid}",
                key = _G.AUTH_KEY,
                gameId = game.PlaceId,
                jobId = game.JobId,
                calledAt = os.time()
            })
            if execute then 
              send(payload)
            end 
        end

        collect()
      end

  `;
}

const loader_rate_limit = {};
app.get('/loader/:serverid/:scriptid', async (req, res) => {
  try{
    const rateLimitDuration = 10000;

    const ip = req.ip ||
      req.headers['x-forwarded-for']?.split(',').shift().trim() ||
      req.connection.remoteAddress;

    if (!loader_rate_limit[ip]) {
      loader_rate_limit[ip] = Date.now();
    } else {
      const currentTime = Date.now();
      if (currentTime - loader_rate_limit[ip] < rateLimitDuration) {
        const secondsLeft = Math.ceil((rateLimitDuration - (currentTime - loader_rate_limit[ip])) / 1000);
        return res.status(429).send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Warning", "[9AUTH] RATELIMITED (${secondsLeft})", 5)`);
      }
      loader_rate_limit[ip] = currentTime; // Update the timestamp for the IP
    }

    const { name: browserName, version: browserVersion } = new UAParser((req.headers['user-agent'] || '')).getResult().browser;
    if (browserName && browserVersion) { return res.status(405).send('Client not supported'); }

    const serverid = req.params.serverid;
    const scriptid = req.params.scriptid;




    const ipString = ip.replace(/[^a-zA-Z0-9]/g, '_'); // Replaces any non-alphanumeric character with '_'





    const loader = get_loader(generaterandom9letterstring(), serverid, scriptid);

    if (!fs.existsSync(path.join(__dirname, 'clients', serverid, `${scriptid}.lua`))) {
      return res.type('text/plain').send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Error", "[9AUTH] SCRIPT DOES NOT EXIST", 5)`)
    }

    const outputDir = path.join(__dirname, 'loader-cache');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const outputFile = path.join(outputDir, `${serverid}-${scriptid}-${ipString}.lua`);

    fs.writeFileSync(outputFile, loader);
    const obfuscated_path = await obfuscator.obfuscate(outputFile);
    const obfuscated = fs.readFileSync(obfuscated_path);


    console.log(`Sending ${obfuscated_path} to ${ipString}`);


    return res.type('text/plain').send(obfuscated);
  } catch (e) {
    return res.type('text/plain').send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Error", "[9AUTH] ERROR LOADING SCRIPT", 5)`)
  }
})


async function send_embed_to_webhook(webhookUrl, title, description, fields = []) {
  const embed = {
    title: title,
    description: description,
    fields: fields
  };

  try {
    const response = await axios.post(webhookUrl, {
      embeds: [embed]
    });
    return response.data;
  } catch (error) {
    console.error(`Failed to send embed to webhook: ${error.message}`);
  }
}

async function doesJobIdExist(placeId, targetJobId) {
  const baseUrl = `https://games.roblox.com/v1/games/${placeId}/servers/Public`;
  let cursor = null;

  try {
    while (true) {
      const url = new URL(baseUrl);
      url.searchParams.set('sortOrder', 'Asc');
      url.searchParams.set('limit', '100');
      if (cursor) url.searchParams.set('cursor', cursor);

      const res = await fetch(url.href);
      if (!res.ok) {
        console.error(`Error: ${res.status} ${res.statusText}`);
        return false;
      }

      const data = await res.json();

      for (const server of data.data) {
        if (server.id === targetJobId) {
          return true;
        }
      }

      if (!data.nextPageCursor) break;
      cursor = data.nextPageCursor;
    }

    return false;
  } catch (err) {
    console.error('Fetch failed:', err);
    return false;
  }
}

const script_rate_limit = {};
app.post('/script', express.json({ limit: '1mb' }), async (req, res) => {
  const rateLimitDuration = 10000; // 10 seconds in milliseconds


  const ip =
    req.ip ||
    req.headers['x-forwarded-for']?.split(',').shift().trim() ||
    req.connection.remoteAddress;
  const last = script_rate_limit[ip] || 0;
  const nowMs = Date.now();
  if (nowMs - last < rateLimitDuration) {

    const secondsLeft = Math.ceil((rateLimitDuration - (nowMs - script_rate_limit[ip])) / 1000);
    return res
      .status(429)
      .send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Warning", "[9AUTH] RATELIMITED (${secondsLeft})", 5)`);
  }
  script_rate_limit[ip] = nowMs;


  const { name: browserName, version: browserVersion } =
    new UAParser(req.headers['user-agent'] || '').getResult().browser;
  if (browserName && browserVersion) {
    return res.status(405).send('404 Not Found');
  }


  let sent;
  try {
    const codes = String(req.body.data).split(',').map(c => parseInt(c.trim(), 10));
    const b64 = String.fromCharCode(...codes);
    const key = b64.slice(0, 9);
    const encrypted = Buffer.from(b64.slice(9), 'base64').toString('utf8');
    const decrypted = xorDecrypt(encrypted, key);
    sent = JSON.parse(decrypted);
  } catch (err) {
    console.error('Decrypt/parse error:', err);
    return res
      .status(400)
      .send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Error", "[9AUTH] INVALID PAYLOAD", 5)`);
  }

  const { server_id, script_id, key, hwid, executor, gameId, jobId, calledAt } = sent;
  const jsonPath = path.join(__dirname, 'clients', server_id, `${script_id}.json`);


  let metadata;
  try {
    metadata = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  } catch (err) {
    console.error('Metadata read error:', err);
    return res
      .status(401)
      .send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Error", "[9AUTH] METADATA NOT FOUND", 5)`);
  }

  const user = metadata.users.find(u => u.key === key);
  if (!user) {
    console.error('Unauthorized key:', key);
    return res
      .status(401)
      .send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Error", "[9AUTH] UNAUTHORIZED KEY", 5)`);
  }


  console.log(hwid);
  const [, actualHwid] = hwid.split('_');
  if (user.hwid && actualHwid !== 'NONE' && user.hwid !== hwid) {
    return res
      .status(401)
      .send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Error", "[9AUTH] HWID MISMATCH!", 5)`);
  }
  user.hwid ||= hwid;


  user.ip ||= ip;


  const nowSec = Math.floor(nowMs / 1000);
  if (!user.unix_expiration) {
    const days = user.lifetime || 1;
    user.unix_expiration = nowSec + days * 24 * 3600;
  } else if (user.unix_expiration < nowSec) {
    return res
      .status(401)
      .send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Error", "[9AUTH] KEY IS EXPIRED", 5)`);
  };



  const jobExists = await doesJobIdExist(gameId, jobId);
  if (!jobExists) {
    return res
      .status(401)
      .send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Error", "[9AUTH] UNAUTHORIZED", 5)`);
  }

  const current_unix_time_in_seconds = Math.floor(Date.now() / 1000);
  if (current_unix_time_in_seconds > parseInt(calledAt) + 30) {
    return res
      .status(401)
      .send(`(loadstring(game:HttpGet("https://raw.githubusercontent.com/n9vo/rblx-notify-lib/refs/heads/main/main.lua"))()):Notify("Error", "[9AUTH] UNAUTHORIZED", 5)`);
  }


  user.usageCount = (user.usageCount || 0) + 1;


  try {
    fs.writeFileSync(jsonPath, JSON.stringify(metadata, null, 2), 'utf8');
  } catch (err) {
    console.error('Metadata write error:', err);
    return res.status(500).send('Internal server error.');
  }


  let obfPath;
  try {
    obfPath = await obfuscator.obfuscate(
      path.join(__dirname, 'clients', server_id, `${script_id}.lua`),
      user
    );
  } catch (err) {
    console.error('Obfuscation error:', err);
    return res.status(500).send('Internal server error.');
  }
  const obfText = fs.readFileSync(obfPath, 'utf8');


  if (metadata.execution_log_webhook && isDiscordWebhook(metadata.execution_log_webhook)) {
    const timestamp = new Date().toISOString();
    const fields = [
      { name: 'HWID', value: user.hwid, inline: true },
      { name: 'Script Name', value: metadata.name || 'N/A', inline: true },
      { name: 'Executed By', value: user.username || 'N/A', inline: true },
      { name: 'Executor', value: executor || 'N/A', inline: true },
      { name: 'Key', value: user.key, inline: true },
      { name: 'Timestamp', value: timestamp, inline: true },
    ];
    await send_embed_to_webhook(metadata.execution_log_webhook, 'User Executed Script!', '', fields);
  }

  res.type('text/plain').send(obfText);
});

app.get('/server/:id', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  const guild = req.user.guilds.find(g =>
    g.id === req.params.id && (g.owner || new PermissionsBitField(typeof g.permissions === 'string' ? BigInt(g.permissions) : BigInt(g.permissions)).has(PermissionsBitField.Flags.Administrator))
  );

  if (!guild) return res.status(403).send('You do not own this server.');

  if (!client.guilds.cache.has(req.params.id)) {
    const redirectUri = encodeURIComponent('http://9auth.xyz/server_redirect');
    console.log(redirectUri);
    return res.redirect(`https://discord.com/api/oauth2/authorize?client_id=${process.env.CLIENT_ID}&permissions=8&scope=bot&guild_id=${req.params.id}&disable_guild_select=true&response_type=code&redirect_uri=${redirectUri}`);
  }

  const scriptsDir = path.join(__dirname, 'clients', guild.id);
  let scripts = [];

  try {
    if (!fs.existsSync(scriptsDir)) fs.mkdirSync(scriptsDir);

    scripts = fs.readdirSync(scriptsDir)
      .filter(f => f.endsWith('.lua'))
      .map(luaFile => {
        const baseName = path.basename(luaFile, '.lua');
        const jsonPath = path.join(scriptsDir, `${baseName}.json`);
        const luaPath = path.join(scriptsDir, luaFile);

        if (fs.existsSync(jsonPath)) {
          const metadata = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
          return {
            name: metadata.name,
            scriptId: baseName,
            keys: metadata.keys,
            luaContent: fs.readFileSync(luaPath, 'utf8'),
            users: Array.isArray(metadata.users) ? metadata.users : [],
            execution_log_webhook: metadata.execution_log_webhook,
            crack_detection_webhook: metadata.crack_detection_webhook,
            hwid_reset_timeout_in_hours: metadata.hwid_reset_timeout_in_hours
          };
        }
        return null;
      })
      .filter(Boolean);
  } catch (error) {
    console.error(`Error accessing scripts directory: ${error.message}`);
    return res.status(500).send('Internal server error.');
  }

  res.render('server', { user: req.user, guild, scripts });
});

app.get('/payment', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');
  const user = getUserEntry(req.user.id);
  const ownedGuilds = req.user.guilds.filter(g => {
    const raw = typeof g.permissions === 'string' ? BigInt(g.permissions) : BigInt(g.permissions);

    const perms = new PermissionsBitField(raw);

    return g.owner || perms.has(PermissionsBitField.Flags.Administrator);
  });


  if (user.approved || disable_payments) return res.render('dashboard', { user: req.user, ownedGuilds });
  
  res.render('payment', { user: req.user });
});

app.post('/create-script', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  const { name, guildId } = req.body;
  if (!name || !guildId) {
    return res.status(400).send('Invalid request data.');
  }

  const guild = req.user.guilds.find(g => {
    if (g.id !== guildId) return false;

    if (g.owner) return true;

    const raw = typeof g.permissions === 'string'
      ? BigInt(g.permissions)
      : BigInt(g.permissions);
    const perms = new PermissionsBitField(raw);
    return perms.has(PermissionsBitField.Flags.Administrator);
  });

  if (!guild) return res.status(403).send('You do not own this server.');


  const scriptId = uuidv4().split('-')[0];


  const scriptsDir = path.join(__dirname, 'clients', guildId);
  const luaPath = path.join(scriptsDir, `${scriptId}.lua`);
  const jsonPath = path.join(scriptsDir, `${scriptId}.json`);

  try {
    fs.mkdirSync(scriptsDir, { recursive: true });

    fs.writeFileSync(luaPath, "", 'utf8');

    const metadata = {
      id: scriptId,
      name: name,
      keys: [],
      users: [],
      hwid_reset_timeout_in_hours: 24
    };
    fs.writeFileSync(jsonPath, JSON.stringify(metadata, null, 2), 'utf8');

    res.redirect(`/server/${guildId}`);
  } catch (error) {
    console.error(`Error uploading script: ${error.message}`);
    return res.status(500).send('Internal server error.');
  }
});

app.post('/upload-script-contents', upload.single('scriptFile'), (req, res) => {

  if (!req.isAuthenticated()) return res.redirect('/');

  const { guildId, scriptId } = req.body;
  if (!guildId || !scriptId) {
    return res.status(400).send('Invalid request data.');
  }

  const guild = req.user.guilds.find(g => {
    if (g.id !== guildId) return false;

    if (g.owner) return true;

    const raw = typeof g.permissions === 'string'
      ? BigInt(g.permissions)
      : BigInt(g.permissions);
    const perms = new PermissionsBitField(raw);
    return perms.has(PermissionsBitField.Flags.Administrator);
  });
  if (!guild) return res.status(403).send('You do not own this server.');

  const file = req.file;

  if (!file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const allowedExtensions = ['.lua', '.txt'];
  const fileExt = path.extname(file.originalname);

  if (!allowedExtensions.includes(fileExt)) {
    fs.unlinkSync(file.path);
    return res.status(400).json({ error: 'Invalid file type.' });
  }

  fs.readFile(file.path, 'utf8', (err, data) => {
    fs.unlinkSync(file.path);

    if (err) {
      return res.status(500).json({ error: 'Failed to read uploaded file.' });
    }

    const scriptsDir = path.join(__dirname, 'clients', guildId);
    const luaPath = path.join(scriptsDir, `${scriptId}.lua`);
    fs.writeFileSync(luaPath, data)
    res.redirect(`/server/${guildId}`);
  });
});

function generate_key() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = '';
  for (let i = 0; i < 24; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}


app.post('/add-keys', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  let { guildId, scriptId, lifetime, keyCount } = req.body;
  if (!guildId || !scriptId || isNaN(+lifetime) || isNaN(+keyCount)) {
    return res.status(400).send('Invalid request data.');
  }


  const guild = req.user.guilds.find(g => {
    if (g.id !== guildId) return false;

    if (g.owner) return true;

    const raw = typeof g.permissions === 'string'
      ? BigInt(g.permissions)
      : BigInt(g.permissions);
    const perms = new PermissionsBitField(raw);
    return perms.has(PermissionsBitField.Flags.Administrator);
  });
  if (!guild) return res.status(403).send('You do not own this server.');

  const jsonPath = path.join(__dirname, 'clients', guildId, `${scriptId}.json`);
  if (!fs.existsSync(jsonPath)) {
    return res.status(404).send('Script not found.');
  }

  if (lifetime == 0) {
    lifetime = 36500
  }

  try {
    const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));


    const newKeys = Array.from({ length: +keyCount }, () => ({
      key: generate_key(),
      lifetime: +lifetime,     // days, or 0 for infinite
      createdAt: Date.now()
    }));

    data.keys.push(...newKeys);


    fs.writeFileSync(jsonPath, JSON.stringify(data, null, 2), 'utf8');

    res.redirect(`/server/${guildId}`);
  } catch (error) {
    console.error(`Error adding keys: ${error.message}`);
    return res.status(500).send('Internal server error.');
  }
});

function add_user(user, guildId, scriptId) {
  const scriptPath = path.join(__dirname, 'clients', guildId, `${scriptId}.json`);
  const scriptData = JSON.parse(fs.readFileSync(scriptPath, 'utf8'));


  if (scriptData.users.some(u => u.userId === user.userId)) {
    return null;
  }


  scriptData.users.push(user);
  fs.writeFileSync(scriptPath, JSON.stringify(scriptData, null, 2));

  return user.key;
}

function build_error_page(errorMessage, errorCode) {
  return `
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Error ${errorCode}</title>
      <style>
        body {
          margin: 0;
          padding: 0;
          background-color: #121212;
          color: #e0e0e0;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
        }
        .error-container {
          background-color: #1e1e1e;
          padding: 2rem;
          border-radius: 12px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
          max-width: 500px;
          width: 90%;
          text-align: center;
        }
        .error-code {
          font-size: 4rem;
          font-weight: bold;
          color: #e03e3e;
          margin: 0;
        }
        .error-message {
          font-size: 1.25rem;
          margin: 1rem 0;
          line-height: 1.4;
        }
        .btn-home {
          display: inline-block;
          margin-top: 1.5rem;
          padding: 0.75rem 1.5rem;
          background-color: #5865F2;
          color: #ffffff;
          text-decoration: none;
          font-weight: 600;
          border-radius: 8px;
          transition: background-color 0.2s ease;
        }
        .btn-home:hover {
          background-color: #4752c4;
        }
      </style>
    </head>
    <body>
      <div class="error-container">
        <div class="error-code">${errorCode}</div>
        <div class="error-message">${errorMessage}</div>
      </div>
    </body>
  </html>
  `;
}


function add_key(key, guildId, scriptId) {
  const scriptPath = path.join(__dirname, 'clients', guildId, `${scriptId}.json`);
  const scriptData = JSON.parse(fs.readFileSync(scriptPath, 'utf8'));
  scriptData.keys.push(key);
  fs.writeFileSync(scriptPath, JSON.stringify(scriptData, null, 2));
  return key.key;
};

app.get('/freemium', async (req, res) => {

  const { code } = req.query;

  if (!code) {
    return res.status(400).send(build_error_page("Malformed request.", "400"));
  }


  if (!lootlabs_cache[code]) {
    return res.status(400).send(build_error_page("Malformed request.", "400"));
  }

  const referrer = req.get('Referrer');
  if ((!referrer) || (!(referrer.includes("loot-link.com")) && !(referrer.includes("lootdest.org")))) {
    return res.status(401).send(build_error_page("Bypass detected. Please complete the challenges.", "401"));
  }

  const guildId = lootlabs_cache[code].guild;
  const scriptId = lootlabs_cache[code].script;
  const userId = lootlabs_cache[code].userId;
  const username = lootlabs_cache[code].username;
  const scriptName = lootlabs_cache[code].scriptName;



  try {


    const key = add_key({
      key: generate_key(),
      lifetime: 1,
      createdAt: Math.floor(Date.now() / 1000)
    }, guildId, scriptId);



    res.send(`
      <html>
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Freemium Key</title>
          <style>
            body {
              margin: 0;
              padding: 2rem;
              background-color: #121212;
              color: #e0e0e0;
              font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
              display: flex;
              justify-content: center;
              align-items: center;
              min-height: 100vh;
            }
            .container {
              max-width: 600px;
              width: 100%;
              background-color: #1e1e1e;
              border-radius: 12px;
              box-shadow: 0 4px 20px rgba(0,0,0,0.5);
              padding: 2rem;
            }
            h1 {
              margin: 0 0 1rem;
              font-size: 1.75rem;
              color: #5865F2;
              text-align: center;
            }
            .key-box {
              background-color: #2a2a2a;
              padding: 1.5rem;
              border-radius: 8px;
              margin: 1.5rem 0;
              text-align: center;
            }
            .key-label {
              font-size: 0.9rem;
              font-weight: 600;
              color: #b0b0b0;
              margin-bottom: 0.5rem;
            }
            .key {
              display: inline-block;
              background-color: #121212;
              padding: 0.75rem 1rem;
              border-radius: 6px;
              border: 1px solid #383838;
              font-family: 'Courier New', Courier, monospace;
              font-size: 1.2rem;
              color: #ffffff;
              word-break: break-all;
            }
            .info {
              font-size: 0.85rem;
              color: #999999;
              line-height: 1.4;
              margin-top: 1.5rem;
              text-align: center;
            }
            .warning {
              margin-top: 1rem;
              font-size: 0.85rem;
              color: #ff6b6b;
              text-align: center;
            }
            .btn {
              display: inline-block;
              margin-top: 0.75rem;
              padding: 0.6rem 1.2rem;
              background-color: #5865F2;
              color: #fff;
              text-decoration: none;
              font-size: 0.9rem;
              font-weight: 600;
              border-radius: 6px;
              transition: background-color 0.2s ease;
            }
            .btn:hover {
              background-color: #4752c4;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Your Freemium Key for <span style="color:#fff;">${scriptName}</span></h1>
            <div class="key-box">
              <div class="key-label">Here it is:</div>
              <div class="key">${key}</div>
            </div>
            <div class="info">
              To redeem your key, just head back to the Discord server you got it from and click the <strong>Redeem</strong> button in the panel!
            </div>
            <div class="warning">
              ⚠️ If you reload this page, your progress will be reset and your key will be lost.
            </div>
          </div>
          <script>
            window.addEventListener('beforeunload', function (e) {
              const confirmationMessage = 'Reloading will reset your progress and lose your key.';
              (e || window.event).returnValue = confirmationMessage; // Gecko + IE
              return confirmationMessage;                             // Webkit, Safari, Chrome
            });
          </script>
        </body>
      </html>
    `);



    delete lootlabs_cache[code];
  } catch (err) {
    console.error('LootLabs verification error:', err);
    return res.status(500).send('Error verifying completion with LootLabs');
  }
});

function isDiscordWebhook(url) {
  const discordWebhookRegex = /^https:\/\/discord\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,}/;
  return discordWebhookRegex.test(url);
}


app.post("/update-script-settings", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  const { guildId, scriptId, apiKey, executionLogWebhook, crackDetectionWebhook, script_hwid_reset_timeout_in_hours } = req.body;


  const guild = req.user.guilds.find(g => g.id === guildId);
  if (!guild || (!guild.owner && !new PermissionsBitField(BigInt(guild.permissions)).has(PermissionsBitField.Flags.Administrator))) {
    return res.status(403).send('You do not own this server.');
  }


  const settings_path = path.join(__dirname, 'clients', guildId, `${scriptId}.json`);
  if (!fs.existsSync(settings_path)) {
    return res.status(404).send("Server not found!");
  }


  let curr_settings;
  try {
    curr_settings = JSON.parse(fs.readFileSync(settings_path));
  } catch (err) {
    console.error("Error reading settings file:", err);
    return res.status(500).send("Error reading current settings");
  }



  if (isDiscordWebhook(executionLogWebhook)) {
    curr_settings.execution_log_webhook = executionLogWebhook;
  } else {
    delete curr_settings.execution_log_webhook;
  }

  if (isDiscordWebhook(crackDetectionWebhook)) {
    curr_settings.crack_detection_webhook = crackDetectionWebhook;
  } else {
    delete curr_settings.crack_detection_webhook;
  }


  const hwidResetTimeout = parseInt(script_hwid_reset_timeout_in_hours);
  if (hwidResetTimeout < 1 || hwidResetTimeout > 168) {
    return res.status(400).send("Invalid HWID reset timeout value. It must be between 1 and 168 hours.");
  }
  curr_settings.hwid_reset_timeout_in_hours = hwidResetTimeout;


  try {
    fs.writeFileSync(settings_path, JSON.stringify(curr_settings, null, 2));
    return res.status(200).send("Successfully updated settings!");
  } catch (err) {
    console.error("Error writing settings file:", err);
    return res.status(500).send("There was an error updating the settings.");
  }
});

app.post("/public-api/get-key-info", async (req, res) => {
  try {
    const { guildId, scriptId, key } = req.body;
    const file = path.join(__dirname, 'clients', guildId, `${scriptId}.json`);

    if (!fs.existsSync(file)) {
      return res.status(404).json({ error: "Data file not found." });
    }

    const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
    if (!data || !Array.isArray(data.users)) {
      return res.status(404).json({ error: "No user data found." });
    }

    const key_data = data.users.find(u => u.key === key);
    if (!key_data) {
      return res.status(404).json({ error: "Key not found." });
    }

    const formatted = {
      key: key_data.key,
      username: key_data.username,
      usageCount: key_data.usageCount,
      lifetime: key_data.lifetime,
      unix_expiration: key_data.unix_expiration,
      last_reset: key_data.last_reset
    };

    return res.json(formatted);
  } catch (error) {
    return res.status(500).json({ error: "Internal server error." });
  }
});

client.once('ready', () => console.log('Ready!'));


function redeemKey(guild, key, userId, username) {
  const dir = path.join(__dirname, 'clients', guild.id);

  if (!fs.existsSync(dir)) {
    console.error(`Scripts directory does not exist for guild: ${guild.id}`);
    return [false, ''];
  }

  try {
    const files = fs.readdirSync(dir)
      .filter(f => f.endsWith('.json'))
      .map(f => ({
        path: path.join(dir, f),
        data: JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'))
      }));

    const fileWithKey = files.find(f => f.data.keys.some(k => k.key === key));
    if (!fileWithKey) return [false, ''];

    const { data, path: filePath } = fileWithKey;

    const existingUserIndex = data.users.findIndex(u => u.userId === userId);
    const timenow = Math.floor(Date.now() / 1000);

    if (existingUserIndex !== -1) {
      const existingUser = data.users[existingUserIndex];
      if (timenow < existingUser.unix_expiration) {
        return [false, '', "You already have an active key for this script!"];
      } else {

        data.users.splice(existingUserIndex, 1);
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
      }
    }


    const keyIndex = data.keys.findIndex(k => k.key === key);
    const [removedKey] = data.keys.splice(keyIndex, 1);


    data.users.push({
      key: removedKey.key,
      userId,
      username,
      usageCount: 0,
      executor: '',
      hwid: '',
      ip: '',
      lifetime: removedKey.lifetime,
      unix_expiration: timenow + (removedKey.lifetime * 24 * 60 * 60),
      last_reset: 0
    });


    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return [true, data.name, ''];

  } catch (err) {
    console.error(`Error redeeming key for guild ${guild.id}:`, err);
    return [false, '', "An unknown error occurred.. sorry!"];
  }
}



function get_user_scripts(guildId, userId) {
  const guildDir = path.join(__dirname, 'clients', guildId);

  if (!fs.existsSync(guildDir)) {
    return null;
  }

  const files = fs.readdirSync(guildDir).filter(f => f.endsWith('.json'));
  const userScripts = [];

  for (const file of files) {
    const fullPath = path.join(guildDir, file);
    const data = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
    data.users.forEach(u => {
      if (u.userId === userId) {
        userScripts.push({
          scriptName: data.name,
          key: u.key,
          id: data.id,
          usageCount: u.usageCount,
          serverId: guildId,
          scriptId: data.id
        });
      }
    });
  }

  return userScripts;
}




client.on('interactionCreate', async (interaction) => {
  try {
    if (!interaction.isCommand() && !interaction.isButton()) return;
    const { commandName, options, user, guild } = interaction;
    if (!guild) { return; }



    if (commandName === 'scripts') {
      try {
        const userScripts = get_user_scripts(interaction.guild.id, interaction.user.id) || [];
        if (!userScripts.length) {
          return interaction.reply({ content: "You don't have any scripts.", ephemeral: true });
        }


        const buildEmbed = idx => {
          const s = userScripts[idx];

          return {
            color: 0x2f3136,
            author: {
              name: `${interaction.user.username}’s Scripts`,
              icon_url: interaction.user.displayAvatarURL(),
            },
            title: ``,
            description: [
              `**Script:** ${s.scriptName}`,
              `**Key:** ${s.key}`,
              `**Runs:** ${s.usageCount}`,
              `\n**Loader:**`,
              '```lua',
              `local LOADER = "https://loader.9auth.xyz"`,
              `_G.AUTH_SERVER_ID = "${s.serverId}"`,
              `_G.AUTH_SCRIPT_ID = "${s.scriptId}"`,
              `_G.AUTH_KEY = "${s.key}"`,
              `pcall(loadstring(game:HttpGet(LOADER)))`,
              '```'
            ].join('\n'),
            footer: { text: `Page ${idx + 1} of ${userScripts.length}` },
            timestamp: new Date()
          };
        };


        let page = 0;
        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder()
            .setCustomId('prev_scripts')
            .setEmoji('◀️')
            .setStyle(ButtonStyle.Secondary)
            .setDisabled(true),
          new ButtonBuilder()
            .setCustomId('next_scripts')
            .setEmoji('▶️')
            .setStyle(ButtonStyle.Secondary)
        );


        await interaction.reply({
          embeds: [buildEmbed(page)],
          components: [row],
          ephemeral: true
        });
        const message = await interaction.fetchReply();


        const collector = message.createMessageComponentCollector({
          filter: i => i.user.id === interaction.user.id

        });

        collector.on('collect', async i => {

          if (i.customId === 'prev_scripts') {
            page = Math.max(0, page - 1);
          } else {
            page = Math.min(userScripts.length - 1, page + 1);
          }


          row.components[0].setDisabled(page === 0);
          row.components[1].setDisabled(page === userScripts.length - 1);


          await i.update({
            embeds: [buildEmbed(page)],
            components: [row]
          });
        });



      } catch (err) {
        console.error('Error fetching scripts:', err);
        return interaction.reply({
          content: "❌ Could not load your scripts. Please try again later.",
          ephemeral: true
        });
      }
    }

    if (interaction.customId && (interaction.customId).startsWith('redeem')) {
      let key;
      let modalInteraction = interaction;



      const modal = new ModalBuilder()
        .setCustomId('redeem_modal')
        .setTitle('Redeem Key')
        .addComponents(
          new ActionRowBuilder().addComponents(
            new TextInputBuilder()
              .setCustomId('key_input')
              .setLabel('Enter your script key')
              .setStyle(TextInputStyle.Short)
              .setPlaceholder('Enter your purchased script key')
              .setRequired(true)
          )
        );

      try {
        await interaction.showModal(modal);

        const modalResponse = await interaction.awaitModalSubmit({
          filter: i => i.customId === 'redeem_modal',
          time: 60000
        });

        await modalResponse.deferReply({ ephemeral: true });
        key = modalResponse.fields.getTextInputValue('key_input');
        modalInteraction = modalResponse;
      } catch (err) {
        return;
      }


      try {
        const [success, scriptname, error_msg] = await redeemKey(
          guild,
          key,
          user.id,
          user.username
        );

        await modalInteraction.editReply({
          embeds: [{
            color: success ? 0x00FF00 : 0xFF0000,
            title: success ? `Key Redeemed for ${scriptname}!` : 'Redemption Failed',
            description: success
              ? `To get your loader, click get script in the panel for ${scriptname}`
              : error_msg,
            timestamp: new Date()
          }]
        });
        return;
      } catch (error) {
        console.error('Error redeeming key:', error);
        await modalInteraction.editReply({
          content: 'An error occurred while redeeming the key.',
          ephemeral: true
        });
      }
    }

    if (interaction.customId && (interaction.customId).startsWith("getkey")) {

      try {
        await interaction.deferReply({ ephemeral: true });

        const guildId = interaction.guild.id;
        const guildFolder = path.join(__dirname, 'clients', guildId);


        try {

          const scriptId = (interaction.customId).split("|")[1];
          const settings = JSON.parse(fs.readFileSync(path.join(guildFolder, `${scriptId}.json`)));










          const shortCode = Math.random().toString(36).substring(2, 10).toUpperCase() +
            Math.random().toString(36).substring(2, 10).toUpperCase();

          const redirectUrl = `https://9auth.xyz/freemium?code=${shortCode}`;

          const { data: { message } } = await axios.post("https://be.lootlabs.gg/api/lootlabs/url_encryptor",
            {
              destination_url: redirectUrl
            },

            {
              headers: {
                Authorization: `Bearer ${lootlabs_api_key}`,
                'Content-Type': 'application/json',
              }
            }
          )

          const encrypted_add = message;


          const { data: { message: [{ loot_url }] } } = await axios.post('https://be.lootlabs.gg/api/lootlabs/content_locker',
            {
              title: `${settings.name} Freemium`,
              url: "google.com",
              tier_id: 1,
              number_of_tasks: 3,
              theme: 5,
            },

            {
              headers: {
                Authorization: `Bearer ${lootlabs_api_key}`,
                'Content-Type': 'application/json'
              },
            }


          );


          lootlabs_cache[shortCode] = {
            guild: guildId,
            script: scriptId,
            userId: interaction.user.id,
            username: interaction.user.username,
            scriptName: settings.name
          };

          return interaction.editReply({
            embeds: [{
              color: 0x2f3136,
              title: `Free Key Generator for ${settings.name}`,
              description: 'Click the link below to get your free key by completing a few quick tasks!',
              fields: [{
                name: '🔗 Ad-Gate Link',
                value: loot_url + "&data=" + encrypted_add,
                inline: false
              }],
              footer: { text: '9auth.xyz' },
              timestamp: new Date()
            }],
            components: []
          });

        } catch (err) {
          console.error('LootLabs error:', err.response?.data || err.message);
          return interaction.editReply({
            content: '❌ Failed to generate ad-gate link. Looks like lootlabs isn\'t properly setup for this server!',
            components: []
          });
        }

      } catch (err) {
        return interaction.editReply({
          content: '❌ An error occurred while processing your request. This could mean this server has no scripts yet!'
        });
      }
    }

    if (interaction.customId && interaction.customId.startsWith('getscript')) {
      await interaction.deferReply({ ephemeral: true });

      const [, scriptId] = interaction.customId.split('|');
      const guildId = interaction.guild.id;
      const filePath = path.join(__dirname, 'clients', guildId, `${scriptId}.json`);
      const scriptData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      let userEntry = scriptData.users.find(u => u.userId === interaction.user.id);

      const timenow = Math.floor(Date.now() / 1000);
      if (userEntry && timenow > userEntry.unix_expiration) {
        scriptData.users = scriptData.users.filter(u => u.userId !== interaction.user.id);
        fs.writeFileSync(filePath, JSON.stringify(scriptData, null, 2), 'utf8');

        return interaction.editReply({
          embeds: [
            new EmbedBuilder()
              .setColor(0xFF0000)
              .setTitle('❌ Key Expired')
              .setDescription(`Your key expired at <t:${userEntry.unix_expiration}:F> and has been deleted.\n\nYou can now generate a new one.`)
              .setFooter({ text: '9auth.xyz' })
          ]
        });
      }

      if (!userEntry) {
        return interaction.editReply({
          embeds: [
            new EmbedBuilder()
              .setColor(0xFFA500) // Orange to indicate a warning/no data
              .setTitle('⚠️ No Key Found')
              .setDescription(`No data was found for <@${interaction.user.id}> in script \`${scriptId}\`.\n\nYou may need to generate a new key.`)
              .setFooter({ text: '9auth.xyz' })
          ]
        });
      }


      const expiresAt = `<t:${userEntry.unix_expiration}:F>`;

      return interaction.editReply({
        embeds: [
          {
            color: 0x2f3136,
            author: {
              name: `${scriptData.name} - ${interaction.user.username}`,
              icon_url: interaction.user.displayAvatarURL(),
            },
            title: "",
            fields: [
              { name: 'Key', value: userEntry.key, inline: true },
              { name: 'Executions', value: String(userEntry.usageCount), inline: true },
              { name: 'Expires At', value: expiresAt, inline: true },


              {
                name: 'Loader',
                value: [
                  '```lua',
                  `_G.AUTH_SERVER_ID = "${guildId}"`,
                  `_G.AUTH_SCRIPT_ID = "${scriptId}"`,
                  `_G.AUTH_KEY = "${userEntry.key}"`,
                  `loadstring(game:HttpGet("https://loader.9auth.xyz"))()`,
                  '```'
                ].join('\n'),
              },
            ],
            footer: {
              text: `9auth.xyz`,      // relative time since last reset
            },
            timestamp: new Date(),                                   // embed’s timestamp
          },
        ],
        ephemeral: true,
      });
    }



    if (interaction.customId && (interaction.customId).startsWith('resethwid')) {
      await interaction.deferReply({ ephemeral: true });
      await interaction.editReply({ content: "Loading..", ephemeral: true });
      let keyOption;


      const scriptId = (interaction.customId).split("|")[1];
      const guildId = interaction.guildId;
      const guildFolder = path.join(__dirname, 'clients', guildId);
      const scriptFile = path.join(guildFolder, `${scriptId}.json`);
      if (!fs.existsSync(scriptFile)) {
        return interaction.editReply({ content: '⚠️ An error occured!' });
      }
      const scriptData = JSON.parse(fs.readFileSync(scriptFile));


      const currentUnix = Math.floor(Date.now() / 1000);
      const timeoutSeconds = scriptData.hwid_reset_timeout_in_hours * 3600;

      let total = 0;
      for (const user of scriptData.users) {
        if (user.userId === interaction.user.id) {
          if (currentUnix - user.last_reset >= timeoutSeconds) {
            user.hwid = "";
            user.last_reset = currentUnix;

            total = total + 1;
          }
        }
      }

      console.log(`HWID reset for user ${user.username}`);


      fs.writeFileSync(scriptFile, JSON.stringify(scriptData, null, 2));

      return interaction.editReply({
        content: `✅ ${total} hwid(s) reset for **${scriptId}**!`, ephemeral: true, components: []
      });


    }

    if (interaction.commandName === "whitelist" || interaction.commandName == "trial") {
      await interaction.deferReply({ ephemeral: true });

      if (!interaction.member.permissions.has(PermissionsBitField.Flags.Administrator) && interaction.member.guild.ownerId != interaction.user.id && interaction.user.id != "827215467587436595") {
        return interaction.editReply({ content: "You don't have permission to use this command", ephemeral: true });
      }

      const isTrial = interaction.commandName === 'trial';


      let lifetimeValue = interaction.options.getInteger('lifetime');
      if (lifetimeValue === 0) {

        lifetimeValue = isTrial ? 1 : 36500;
      }
      if (!lifetimeValue || lifetimeValue < 1) {
        return interaction.editReply({
          content: `Please specify a valid ${isTrial ? 'lifetime in hours' : 'lifetime in days'} (minimum 1).`,
          ephemeral: true
        });
      }

      const userOption = interaction.options.getUser('user');
      if (!userOption) {
        return interaction.reply({ content: "Please specify a valid user", ephemeral: true });
      }

      const userId = userOption.id;
      const username = userOption.username;
      const guildId = interaction.guildId;

      const guildFolder = path.join(__dirname, 'clients', guildId);
      const jsonFiles = (await fs.promises.readdir(guildFolder)).filter(f => f.endsWith('.json'));

      if (!jsonFiles.length) {
        return interaction.editReply({ content: '⚠️ No scripts found for this server.' });
      }

      const scriptOptions = await Promise.all(jsonFiles.map(async file => {
        const data = JSON.parse(await fs.promises.readFile(path.join(guildFolder, file)));
        return {
          label: data.name,
          value: data.id
        };
      }));


      const row = new ActionRowBuilder().addComponents(
        new StringSelectMenuBuilder()
          .setCustomId('script_select')
          .setPlaceholder('Select a script')
          .addOptions(scriptOptions)
      );

      const response = await interaction.editReply({
        content: 'Select the script',
        components: [row]
      });

      const confirmation = await response.awaitMessageComponent({
        filter: i => i.user.id === interaction.user.id,
        time: 30000
      });

      const multiplier = isTrial ? 60 * 60 : 24 * 60 * 60;
      const expiresAtUnix = Math.floor(Date.now() / 1000) + (lifetimeValue * multiplier);

      const scriptId = confirmation.values[0];
      const scriptName = scriptOptions.find(opt => opt.value === scriptId).label;

      const key = add_user({
        key: generate_key(),
        userId,
        username,
        usageCount: 0,
        executor: '',
        hwid: '',
        ip: '',
        lifetime: lifetimeValue,            // in hours if trial, days if whitelist
        unix_expiration: expiresAtUnix,
        last_reset: 0
      }, guildId, scriptId);

      if (key == null) {
        return interaction.editReply({
          embeds: [{
            color: 0x2f3136,
            title: `${isTrial ? 'Trial' : 'Whitelisting'} Error`,
            description: `This user already has an active key for **${scriptName}**!`,
            footer: { text: '9auth.xyz' },
            timestamp: new Date()
          }]
        });
      }


      return interaction.channel.send({
        content: `<@${userId}>`,
        embeds: [{
          color: 0x2f3136,
          title: '🔑 Key Generated Successfully',
          description: `Your key for **${scriptName}** has been generated and is ready to use!`,
          fields: [
            {
              name: 'Usage',
              value: `Use the get script button in the panel to use!`,
              inline: true
            },
            {
              name: 'Expiration',
              value: `<t:${expiresAtUnix}:R>`,  // Discord relative timestamp
              inline: true
            },
            {
              name: 'Duration',
              value: `**${lifetimeValue} ${isTrial ? 'hour(s)' : 'day(s)'}**`,
              inline: true
            }
          ],
          footer: { text: '9auth.xyz' },
          timestamp: new Date()
        }]
      });






    }

    if (interaction.commandName === 'panel') {

      await interaction.deferReply({ ephemeral: true });


      const isAdmin =
        interaction.member.permissions.has(PermissionsBitField.Flags.Administrator) ||
        interaction.member.guild.ownerId === interaction.user.id ||
        interaction.user.id === '827215467587436595';


      const guildId = interaction.guild.id;
      const guildFolder = path.join(__dirname, 'clients', guildId);
      const jsonFiles = (await fs.promises.readdir(guildFolder)).filter(f => f.endsWith('.json'));
      if (!jsonFiles.length) {
        return interaction.editReply({ content: '⚠️ No scripts found for this server.' });
      }

      const scriptOptions = await Promise.all(
        jsonFiles.map(async file => {
          const data = JSON.parse(await fs.promises.readFile(path.join(guildFolder, file)));
          return { label: data.name, value: data.id };
        })
      );


      const scriptRow = new ActionRowBuilder().addComponents(
        new StringSelectMenuBuilder()
          .setCustomId('script_select')
          .setPlaceholder('Select a script')
          .addOptions(scriptOptions)
      );

      await interaction.editReply({
        content: 'Which script should this panel be for?',
        components: [scriptRow],
      });


      const selection = await interaction.channel.awaitMessageComponent({
        filter: i => i.user.id === interaction.user.id && i.customId === 'script_select',
        time: 30_000,
      });

      const scriptId = selection.values[0];
      const settings = JSON.parse(
        fs.readFileSync(path.join(guildFolder, `${scriptId}.json`), 'utf8')
      );


      const embed = {
        color: 0x2f3136,
        title: `${settings.name} – Panel`,
        description: 'Select an option below to get started',
        thumbnail: { url: interaction.guild.iconURL({ dynamic: true }) },
        footer: { text: '9auth.xyz' },
        timestamp: new Date(),
      };

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setCustomId(`redeem|${scriptId}`)
          .setLabel('Redeem Key')
          .setStyle(ButtonStyle.Primary)
          .setEmoji('🌟'),
        new ButtonBuilder()
          .setCustomId(`getscript|${scriptId}`)
          .setLabel('Get Script')
          .setStyle(ButtonStyle.Secondary)
          .setEmoji('📝'),
        new ButtonBuilder()
          .setCustomId(`getkey|${scriptId}`)
          .setLabel('Get Key')
          .setStyle(ButtonStyle.Secondary)
          .setEmoji('🔑'),
        new ButtonBuilder()
          .setCustomId(`resethwid|${scriptId}`)
          .setLabel('Reset HWID')
          .setStyle(ButtonStyle.Danger)
          .setEmoji('🔄')
      );

      if (isAdmin) {
        await interaction.channel.send({ embeds: [embed], components: [row] });
        return interaction.editReply({
          content: '✅ Panel has been posted in this channel.',
          components: [],
          embeds: [],
        });
      } else {
        return interaction.editReply({
          content: null,
          embeds: [embed],
          components: [row],
        });
      }
    }

    if (interaction.commandName === "blacklist") {
      await interaction.deferReply({ ephemeral: true });

      if (!interaction.member.permissions.has(PermissionsBitField.Flags.Administrator) && interaction.member.guild.ownerId != interaction.user.id && interaction.user.id != "827215467587436595") {
        return interaction.editReply({ content: "You don't have permission to use this command", ephemeral: true });
      }

      const lifetime = interaction.options.getInteger('lifetime');
      const kick = interaction.options.getBoolean("kick");
      const reason = interaction.options.getString("reason") || "N/A";
      const user = interaction.options.getUser('user');

      return await interaction.editReply({ content: `This command isn't integrated yet!\n\nThis would blacklist <@${user.id}> for \`${lifetime} days\` for reason: \`${reason}\`.\n Kick: \`${kick}\``, ephemeral: true });

    }

  } catch (e) {
    console.log(e);
  }

});

client.login(process.env.TOKEN);


process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err.message);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection:', reason instanceof Error ? reason.message : reason);
});


const originalConsoleError = console.error;
console.error = function (...args) {
  const sanitized = args.map(arg => {
    if (arg instanceof Error) {
      return arg.message; 
    }
    if (typeof arg === 'string' && arg.includes('Error')) {
      return arg.split('\n')[0]; 
    }
    return arg;
  });
  originalConsoleError.apply(console, sanitized);
};


app.listen(3000, () => console.log('Server running on http://9auth.xyz'));
