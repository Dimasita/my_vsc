local cjson = require "cjson"
local mysql = require "resty.mysql"
local jwt = require "resty.jwt"

local h = ngx.req.get_headers()
if not h['Authorization'] then
    return ngx.exec("@error")
end

for header, _ in pairs(h) do
    ngx.req.clear_header(header)
end

local jwt_token = h['Authorization']
local jwt_obj = jwt:verify("Xz[JddQ(SveH@ezye$u^B{2t3[beT4LEYV`d`7!n'f('B%Q~]+K]06tRQy`FSyt", jwt_token)


if jwt_obj.verified==true and jwt_obj.valid==true then

    local project = jwt_obj.payload.sub

    if project == nil then
        return ngx.exec("@error")
    end

    local db, err = mysql:new()
    db:set_timeout(1000)
    local ok, err, errno, sqlstate = db:connect
    {
        host = "127.0.0.1",
        port = 3306,
        database = "codeserver",
        user = "root",
        password = "",
    }

    if not ok then
        ngx.log(ngx.ERR,"MySQL failed to connect: ", err, ": ", errno, " ", sqlstate)
        return ngx.exec("@error")
    end

    res, err, errcode, sqlstate = db:query("SELECT port FROM projects WHERE id = '" .. project .. "' LIMIT 1")

    if not res or res[1]["port"] == nil then
        ngx.log(ngx.ERR, "bad result #", i, ": ", err, ": ", errcode, ": ", sqlstate, ".")
        return ngx.exec("@error")
    end

    ngx.var.target = "127.0.0.1:" .. res[1]["port"]
    return ngx.exec("@project")

else
    if string.find(jwt_obj.reason, "jwt token expired at:") == nil then
        return ngx.exec("@error")
    else
        return ngx.exec("@expire")
    end
end

return
