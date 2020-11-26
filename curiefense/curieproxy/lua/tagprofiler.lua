module(..., package.seeall)

local globals       = require "lua.globals"
local utils         = require "lua.utils"
local rangesbtree   = require "lua.rangesbtree"
local cjson         = require "cjson"
local json_safe     = require "cjson.safe"

local re_match        = utils.re_match
local tag_request     = utils.tag_request
-- local btree_search    = rangesbtree.btree_search
local json_encode     = cjson.encode



function match_singles(request_map, list_entry)
  for entry_key, list_entries in pairs(list_entry) do
    -- exact request map
    local entry_match = list_entries[request_map[entry_key]]
    if entry_match then
      return entry_match
    end
    -- exact request map's attr
    entry_match = list_entries[request_map.attrs[entry_key]]
    if entry_match then
      return entry_match
    end

    -- pattern matching for all but ip.
    if entry_key ~= 'ip' then
      for pattern, annotation in pairs(list_entries) do
        local value = request_map.attrs[entry_key]
        if value then
          if re_match(value, pattern) then
            request_map.handle:logDebug(string.format("matched >> match_singles - regex %s %s", value, pattern))
            return annotation
          end
        end
      end
    end
  end
  -- no match
  return false
end

function match_pairs(request_map, list_entry)
  for pair_name, match_entries in pairs(list_entry) do
    for key, va in pairs(match_entries) do
      local value, annotation = unpack(va)
      local reqmap_value = request_map[pair_name][key]
      if value and reqmap_value then
        if reqmap_value == value or re_match(reqmap_value, value) then
          request_map.handle:logDebug(string.format("matched >> match_pairs %s %s", reqmap_value, value))
          return annotation
        end
      end
    end
  end
  return false
end

function negate_match_pairs(request_map, list_entry)
  for pair_name, match_entries in pairs(list_entry) do
    for key, va in pairs(match_entries) do
      local value, annotation = unpack(va)
      local reqmap_value = request_map[pair_name][key]
      if value and reqmap_value then
        if reqmap_value ~= value and not re_match(reqmap_value, value) then
          request_map.handle:logDebug(string.format("matched >> negate_match_pairs %s NOT %s", reqmap_value, value))
          return annotation
        end
      end
    end
  end
  return false
end

function match_iprange(request_map, list_entry)
  local ipnum = request_map.attrs.ipnum
  for _, entry in pairs(list_entry) do
    range, annotation = unpack(entry)
    if ipnum and range[1] and range[2] then
      if ipnum >= range[1] and ipnum <= range[2] then
        request_map.handle:logDebug(string.format("matched >> match_iprange range [%s %s], annotation %s, ipnum %s", range[1] , range[2], annotation, ipnum))
        return annotation
      end
    end
  end
  -- no match
  return false
end

-- returns the first match's annotation or "1" (when normalized)
function match_or_list(request_map, list)
  --- IP > ATTRS > HCA > IPRANGE
  --- EXACT then REGEX
  request_map.handle:logDebug(string.format("match_or_list request_map %s\n%s\n%s\n%s", json_encode(request_map.headers), json_encode(request_map.cookies), json_encode(request_map.args), json_encode(request_map.attrs)))

  if list.singles then
    request_map.handle:logDebug(string.format("match_or_list list.singles %s", json_encode(list.singles)))
    local annotation, tags = match_singles(request_map, list.singles)
    if annotation then
      return annotation, list.tags
    end
  end

  if list.pairs then
    request_map.handle:logDebug(string.format("match_or_list list.pairs %s", json_encode(list.pairs)))
    local annotation, tags = match_pairs(request_map, list.pairs)
    if annotation then
      return annotation, list.tags
    end
  end

  if list.iprange:len() > 0 then
    local within = list.iprange:get(request_map.attrs.ip)
    if within then
      return within, list.tags
    end
  end

  return false, false
end

-- returns the first match's annotation or "1" (when normalized)
function negate_match_or_list(request_map, list)
  -- not match_x will do the trick.
  if list.negate_singles and next(list.negate_singles) then
    local annotation, tags = match_singles(request_map, list.negate_singles)
    if not annotation then
      return 'negate', list.tags
    end
  end

  if list.negate_pairs and next(list.negate_pairs) then
    local annotation, tags = negate_match_pairs(request_map, list.negate_pairs)
    if annotation then
      return annotation, list.tags
    end
  end

  if list.negate_iprange:len() > 0 then
    local within = list.negate_iprange:get(k)(request_map.attrs.ip)
    if not within then
      return 'negate', list.tags
    end
  end

  return false, false
end

function tag_lists(request_map)

  for _, list in pairs(globals.ProfilingLists) do
    if list.entries_relation == "OR" then

      local annotation, tags = match_or_list(request_map, list)

      if annotation then
        tag_request(request_map, tags)
      end

      annotation, tags = negate_match_or_list(request_map, list)

      if annotation then
        tag_request(request_map, tags)
      end

    end

  end

end
