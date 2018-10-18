----------------------------------------
-- script-name: common.lua
--
-- authors: Iñigo Ruiz <iruizr7@gmail.com>

--   MCPTT Wireshark Dissector
--   Copyright (C) 2018  Nemergent Initiative http://www.nemergent.com

--   This program is free software: you can redistribute it and/or modify
--   it under the terms of the GNU General Public License as published by
--   the Free Software Foundation, either version 3 of the License, or
--   (at your option) any later version.

--   This program is distributed in the hope that it will be useful,
--   but WITHOUT ANY WARRANTY; without even the implied warranty of
--   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--   GNU General Public License for more details.

--   You should have received a copy of the GNU General Public License
--   along with this program.  If not, see <http://www.gnu.org/licenses/>.

--
-- Version: 1.1
--
--
-- OVERVIEW:
-- This script provides common functionality routines of MCX dissectors.


-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1 = 1,
    LEVEL_2 = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
local DEBUG = debug_level.LEVEL_1

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if DEBUG > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({ "MCX COMMON:", ... }, " "))
        end

        if DEBUG > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end

-- call it now
reset_debug_level()

----------------------------------------
---- Some constants for later use ----
-- the fixed order header size
-- local FIXED_HEADER_LEN = 8 (this value did not include app name: 'MCPT', 'MCPC' or 'MCPC')
FIXED_HEADER_LEN = 12

-- The smallest possible MCPTT field size
-- Has to be at least a field ID (8 bits), the value length (8 bits) and the padding up to the nearer multiple of 4.
MIN_FIELD_LEN = 4

-- RTCP Padding check function
function rtcp_padding(pos, tvbuf, pktlen, pktlen_remaining)
    if pktlen_remaining < MIN_FIELD_LEN then
        -- Check if RTCP padding was needed
        if (pos) % 4 ~= 0 then
            local padding_bytes = 4 - ((pos) % 4)
            for i = 0, padding_bytes - 1, 1 do
                if tvbuf:range(pos, 1):uint() == 0 then
                    pos = pos + 1
                end
            end
            pktlen_remaining = pktlen - pos
            if pktlen_remaining == 0 then
                return -1
            else
                return pos
            end
        else
            return -2
        end
    end
end

-- Field Padding check function
function field_padding(pos, field_start, minus)
    local field_length = pos - field_start
    dprint2("[PAD] Field length: ", field_length)
    local pad_length = field_length - minus
    if pad_length % 4 ~= 0 then
        local padding_bytes = 4 - ((pos) % 4)
        dprint2("[PAD] Padding needed: ", padding_bytes)
        return padding_bytes
    else
        return 0
    end
end
