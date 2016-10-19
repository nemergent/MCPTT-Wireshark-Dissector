----------------------------------------
-- script-name: mcptt.lua
--
-- author: Iñigo Ruiz <iruizr7@gmail.com>

--   MCPTT Wireshark Dissector
--   Copyright (C) 2016  Nemergent Initiative http://www.nemergent.com

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
-- Version: 1.0
--
--
-- OVERVIEW:
-- This script provides a dissector for the Mission Critical Push To Talk (MCPTT) defined by the 3GPP in the TS 23.179.

-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
local DEBUG = debug_level.LEVEL_1

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if DEBUG > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if DEBUG > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

-- creates a Proto object, but doesn't register it yet
local mcptt = Proto("mcptt","Mission Critical PTT Protocol Floor Control")
local mcptt_pc = Proto("mcpc","Mission Critical PTT Protocol Pre-established session call control")
local mcptt_cp = Proto("mccp", "Mission Critical MBMS subchannel Control Protocol")

----------------------------------------
---- Some constants for later use ----
-- the fixed order header size
local FIXED_HEADER_LEN = 8

-- The smallest possible MCPTT field size
-- Has to be at least a field ID (8 bits), the value length (8 bits) and a NULL value.
local MIN_FIELD_LEN = 2

-- 3GPP TS 24.380 version 13.0.2 Release 13
-- Table 8.2.3.1-2: Floor control specific fields
local field_codes = {
    [102] = "Floor Priority",
    [103] = "Duration",
    [104] = "Reject Cause",
    [105] = "Queue Info",
    [106] = "Granted Party's Identity",
    [108] = "Permission to Request the Floor",
    [109] = "User ID",
    [110] = "Queue Size",
    [111] = "Message Sequence-Number",
    [112] = "Queued User ID",
    [113] = "Source",
    [114] = "Track Info",
    [115] = "Message Type",
    [116] = "Floor Indicator"
}

-- 3GPP TS 24.380 version 13.0.2 Release 13
-- Table 8.3.3.1-2: Pre-established session call control fields
local field_codes_pc = {
    [0] = "Media Streams",
    [1] = "MCPTT Session Identity",
    [2] = "Warning Text",
    [3] = "MCPTT Group Identity",
    [4] = "Answer State",
    [5] = "Inviting MCPTT User Identity",
    [6] = "Reason Code"
}

-- 3GPP TS 24.380 version 13.0.2 Release 13
-- Table 8.2.2-1: Floor control specific messages
local type_codes = {
    [0] = "Floor Request",
    [1] = "Floor Granted",
    [3] = "Floor Deny",
    [4] = "Floor Release",
    [5] = "Floor Idle",
    [2] = "Floor Taken",
    [6] = "Floor Revoke",
    [8] = "Floor Queue Position Request",
    [9] = "Floor Queue Position Info",
    [10] = "Floor Ack"
}

-- 3GPP TS 24.380 version 13.0.2 Release 13
-- Table 8.3.2-1: Pre-established session call control specific messages
local type_codes_pc = {
    [0] = "Connect",
    [1] = "Disconnect",
    [2] = "Acknoledgement"
}

local ack_code = {
    [0] = "ACK not required",
    [1] = "ACK Required",
}

-- Table 8.2.3.12-1: Source field coding
local source_code = {
    [0] = "Floor Participant",
    [1] = "Participating MCPTT Function",
    [2] = "Controlling MCPTT Function",
    [3] = "Non-Controlling MCPTT Function"
}

-- 8.2.6.2 Rejection cause codes and rejection cause phrase
local reject_cause = {
    [1] = "Another MCPTT client has permission",
    [2] = "Internal floor control server error ",
    [3] = "Only one participant",
    [4] = "Retry-after timer has not expired",
    [5] = "Receive only",
    [6] = "No resources available",
    [7] = " Queue full",
    [255] = "Other reason"
}

-- 8.2.10.2 Floor revoke cause codes and revoke cause phrases
local revoke_cause = {
    [1] = "Only one MCPTT client",
    [2] = "Media burst too long",
    [3] = "No permission to send a Media Burst",
    [4] = "Media Burst pre-empted",
    [6] = "No resources available",
    [255] = "Other reason"
}

-- 3GPP TS 24.380 version 13.0.2 Release 13
-- 8.3.3.3 MCPTT Session Identity field
local session_type = {
    [0] = "No type",
    [1] = "Private",
    [3] = "Prearranged",
    [4] = "Chat"
}

-- 3GPP TS 24.380 version 13.0.2 Release 13
-- 8.3.3.6 Answer State field
local answer_state = {
    [0] = "Unconfirmed",
    [1] = "Confirmed"
}

-- 3GPP TS 24.380 version 13.0.2 Release 13
-- 8.3.3.8 Reason Code field
local reason_code = {
    [0] = "Accepted",
    [1] = "Busy",
    [2] = "Not Accepted"
}

-- 3GPP TS 24.380 version 13.2.0 Release 13
-- Table 8.4.2-1: MBMS subchannel control protocol messages
local type_codes_cp = {
    [0] = "Map Group To Bearer",
    [1] = "Unmap Group To Bearer"
}

-- 3GPP TS 24.380 version 13.2.0 Release 13
-- Table 8.4.3.1-2: MBMS subchannel control protocol specific fields
local field_codes_cp = {
	[0] = "Subchannel",
	[1] = "TMGI",
	[2] = "Not used",
	[3] = "MCPTT Group ID"
}

-- 3GPP TS 24.380 version 13.2.0 Release 13
-- 8.4.3.3 MBMS Subchannel field
local ip_version = {
	[0] = "IP version 4",
	[1] = "IP version 6"
}

local pf_type           = ProtoField.new ("Message type", "mcptt.type", ftypes.UINT8, type_codes, base.DEC, 0x0F)
local pf_ackreq         = ProtoField.new ("ACK Requirement", "mcptt.ackreq", ftypes.UINT8, ack_code, base.DEC, 0x10)

local pf_floorprio      = ProtoField.uint16 ("mcptt.floorprio", "Floor Priority", base.DEC)
local pf_duration       = ProtoField.uint16 ("mcptt.duration", "Duration (s)", base.DEC)
local pf_reject_cause   = ProtoField.new ("Reject Cause", "mcptt.rejcause", ftypes.UINT16, reject_cause, base.DEC)
local pf_revoke_cause   = ProtoField.new ("Revoke Cause", "mcptt.revcause", ftypes.UINT16, revoke_cause, base.DEC)
local pf_reject_phrase  = ProtoField.new ("Reject Phrase", "mcptt.rejphrase", ftypes.STRING)
local pf_queue_info     = ProtoField.uint16 ("mcptt.queue", "Queue place", base.DEC)
local pf_queue_unknown  = ProtoField.new ("Queue place not kwnown", "mcptt.queue_unknown", ftypes.STRING)
local pf_queue_prio     = ProtoField.uint16 ("mcptt.queueprio", "Queue Priority", base.DEC)
local pf_granted_id     = ProtoField.new ("Granted Party's Identity", "mcptt.grantedid", ftypes.STRING)
local pf_req_perm       = ProtoField.bool ("mcptt.reqperm", "Permission to Request the Floor")
local pf_user_id        = ProtoField.new ("User ID", "mcptt.userid", ftypes.STRING)
local pf_queue_size     = ProtoField.uint16 ("mcptt.queuesize", "Queue Size", base.DEC)
local pf_sequence       = ProtoField.uint16 ("mcptt.sequence", "Sequence Number", base.DEC)
local pf_queued_id      = ProtoField.new ("Queued User ID", "mcptt.queuedid", ftypes.STRING)
local pf_source         = ProtoField.new ("Source", "mcptt.source", ftypes.UINT16, source_code, base.DEC)
local pf_msg_type       = ProtoField.new ("Message ACK type", "mcptt.acktype", ftypes.UINT16, type_codes, base.DEC, 0x0700)

local pf_indicators     = ProtoField.new ("Floor Indicator", "mcptt.indicator", ftypes.UINT16, nil, base.HEX)
local pf_ind_normal     = ProtoField.new ("Normal", "mcptt.normal", ftypes.UINT16, nil, base.DEC, 0x8000)
local pf_ind_broad      = ProtoField.new ("Broadcast Group", "mcptt.broadcast", ftypes.UINT16, nil, base.DEC, 0x4000)
local pf_ind_sys        = ProtoField.new ("System", "mcptt.system", ftypes.UINT16, nil, base.DEC, 0x2000)
local pf_ind_emerg      = ProtoField.new ("Emergency", "mcptt.emergency", ftypes.UINT16, nil, base.DEC, 0x1000)
local pf_ind_inmin      = ProtoField.new ("Inminent Peril", "mcptt.inm_peril", ftypes.UINT16, nil, base.DEC, 0x0800)

local pf_debug          = ProtoField.uint16 ("mcptt.debug", "Debug", base.DEC)

local pf_type_pc        = ProtoField.new ("Message type", "mcpc.type", ftypes.UINT8, type_codes_pc, base.DEC, 0x0F)
local pf_media_stream   = ProtoField.uint8 ("mcpc.stream", "Media Stream", base.DEC)
local pf_control_channel= ProtoField.uint8 ("mcpc.ctrlchannel", "Control Channel", base.DEC)
local pf_sess_identity  = ProtoField.new ("MCPTT Session Identity", "mcpc.sess_id", ftypes.STRING)
local pf_sess_type      = ProtoField.new ("MCPTT Session Type", "mcpc.sess_type", ftypes.UINT8, session_type, base.DEC)
local pf_warn_text      = ProtoField.new ("Warning text", "mcpc.warn_text", ftypes.STRING)
local pf_group_id       = ProtoField.new ("MCPTT Group Identity", "mcpc.group_id", ftypes.STRING)
local pf_answ_state     = ProtoField.new ("Answer State", "mcpc.answ_state", ftypes.UINT16, answer_state, base.DEC)
local pf_inv_user_id    = ProtoField.new ("Inviting MCPTT User Identity", "mcpc.inv_user_id", ftypes.STRING)
local pf_reason_code    = ProtoField.new ("Reason Code", "mcpc.reason_code", ftypes.UINT16, reason_code, base.DEC)

local pf_type_cp        = ProtoField.new ("Message type", "mccp.type", ftypes.UINT8, type_codes_cp, base.DEC, 0x0F)
local pf_group_id_cp    = ProtoField.new ("MCPTT Group Identity", "mccp.group_id", ftypes.STRING)
local pf_tmgi           = ProtoField.new ("Temporary Mobile Group Identity (TMGI)", "mccp.tmgi", ftypes.BYTES)
local pf_subchannel     = ProtoField.new ("MBMS Subchannel", "mccp.mbms_subchannel", ftypes.BYTES)
local pf_audio_m_line   = ProtoField.new ("Audio m-line Number", "mccp.audio_m_line", ftypes.UINT8, nil, base.DEC, 0xF0)
local pf_floor_m_line   = ProtoField.new ("Floor m-line Number", "mccp.floor_m_line", ftypes.UINT8, nil, base.DEC, 0x0F)
local pf_ip_version     = ProtoField.new ("IP Version", "mccp.ip_version", ftypes.UINT8, ip_version, base.DEC, 0xF0)
local pf_floor_ctrl_port = ProtoField.new ("Floor Control Port", "mccp.floor_ctrl_port", ftypes.UINT32)
local pf_media_port     = ProtoField.new ("Media Port", "mccp.media_port", ftypes.UINT32) 
local pf_ipv4_addr      = ProtoField.new ("IPv4 Address", "mccp.ipv4_address", ftypes.IPv4)
local pf_ipv6_addr      = ProtoField.new ("IPv4 Address", "mccp.ipv4_address", ftypes.IPv6)
	
mcptt.fields = {
    pf_ackreq,
    pf_type,
    pf_sequence,
    pf_duration,
    pf_floorprio,
    pf_reject_cause,
    pf_revoke_cause,
    pf_reject_phrase,
    pf_queue_info,
    pf_queued_id,
    pf_queue_unknown,
    pf_queue_prio,
    pf_queue_size,
    pf_granted_id,
    pf_req_perm,
    pf_user_id,
    pf_source,
    pf_indicators,
    pf_ind_normal,
    pf_ind_broad,
    pf_ind_sys,
    pf_ind_emerg,
    pf_ind_inmin,
    pf_msg_type,
    pf_debug
}

mcptt_pc.fields = {
    pf_type_pc,
    pf_media_stream,
    pf_control_channel,
    pf_sess_identity,
    pf_sess_type,
    pf_warn_text,
    pf_group_id,
    pf_answ_state,
    pf_inv_user_id,
    pf_reason_code
}

mcptt_cp.fields = {
    pf_type_cp,
    pf_group_id_cp,
    pf_tmgi,
    pf_subchannel,
	pf_audio_m_line,
	pf_floor_m_line,
	pf_ip_version,
	pf_floor_ctrl_port,
	pf_media_port,
	pf_ipv4_addr,
	pf_ipv6_addr
}

-- Expert info
local ef_bad_field = ProtoExpert.new("mcptt.bad_field", "Field missing or malformed",
                                     expert.group.MALFORMED, expert.severity.WARN)
local ef_bad_field_pc = ProtoExpert.new("mcptt_pc.bad_field", "Field missing or malformed",
                                  expert.group.MALFORMED, expert.severity.WARN)
local ef_bad_field_cp = ProtoExpert.new("mcptt_cp.bad_field", "Field missing or malformed",
                                  expert.group.MALFORMED, expert.severity.WARN)							  
								  

mcptt.experts = {
    ef_bad_field
}

mcptt_pc.experts = {
    ef_bad_field_pc
}

mcptt_cp.experts = {
    ef_bad_field_cp
}

-- Local values for our use
local type      = Field.new("mcptt.type")
local type_pc   = Field.new("mcpc.type")
local type_cp   = Field.new("mccp.type")
local grantedid = Field.new("mcptt.grantedid")
local duration  = Field.new("mcptt.duration")
local rejphrase = Field.new("mcptt.rejphrase")


function mcptt.dissector(tvbuf,pktinfo,root)
    dprint2("mcptt.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCPTT")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcptt, tvbuf:range(0,pktlen), "Mission Critical Push-to-talk: Floor control")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_ackreq, tvbuf:range(0,1))
    tree:add(pf_type, tvbuf:range(0,1))

    local pk_info = "MCPT " .. type_codes[type().value]
    pktinfo.cols.info = pk_info

    -- We have parsed all the fixed order header
    local pos = FIXED_HEADER_LEN
    local pktlen_remaining = pktlen - pos

    while pktlen_remaining > 0 do
        dprint2("PKT remaining: ", pktlen_remaining)
        if pktlen_remaining < MIN_FIELD_LEN then
            tree:add_proto_expert_info(ef_bad_field)
            return
        end

        -- Get the Field ID (8 bits)
        local field_id = tvbuf:range(pos,1)
        local field_name = field_codes[field_id:uint()]
        pos = pos +1

        dprint2(field_id:uint())
        dprint2("FIELD ID: ", field_name)
        dprint2("POS: ", pos-1)

        if field_name == "Floor Priority" then
            dprint2("============FLOOR PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8?
            -- Table 8.2.3.2-1: Floor Priority field coding
            -- Add the Floor priority to the tree
            tree:add(pf_floorprio, tvbuf:range(pos,1))

            pos = pos + field_len

        elseif field_name == "Duration" then
            dprint2("============Duration")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.3-1: Duration field coding
            -- Add the Duration to the tree
            tree:add(pf_duration, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (for ".. duration().display .." s)"
            pktinfo.cols.info = pk_info

        elseif field_name == "Reject Cause" then
            dprint2("============Reject Cause")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.4-1: Reject Cause field coding
            -- Add the Reject Cause bits to the tree
            if type().value == 6 then
                tree:add(pf_revoke_cause, tvbuf:range(pos,2))
            elseif type().value == 3 then
                tree:add(pf_reject_cause, tvbuf:range(pos,2))
            end
            pos = pos + 2

            if field_len > 2 then
                -- Add the Reject Phrase to the tree
                tree:add(pf_reject_phrase, tvbuf:range(pos,field_len-2))
                pos = pos + field_len-2

                pk_info = pk_info .. " (".. rejphrase().display ..")"
                pktinfo.cols.info = pk_info

                -- Consume the possible padding
                while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                    pos = pos +1
                end
            end

        elseif field_name == "Queue Info" then --TODO: Not Tested
            dprint2("============Queue Info")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.5-1: Queue Info field coding
            -- Add the Queue Info to the tree
            local queue_pos = tvbuf:range(pos,1):uint()
            if queue_pos == 65535 then
                tree:add(pf_queue_unknown, "MCPTT Server did not disclose queue position")
            elseif queue_pos == 65534 then
                tree:add(pf_queue_unknown, "Client not queued")
            else
                tree:add(pf_queue_info, queue_pos)
            end
            pos = pos +1

            -- Add the Queue Priority to the tree
            tree:add(pf_queue_prio, tvbuf:range(pos,1))
            pos = pos +1

        elseif field_name == "Granted Party's Identity" then
            dprint2("============Granted Party's Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Granted Party's Identity to the tree
            tree:add(pf_granted_id, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (by ".. grantedid().display ..")"
            pktinfo.cols.info = pk_info

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "Permission to Request the Floor" then
            dprint2("============Permission to Request the Floor")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_req_perm, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queue Size" then --TODO: Not Tested
            dprint2("============Queue Size")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_queue_size, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queued User ID" then
            dprint2("============Queued User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Queued User ID to the tree
            tree:add(pf_queued_id, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "Message Sequence-Number" then --TODO: Not Tested
            dprint2("============Message Sequence-Number")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_sequence, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Source" then
            dprint2("============Source")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_source, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Message Type" then
            dprint2("============Message Type")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_msg_type, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Floor Indicator" then
            dprint2("============Floor Indicator")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Create a new subtree for the Indicators
            local ind_tree = tree:add(pf_indicators, tvbuf:range(pos,field_len))

            -- Add the Floor Indicator to the tree
            ind_tree:add(pf_ind_normal, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_broad, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_sys, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_emerg, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_inmin, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "User ID" then --TODO: Not Tested
            dprint2("============User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the User ID to the tree
            tree:add(pf_user_id, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end

        end

        pktlen_remaining = pktlen - pos

    end


    dprint2("mcptt.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

function mcptt_pc.dissector(tvbuf,pktinfo,root)
    dprint2("mcptt_pc.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCPC")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcptt_pc, tvbuf:range(0,pktlen), "Mission Critical Push-to-talk: Pre-established session call control")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_ackreq, tvbuf:range(0,1))
    tree:add(pf_type_pc, tvbuf:range(0,1))

    dprint2("MESSAGE TYPE:", type_pc().value)
    local pk_info = "MCPC " .. type_codes_pc[type_pc().value]
    pktinfo.cols.info = pk_info

    -- We have parsed all the fixed order header
    local pos = FIXED_HEADER_LEN
    local pktlen_remaining = pktlen - pos

    while pktlen_remaining > 0 do
        dprint2("PKT remaining: ", pktlen_remaining)
        if pktlen_remaining < MIN_FIELD_LEN then
            tree:add_proto_expert_info(ef_bad_field_pc)
            return
        end

        -- Get the Field ID (8 bits)
        local field_id = tvbuf:range(pos,1)
        local field_name = field_codes_pc[field_id:uint()]
        pos = pos +1

        dprint2(field_id:uint())
        dprint2("FIELD ID: ", field_name)
        dprint2("POS: ", pos-1)

        if field_name == "Media Streams" then
            dprint2("============Media Streams")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            tree:add(pf_media_stream, tvbuf:range(pos,1))
            pos = pos +1

            tree:add(pf_control_channel, tvbuf:range(pos,1))
            pos = pos +1

            pos = pos + field_len

        elseif field_name == "MCPTT Session Identity" then
            dprint2("============MCPTT Session Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the MCPTT Session Type to the tree
            tree:add(pf_sess_type, tvbuf:range(pos,1))

            -- Add the MCPTT Session Identity to the tree
            tree:add(pf_sess_identity, tvbuf:range(pos+1,field_len-1))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "Warning Text" then
            dprint2("============Warning Text")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Warning Text to the tree
            tree:add(pf_warn_text, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "MCPTT Group Identity" then
            dprint2("============MCPTT Group Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the MCPTT Group Identity to the tree
            tree:add(pf_group_id, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "Answer State" then --TODO: Not Tested
            dprint2("============Answer State")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Answer State to the tree
            tree:add(pf_answ_state, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Inviting MCPTT User Identity" then
            dprint2("============Inviting MCPTT User Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Inviting MCPTT User Identity to the tree
            tree:add(pf_inv_user_id, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "Reason Code" then --TODO: Not Tested
            dprint2("============Reason Code")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Reason Code to the tree
            tree:add(pf_reason_code, tvbuf:range(pos,field_len))
            pos = pos + field_len

        end

        pktlen_remaining = pktlen - pos

    end


    dprint2("mcpc.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

function mcptt_cp.dissector(tvbuf,pktinfo,root)
	dprint2("mcptt_cp.dissector called")
	
	-- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCCP")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcptt_cp, tvbuf:range(0,pktlen), "Mission Critical MBMS subchannel Control Protocol")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_type_cp, tvbuf:range(0,1))

    dprint2("MESSAGE TYPE:", type_cp().value)
    local pk_info = "MCCP " .. type_codes_cp[type_cp().value]
    pktinfo.cols.info = pk_info

    -- We have parsed all the fixed order header
    local pos = FIXED_HEADER_LEN
    local pktlen_remaining = pktlen - pos
	
	while pktlen_remaining > 0 do
        dprint2("PKT remaining: ", pktlen_remaining)
        if pktlen_remaining < MIN_FIELD_LEN then
            tree:add_proto_expert_info(ef_bad_field_cp)
            return
        end

        -- Get the Field ID (8 bits)
        local field_id = tvbuf:range(pos,1)
        local field_name = field_codes_cp[field_id:uint()]
        pos = pos +1

        dprint2(field_id:uint())
        dprint2("FIELD ID: ", field_name)
        dprint2("POS: ", pos-1)

        if field_name == "MCPTT Group ID" then
            dprint2("============MCPTT Group ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the MCPTT Group Identity to the tree
            tree:add(pf_group_id_cp, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "TMGI" then 
            dprint2("============TMGI")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the TMGI to the tree
            tree:add(pf_tmgi, tvbuf:range(pos,field_len))
            pos = pos + field_len
			
            dprint2("Padding until: ", pos)			

        elseif field_name == "Subchannel" then
            dprint2("============Subchannel")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the MBMS Subchannel to the tree
            -- Create a new subtree for the MBMS Subchannel
            local subch_tree = tree:add(pf_subchannel, tvbuf:range(pos,field_len))
			
			subch_tree:add(pf_audio_m_line, tvbuf:range(pos, 1))
			subch_tree:add(pf_floor_m_line, tvbuf:range(pos, 1))
			local floor_line = bit.band(tvbuf:range(pos, 1):int(), 0x000F)
			pos = pos +1
			subch_tree:add(pf_ip_version, tvbuf:range(pos, 1))
			local loc_ip_version = bit.rshift(tvbuf:range(pos, 1):int(), 4)
			local loc_ip_version_name = ip_version[loc_ip_version]
			pos = pos +1
			if floor_line ~= 0 then
				subch_tree:add(pf_floor_ctrl_port, tvbuf:range(pos, 4))
				pos = pos +4
			end
			subch_tree:add(pf_media_port, tvbuf:range(pos, 4))
			pos = pos +4
			if loc_ip_version_name == "IP version 4" then
              subch_tree:add(pf_ipv4_addr, tvbuf:range(pos, 4))
			  pos = pos +4
			elseif loc_ip_version_name == "IP version 6" then
			  subch_tree:add(pf_ipv6_addr, tvbuf:range(pos, 16))
			  pos = pos +16
			end
            
        end

        pktlen_remaining = pktlen - pos

    end

	

    dprint2("mccp.dissector returning",pos)
	
	-- tell wireshark how much of tvbuff we dissected
    return pos
end

-- we want to have our protocol dissection invoked for a specific RTCP APP Name,
-- so get the rtcp.app.name dissector table and add our protocol to it
DissectorTable.get("rtcp.app.name"):add("MCPT", mcptt.dissector)
DissectorTable.get("rtcp.app.name"):add("MCPC", mcptt_pc.dissector)
DissectorTable.get("rtcp.app.name"):add("MCCP", mcptt_cp.dissector)