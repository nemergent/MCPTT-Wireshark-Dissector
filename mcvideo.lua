----------------------------------------
-- script-name: mcvideo.lua
--
-- author: Iñigo García (inigo.garcia@nemergent-solutions.com)

--   MCVIDEO Wireshark Dissector
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
-- Beta version 0.1
--
--
-- OVERVIEW:
-- This script provides a dissector for the Mission Critical VIDEO (MCVIDEO) defined by the 3GPP in the TS 24.581.

dofile("mcx-common/common.lua")

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
            print(table.concat({"MCVIDEO: ", ...}," "))
        end

        if DEBUG > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

dprint("Nemergent MCVIDEO Wireshark dissector (Nemergent Initiative http://www.nemergent.com)")
dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

-- creates a Proto object, but doesn't register it yet
local mcvideo_0 = Proto("mcvideo_0", "Mission Critical Video Protocol Transmission Control (0 type)")
local mcvideo_1 = Proto("mcvideo_1", "Mission Critical Video Protocol Transmission Control (1 type)")
local mcvideo_2 = Proto("mcvideo_2", "Mission Critical Video Protocol Transmission Control (2 type)")

-- 3GPP TS 24.581 version 15 Release 15
-- Table 9.2.3.1-1: Transmission control specific data fields
local field_codes = {
    [0] = "Transmission Priority",
    [1] = "Duration",
    [2] = "Reject Cause",
    [3] = "Queue Info",
    [4] = "Granted Party's Identity",
    [5] = "Permission to Request the Transmission",
    [6] = "User ID",
    [7] = "Queue Size",
    [8] = "Message Sequence-Number",
    [9] = "Queued User ID",
    [10] = "Source",
    [11] = "Track Info",
    [12] = "Message Type",
    [13] = "Transmission Indicator",	
	[14] = "SSRC",
	[15] = "Result",
	[16] = "Message Name",
	[17] = "Overriding ID",
	[18] = "Overridden ID",
	[19] = "Reception Priority",	
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

-- 3GPP TS 24.581 version 15 Release 15
-- Table 9.2.2.1-1: Transmission control specific messages sent by the transmission participant
local type_codes_0 = {
    [0] = "Transmission Request",
    [2] = "Transmission Release",
    [3] = "Queue Position Request",
    [4] = "Receive Media Request",
    [5] = "Transmission Cancel Request",
    [7] = "Remote Transmission Request",
    [8] = "Remote Transmission Cancel Request"
}

-- 3GPP TS 24.581 version 15 Release 15
-- Table 9.2.2.1-2: Transmission control specific messages sent by the transmission control server
local type_codes_1 = {
    [0] = "Transmission Granted",
    [1] = "Transmission Rejected",
    [2] = "Transmission Arbitration Taken",
    [3] = "Transmission Arbitration Release",
    [4] = "Transmission Revoked",
    [5] = "Queue Position Info",
    [6] = "Media transmission notification",
	[7] = "Receive media response",
	[8] = "Media reception notification",
	[9] = "Transmission cancel response",
	[10] = "Transmission cancel request notify",
	[11] = "Remote Transmission response",
	[12] = "Remote Transmission cancel response",
	[13] = "Media reception override notification",
	[14] = "Transmission end notify",
	[15] = "Transmission idle"
}

-- 3GPP TS 24.581 version 15 Release 15
-- Table 9.2.2.1-3: Transmission control specific messages sent by both the transmission control server and transmission control participant
local type_codes_2 = {
    [0] = "Transmission end request",
    [1] = "Transmission end response",
    [2] = "Media reception end request",
    [3] = "Media reception end response",
    [4] = "Transmission control ack"
}
-- 3GPP TS 24.380 version 13.0.2 Release 13
-- Table 8.3.2-1: Pre-established session call control specific messages
local type_codes_pc = {
    [0] = "Connect",
    [1] = "Disconnect",
    [2] = "Acknowledgement"
}

local ack_code = {
    [0] = "ACK not required",
    [1] = "ACK Required",
}

-- Table 8.2.3.12-1: Source field coding
local source_code = {
    [0] = "Transmission Participant",
    [1] = "Participating MCPTT Function",
    [2] = "Controlling MCPTT Function",
    [3] = "Non-Controlling MCPTT Function"
}

-- 9.2.6.2	Rejection cause codes and rejection cause phrase
local reject_cause = {
    [1] = "Transmission limit reached",
    [2] = "Internal transmission control server error",
    [3] = "Only one participant",
    [4] = "Retry-after timer has not expired",
    [5] = "Receive only",
    [6] = "No resources available",
    [255] = "Other reason"
}

-- 9.2.10.2	Transmission revoked cause codes and revoked cause phrases
local revoke_cause = {
    [1] = "Only one MCVideo client",
    [2] = "Media burst too long",
    [3] = "No permission to send a Media Burst",
    [4] = "Media Burst pre-empted",
	[5] = "Terminate the RTP stream",
    [6] = "No resources available",
	[7] = "Queue the transmission",
    [255] = "Other reason"
}

-- 3GPP TS 24.380 version 13.0.2 Release 13
-- 8.3.3.3 MCVIDEO Session Identity field
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
-- with TS 24.380 version 13.3.0 Release 13 changes
-- Table 8.4.3.1-2: MBMS subchannel control protocol specific fields
local field_codes_cp = {
	[0] = "Subchannel",
	[1] = "TMGI",
	[2] = "MCPTT Group ID",
	[3] = "MCPTT Group ID"
}

-- 3GPP TS 24.380 version 13.2.0 Release 13
-- 8.4.3.3 MBMS Subchannel field
local ip_version = {
	[0] = "IP version 4",
	[1] = "IP version 6"
}
-- MCVIDEO_0
local pf_type_0			= ProtoField.new ("Message type", "mcvideo_0.type", ftypes.UINT8, type_codes_0, base.DEC, 0x0F)
local pf_ackreq_0       = ProtoField.new ("ACK Requirement", "mcvideo_0.ackreq", ftypes.UINT8, ack_code, base.DEC, 0x10)

local pf_txprio_0		= ProtoField.uint16 ("mcvideo_0.txprio", "Transmission Priority", base.DEC)
local pf_duration_0     = ProtoField.uint16 ("mcvideo_0.duration", "Duration (s)", base.DEC)
local pf_reject_cause_0 = ProtoField.new ("Reject Cause", "mcvideo_0.rejcause", ftypes.UINT16, reject_cause, base.DEC)
local pf_reject_phrase_0= ProtoField.new ("Reject Phrase", "mcvideo_0.rejphrase", ftypes.STRING)
local pf_queue_info_0   = ProtoField.uint16 ("mcvideo_0.queue", "Queue place", base.DEC)
local pf_queue_unknown_0= ProtoField.new ("Queue place not kwnown", "mcvideo_0.queue_unknown", ftypes.STRING)
local pf_queue_prio_0   = ProtoField.uint16 ("mcvideo_0.queueprio", "Queue Priority", base.DEC)
local pf_granted_id_0   = ProtoField.new ("Granted Party's Identity", "mcvideo_0.grantedid", ftypes.STRING)
local pf_req_perm_0     = ProtoField.bool ("mcvideo_0.reqperm", "Permission to Request the Transmission")
local pf_user_id_0      = ProtoField.new ("User ID", "mcvideo_0.userid", ftypes.STRING)
local pf_queue_size_0   = ProtoField.uint16 ("mcvideo_0.queuesize", "Queue Size", base.DEC)
local pf_sequence_0     = ProtoField.uint16 ("mcvideo_0.sequence", "Sequence Number", base.DEC)
local pf_queued_id_0    = ProtoField.new ("Queued User ID", "mcvideo_0.queuedid", ftypes.STRING)
local pf_source_0       = ProtoField.new ("Source", "mcvideo_0.source", ftypes.UINT16, source_code, base.DEC)

local pf_msg_type_0       = ProtoField.new ("Message ACK type", "mcvideo_0.acktype", ftypes.UINT16, type_codes_0, base.DEC, 0x0700)
local pf_indicators_0     = ProtoField.new ("Transmission Indicator", "mcvideo_0.indicator", ftypes.UINT16, nil, base.HEX)
local pf_ind_normal_0     = ProtoField.new ("Normal", "mcvideo_0.normal", ftypes.UINT16, nil, base.DEC, 0x8000)
local pf_ind_broad_0      = ProtoField.new ("Broadcast Group", "mcvideo_0.broadcast", ftypes.UINT16, nil, base.DEC, 0x4000)
local pf_ind_sys_0        = ProtoField.new ("System", "mcvideo_0.system", ftypes.UINT16, nil, base.DEC, 0x2000)
local pf_ind_emerg_0      = ProtoField.new ("Emergency", "mcvideo_0.emergency", ftypes.UINT16, nil, base.DEC, 0x1000)
local pf_ind_immin_0      = ProtoField.new ("Imminent Peril", "mcvideo_0.imm_peril", ftypes.UINT16, nil, base.DEC, 0x0800)
local pf_ssrc_0			= ProtoField.uint32 ("mcvideo_0.ssrc", "SSRC", base.DEC)
local pf_result_0			= ProtoField.bool ("mcvideo_0.result", "Result")
local pf_msg_name_0		= ProtoField.new ("Message name", "mcvideo_0.msgname", ftypes.STRING)
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
local pf_rxprio_0		= ProtoField.uint16 ("mcvideo_0.rxprio", "Reception Priority", base.DEC)

-- MCVIDEO_1
local pf_type_1			= ProtoField.new ("Message type", "mcvideo_1.type", ftypes.UINT8, type_codes_1, base.DEC, 0x0F)
local pf_ackreq_1        = ProtoField.new ("ACK Requirement", "mcvideo_1.ackreq", ftypes.UINT8, ack_code, base.DEC, 0x10)

local pf_txprio_1			= ProtoField.uint16 ("mcvideo_1.txprio", "Transmission Priority", base.DEC)
local pf_duration_1       = ProtoField.uint16 ("mcvideo_1.duration", "Duration (s)", base.DEC)
local pf_reject_cause_1   = ProtoField.new ("Reject Cause", "mcvideo_1.rejcause", ftypes.UINT16, reject_cause, base.DEC)
local pf_reject_phrase_1  = ProtoField.new ("Reject Phrase", "mcvideo_1.rejphrase", ftypes.STRING)
local pf_queue_info_1     = ProtoField.uint16 ("mcvideo_1.queue", "Queue place", base.DEC)
local pf_queue_unknown_1  = ProtoField.new ("Queue place not kwnown", "mcvideo_1.queue_unknown", ftypes.STRING)
local pf_queue_prio_1     = ProtoField.uint16 ("mcvideo_1.queueprio", "Queue Priority", base.DEC)
local pf_granted_id_1     = ProtoField.new ("Granted Party's Identity", "mcvideo_1.grantedid", ftypes.STRING)
local pf_req_perm_1       = ProtoField.bool ("mcvideo_1.reqperm", "Permission to Request the Transmission")
local pf_user_id_1        = ProtoField.new ("User ID", "mcvideo_1.userid", ftypes.STRING)
local pf_queue_size_1     = ProtoField.uint16 ("mcvideo_1.queuesize", "Queue Size", base.DEC)
local pf_sequence_1       = ProtoField.uint16 ("mcvideo_1.sequence", "Sequence Number", base.DEC)
local pf_queued_id_1      = ProtoField.new ("Queued User ID", "mcvideo_1.queuedid", ftypes.STRING)
local pf_source_1         = ProtoField.new ("Source", "mcvideo_1.source", ftypes.UINT16, source_code, base.DEC)

local pf_msg_type_1       = ProtoField.new ("Message ACK type", "mcvideo_1.acktype", ftypes.UINT16, type_codes_1, base.DEC, 0x0700)
local pf_indicators_1     = ProtoField.new ("Transmission Indicator", "mcvideo_1.indicator", ftypes.UINT16, nil, base.HEX)
local pf_ind_normal_1     = ProtoField.new ("Normal", "mcvideo_1.normal", ftypes.UINT16, nil, base.DEC, 0x8000)
local pf_ind_broad_1      = ProtoField.new ("Broadcast Group", "mcvideo_1.broadcast", ftypes.UINT16, nil, base.DEC, 0x4000)
local pf_ind_sys_1        = ProtoField.new ("System", "mcvideo_1.system", ftypes.UINT16, nil, base.DEC, 0x2000)
local pf_ind_emerg_1      = ProtoField.new ("Emergency", "mcvideo_1.emergency", ftypes.UINT16, nil, base.DEC, 0x1000)
local pf_ind_immin_1      = ProtoField.new ("Imminent Peril", "mcvideo_1.imm_peril", ftypes.UINT16, nil, base.DEC, 0x0800)
local pf_ssrc_1			= ProtoField.uint32 ("mcvideo_1.ssrc", "SSRC", base.DEC)
local pf_result_1			= ProtoField.bool ("mcvideo_1.result", "Result")
local pf_msg_name_1		= ProtoField.new ("Message name", "mcvideo_1.msgname", ftypes.STRING)
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
local pf_rxprio_1		= ProtoField.uint16 ("mcvideo_1.rxprio", "Reception Priority", base.DEC)
-- MCVIDEO_2

local pf_type_2			= ProtoField.new ("Message type", "mcvideo_2.type", ftypes.UINT8, type_codes_2, base.DEC, 0x0F)
local pf_ackreq_2         = ProtoField.new ("ACK Requirement", "mcvideo_2.ackreq", ftypes.UINT8, ack_code, base.DEC, 0x10)

local pf_txprio_2			= ProtoField.uint16 ("mcvideo_2.txprio", "Transmission Priority", base.DEC)
local pf_duration_2       = ProtoField.uint16 ("mcvideo_2.duration", "Duration (s)", base.DEC)
local pf_reject_cause_2   = ProtoField.new ("Reject Cause", "mcvideo_2.rejcause", ftypes.UINT16, reject_cause, base.DEC)
local pf_reject_phrase_2  = ProtoField.new ("Reject Phrase", "mcvideo_2.rejphrase", ftypes.STRING)
local pf_queue_info_2     = ProtoField.uint16 ("mcvideo_2.queue", "Queue place", base.DEC)
local pf_queue_unknown_2  = ProtoField.new ("Queue place not kwnown", "mcvideo_2.queue_unknown", ftypes.STRING)
local pf_queue_prio_2     = ProtoField.uint16 ("mcvideo_2.queueprio", "Queue Priority", base.DEC)
local pf_granted_id_2     = ProtoField.new ("Granted Party's Identity", "mcvideo_2.grantedid", ftypes.STRING)
local pf_req_perm_2       = ProtoField.bool ("mcvideo_2.reqperm", "Permission to Request the Transmission")
local pf_user_id_2        = ProtoField.new ("User ID", "mcvideo_2.userid", ftypes.STRING)
local pf_queue_size_2     = ProtoField.uint16 ("mcvideo_2.queuesize", "Queue Size", base.DEC)
local pf_sequence_2       = ProtoField.uint16 ("mcvideo_2.sequence", "Sequence Number", base.DEC)
local pf_queued_id_2      = ProtoField.new ("Queued User ID", "mcvideo_2.queuedid", ftypes.STRING)
local pf_source_2         = ProtoField.new ("Source", "mcvideo_2.source", ftypes.UINT16, source_code, base.DEC)

local pf_msg_type_2       = ProtoField.new ("Message ACK type", "mcvideo_2.acktype", ftypes.UINT16, type_codes_2, base.DEC, 0x0700)
local pf_indicators_2     = ProtoField.new ("Transmission Indicator", "mcvideo_2.indicator", ftypes.UINT16, nil, base.HEX)
local pf_ind_normal_2     = ProtoField.new ("Normal", "mcvideo_2.normal", ftypes.UINT16, nil, base.DEC, 0x8000)
local pf_ind_broad_2      = ProtoField.new ("Broadcast Group", "mcvideo_2.broadcast", ftypes.UINT16, nil, base.DEC, 0x4000)
local pf_ind_sys_2        = ProtoField.new ("System", "mcvideo_2.system", ftypes.UINT16, nil, base.DEC, 0x2000)
local pf_ind_emerg_2      = ProtoField.new ("Emergency", "mcvideo_2.emergency", ftypes.UINT16, nil, base.DEC, 0x1000)
local pf_ind_immin_2      = ProtoField.new ("Imminent Peril", "mcvideo_2.imm_peril", ftypes.UINT16, nil, base.DEC, 0x0800)
local pf_ssrc_2			= ProtoField.uint32 ("mcvideo_2.ssrc", "SSRC", base.DEC)
local pf_result_2			= ProtoField.bool ("mcvideo_2.result", "Result")
local pf_msg_name_2		= ProtoField.new ("Message name", "mcvideo_2.msgname", ftypes.STRING)
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
local pf_rxprio_2		= ProtoField.uint16 ("mcvideo_2.rxprio", "Reception Priority", base.DEC)




local pf_debug          = ProtoField.uint16 ("mcptt.debug", "Debug", base.DEC)

	


mcvideo_0.fields = {
	pf_ackreq_0,
	pf_type_0,
	pf_txprio_0,
	pf_duration_0,
	pf_reject_cause_0,
	pf_revoke_cause_0,
	pf_reject_phrase_0,
	pf_queue_info_0,
	pf_queue_unknown_0,
	pf_queue_prio_0,
	pf_granted_id_0,
	pf_req_perm_0,
	pf_user_id_0,
	pf_queue_size_0,
	pf_sequence_0,
	pf_queued_id_0,
	pf_source_0,
	pf_msg_type_0,
	pf_indicators_0,
	pf_ind_normal_0,
	pf_ind_broad_0,
	pf_ind_sys_0,
	pf_ind_emerg_0,
	pf_ind_immin_0,
	pf_ssrc_0,
	pf_result_0,
	pf_msg_name_0,
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
	pf_rxprio_0
}


mcvideo_1.fields = {
	pf_ackreq_1,
	pf_type_1,
	pf_txprio_1,
	pf_duration_1,
	pf_reject_cause_1,
	pf_revoke_cause_1,
	pf_reject_phrase_1,
	pf_queue_info_1,
	pf_queue_unknown_1,
	pf_queue_prio_1,
	pf_granted_id_1,
	pf_req_perm_1,
	pf_user_id_1,
	pf_queue_size_1,
	pf_sequence_1,
	pf_queued_id_1,
	pf_source_1,
	pf_msg_type_1,
	pf_indicators_1,
	pf_ind_normal_1,
	pf_ind_broad_1,
	pf_ind_sys_1,
	pf_ind_emerg_1,
	pf_ind_immin_1,
	pf_ssrc_1,
	pf_result_1,
	pf_msg_name_1,
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
	pf_rxprio_1
}

mcvideo_2.fields = {
	pf_ackreq_2,
	pf_type_2,
	pf_txprio_2,
	pf_duration_2,
	pf_reject_cause_2,
	pf_revoke_cause_2,
	pf_reject_phrase_2,
	pf_queue_info_2,
	pf_queue_unknown_2,
	pf_queue_prio_2,
	pf_granted_id_2,
	pf_req_perm_2,
	pf_user_id_2,
	pf_queue_size_2,
	pf_sequence_2,
	pf_queued_id_2,
	pf_source_2,
	pf_msg_type_2,
	pf_indicators_2,
	pf_ind_normal_2,
	pf_ind_broad_2,
	pf_ind_sys_2,
	pf_ind_emerg_2,
	pf_ind_immin_2,
	pf_ssrc_2,
	pf_result_2,
	pf_msg_name_2,
--	[17] = "Overriding ID",
--	[18] = "Overridden ID",
	pf_rxprio_2
}
-- Local values for our use
local type_0    = Field.new("mcvideo_0.type")
local type_1    = Field.new("mcvideo_1.type")
local type_2    = Field.new("mcvideo_2.type")



 local grantedid_mcvideo_0 = Field.new("mcvideo_0.grantedid")
 local duration_mcvideo_0  = Field.new("mcvideo_0.duration")
 local rejphrase_mcvideo_0 = Field.new("mcvideo_0.rejphrase")

 local grantedid_mcvideo_1 = Field.new("mcvideo_1.grantedid")
 local duration_mcvideo_1  = Field.new("mcvideo_1.duration")
 local rejphrase_mcvideo_1 = Field.new("mcvideo_1.rejphrase")

 local grantedid_mcvideo_2 = Field.new("mcvideo_2.grantedid")
 local duration_mcvideo_2  = Field.new("mcvideo_2.duration")
 local rejphrase_mcvideo_2 = Field.new("mcvideo_2.rejphrase")


function mcvideo_0.dissector(tvbuf,pktinfo,root)

    dprint2("mcvideo_0.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCV0")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcvideo_0, tvbuf:range(0,pktlen), "Mission Critical Video: Transmission control")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_ackreq_0, tvbuf:range(0,1))
    tree:add(pf_type_0, tvbuf:range(0,1))

    local pk_info = "MCV0 " .. type_codes_0[type_0().value]
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

        if field_name == "Transmission Priority" then
            dprint2("============TX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8?
            -- Table 8.2.3.2-1: Transmission Priority field coding
            -- Add the Transmission priority to the tree
            tree:add(pf_txprio_0, tvbuf:range(pos,1))

            pos = pos + field_len

        elseif field_name == "Duration" then
            dprint2("============Duration")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.3-1: Duration field coding
            -- Add the Duration to the tree
            tree:add(pf_duration_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (for ".. duration_mcvideo_0().display .." s)"
            pktinfo.cols.info = pk_info

        elseif field_name == "Reject Cause" then
            dprint2("============Reject Cause")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.4-1: Reject Cause field coding
            -- Add the Reject Cause bits to the tree
            if type_0().value == 4 then
                tree:add(pf_revoke_cause_0, tvbuf:range(pos,2))
            elseif type_0().value == 1 then
                tree:add(pf_reject_cause_0, tvbuf:range(pos,2))
            end
            pos = pos + 2

            if field_len > 2 then
                -- Add the Reject Phrase to the tree
                tree:add(pf_reject_phrase_0, tvbuf:range(pos,field_len-2))
                pos = pos + field_len-2

                pk_info = pk_info .. " (".. rejphrase_mcvideo_0().display ..")"
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
                tree:add(pf_queue_unknown_0, "MCPTT Server did not disclose queue position")
            elseif queue_pos == 65534 then
                tree:add(pf_queue_unknown_0, "Client not queued")
            else
                tree:add(pf_queue_info_0, queue_pos)
            end
            pos = pos +1

            -- Add the Queue Priority to the tree
            tree:add(pf_queue_prio_0, tvbuf:range(pos,1))
            pos = pos +1

        elseif field_name == "Granted Party's Identity" then
            dprint2("============Granted Party's Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Granted Party's Identity to the tree
            tree:add(pf_granted_id_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (by ".. grantedid_mcvideo_0().display ..")"
            pktinfo.cols.info = pk_info

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "Permission to Request the Transmission" then
            dprint2("============Permission to Request the Transmission")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Transmission to the tree
            tree:add(pf_req_perm_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queue Size" then --TODO: Not Tested
            dprint2("============Queue Size")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_queue_size_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queued User ID" then
            dprint2("============Queued User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Queued User ID to the tree
            tree:add(pf_queued_id_0, tvbuf:range(pos,field_len))
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
            tree:add(pf_sequence_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Source" then
            dprint2("============Source")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_source_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Message Type" then
            dprint2("============Message Type")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_msg_type_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Transmission Indicator" then
            dprint2("============Transmission Indicator")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Create a new subtree for the Indicators
            local ind_tree = tree:add(pf_indicators_0, tvbuf:range(pos,field_len))

            -- Add the Floor Indicator to the tree
            ind_tree:add(pf_ind_normal_0, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_broad_0, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_sys_0, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_emerg_0, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_immin_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "User ID" then --TODO: Not Tested
            dprint2("============User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the User ID to the tree
            tree:add(pf_user_id_0, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end

        
		
		elseif field_name == "SSRC" then
			dprint2("============SSRC")
			-- Get the field length (8 bits) (it should be always 6)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the SSRC to the tree (only 32 bits, the other 16 are spare) 
			tree:add(pf_ssrc_0, tvbuf:range(pos,4))
            pos = pos + field_len
			
			-- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
		
		
		elseif field_name == "Result" then
			dprint2("============Result")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Result to the tree
			tree:add(pf_result_0, tvbuf:range(pos,field_len))
            pos = pos + field_len
			
			-- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
		
		elseif field_name == "Message Name" then
			dprint2("============Message Name")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Message Name to the tree (only 32 bits, the other 16 are spare) 
			tree:add(pf_msg_name_0, tvbuf:range(pos,4))
            pos = pos + field_len
			
			-- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
			
		elseif field_name == "Reception Priority" then
            dprint2("============RX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8
            -- Table 9.2.3.19-1: Reception Priority field coding
            -- Add the Transmission priority to the tree
            tree:add(pf_rxprio_0, tvbuf:range(pos,1))

            pos = pos + field_len
		end
        pktlen_remaining = pktlen - pos

    end


    dprint2("mcvideo_0.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

function mcvideo_1.dissector(tvbuf,pktinfo,root)

    dprint2("mcvideo_1.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCV1")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcvideo_1, tvbuf:range(0,pktlen), "Mission Critical Video: Transmission control")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_ackreq_1, tvbuf:range(0,1))
    tree:add(pf_type_1, tvbuf:range(0,1))

    local pk_info = "MCV1 " .. type_codes_1[type_1().value]
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

        if field_name == "Transmission Priority" then
            dprint2("============TX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8?
            -- Table 8.2.3.2-1: Floor Priority field coding
            -- Add the Floor priority to the tree
            tree:add(pf_txprio_1, tvbuf:range(pos,1))

            pos = pos + field_len

        elseif field_name == "Duration" then
            dprint2("============Duration")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.3-1: Duration field coding
            -- Add the Duration to the tree
            tree:add(pf_duration_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (for ".. duration_mcvideo_1().display .." s)"
            pktinfo.cols.info = pk_info

        elseif field_name == "Reject Cause" then
            dprint2("============Reject Cause")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.4-1: Reject Cause field coding
            -- Add the Reject Cause bits to the tree
            if type_1().value == 4 then
                tree:add(pf_revoke_cause_1, tvbuf:range(pos,2))
            elseif type_1().value == 1 then
                tree:add(pf_reject_cause_1, tvbuf:range(pos,2))
            end
            pos = pos + 2

            if field_len > 2 then
                -- Add the Reject Phrase to the tree
                tree:add(pf_reject_phrase_1, tvbuf:range(pos,field_len-2))
                pos = pos + field_len-2

                pk_info = pk_info .. " (".. rejphrase_mcvideo_1().display ..")"
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
                tree:add(pf_queue_unknown_1, "MCPTT Server did not disclose queue position")
            elseif queue_pos == 65534 then
                tree:add(pf_queue_unknown_1, "Client not queued")
            else
                tree:add(pf_queue_info_1, queue_pos)
            end
            pos = pos +1

            -- Add the Queue Priority to the tree
            tree:add(pf_queue_prio_1, tvbuf:range(pos,1))
            pos = pos +1

        elseif field_name == "Granted Party's Identity" then
            dprint2("============Granted Party's Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Granted Party's Identity to the tree
            tree:add(pf_granted_id_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (by ".. grantedid_mcvideo_1().display ..")"
            pktinfo.cols.info = pk_info

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "Permission to Request the Transmission" then
            dprint2("============Permission to Request the Transmission")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Transmission to the tree
            tree:add(pf_req_perm_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queue Size" then --TODO: Not Tested
            dprint2("============Queue Size")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_queue_size_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queued User ID" then
            dprint2("============Queued User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Queued User ID to the tree
            tree:add(pf_queued_id_1, tvbuf:range(pos,field_len))
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
            tree:add(pf_sequence_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Source" then
            dprint2("============Source")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_source_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Message Type" then
            dprint2("============Message Type")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_msg_type_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Transmission Indicator" then
            dprint2("============Transmission Indicator")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Create a new subtree for the Indicators
            local ind_tree = tree:add(pf_indicators_1, tvbuf:range(pos,field_len))

            -- Add the Floor Indicator to the tree
            ind_tree:add(pf_ind_normal_1, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_broad_1, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_sys_1, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_emerg_1, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_immin_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "User ID" then --TODO: Not Tested
            dprint2("============User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the User ID to the tree
            tree:add(pf_user_id_1, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end

        
		
		elseif field_name == "SSRC" then
			dprint2("============SSRC")
			-- Get the field length (8 bits) (it should be always 6)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the SSRC to the tree (only 32 bits, the other 16 are spare) 
			tree:add(pf_ssrc_1, tvbuf:range(pos,4))
            pos = pos + field_len
			
			-- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
			
		
		elseif field_name == "Result" then
			dprint2("============Result")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Result to the tree
			tree:add(pf_result_1, tvbuf:range(pos,field_len))
            pos = pos + field_len
			
			-- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
			
		elseif field_name == "Message Name" then
			dprint2("============Message Name")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Message Name to the tree (only 32 bits, the other 16 are spare) 
			tree:add(pf_msg_name_1, tvbuf:range(pos,4))
            pos = pos + field_len
			
			-- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
			
		elseif field_name == "Reception Priority" then
            dprint2("============RX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8
            -- Table 9.2.3.19-1: Reception Priority field coding
            -- Add the Transmission priority to the tree
            tree:add(pf_rxprio_1, tvbuf:range(pos,1))

            pos = pos + field_len
		end
        pktlen_remaining = pktlen - pos

    end


    dprint2("mcvideo_1.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

function mcvideo_2.dissector(tvbuf,pktinfo,root)

    dprint2("mcvideo_2.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("MCV2")

    -- Save the packet length
    local pktlen = tvbuf:reported_length_remaining()

    -- Add ourselves to the tree
    -- The second argument represent how much packet length this tree represents,
    -- we are taking the entire packet until the end.
    local tree = root:add(mcvideo_2, tvbuf:range(0,pktlen), "Mission Critical Video: Transmission control")

    -- Add the MCPTT type and ACK req. to the sub-tree
    tree:add(pf_ackreq_2, tvbuf:range(0,1))
    tree:add(pf_type_2, tvbuf:range(0,1))

    local pk_info = "MCV2 " .. type_codes_2[type_2().value]
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

        if field_name == "Transmission Priority" then
            dprint2("============TX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8?
            -- Table 8.2.3.2-1: Floor Priority field coding
            -- Add the Floor priority to the tree
            tree:add(pf_txprio_2, tvbuf:range(pos,1))

            pos = pos + field_len

        elseif field_name == "Duration" then
            dprint2("============Duration")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.3-1: Duration field coding
            -- Add the Duration to the tree
            tree:add(pf_duration_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (for ".. duration_mcvideo_2().display .." s)"
            pktinfo.cols.info = pk_info

        elseif field_name == "Reject Cause" then
            dprint2("============Reject Cause")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Table 8.2.3.4-1: Reject Cause field coding
            -- Add the Reject Cause bits to the tree
            if type_2().value == 4 then
                tree:add(pf_revoke_cause_2, tvbuf:range(pos,2))
            elseif type_2().value == 1 then
                tree:add(pf_reject_cause_2, tvbuf:range(pos,2))
            end
            pos = pos + 2

            if field_len > 2 then
                -- Add the Reject Phrase to the tree
                tree:add(pf_reject_phrase_2, tvbuf:range(pos,field_len-2))
                pos = pos + field_len-2

                pk_info = pk_info .. " (".. rejphrase_mcvideo_2().display ..")"
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
                tree:add(pf_queue_unknown_2, "MCPTT Server did not disclose queue position")
            elseif queue_pos == 65534 then
                tree:add(pf_queue_unknown_2, "Client not queued")
            else
                tree:add(pf_queue_info_2, queue_pos)
            end
            pos = pos +1

            -- Add the Queue Priority to the tree
            tree:add(pf_queue_prio_2, tvbuf:range(pos,1))
            pos = pos +1

        elseif field_name == "Granted Party's Identity" then
            dprint2("============Granted Party's Identity")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Granted Party's Identity to the tree
            tree:add(pf_granted_id_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

            pk_info = pk_info .. " (by ".. grantedid_mcvideo_2().display ..")"
            pktinfo.cols.info = pk_info

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
            dprint2("Padding until: ", pos)

        elseif field_name == "Permission to Request the Transmission" then
            dprint2("============Permission to Request the Transmission")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Transmission to the tree
            tree:add(pf_req_perm_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queue Size" then --TODO: Not Tested
            dprint2("============Queue Size")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_queue_size_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Queued User ID" then
            dprint2("============Queued User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the Queued User ID to the tree
            tree:add(pf_queued_id_2, tvbuf:range(pos,field_len))
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
            tree:add(pf_sequence_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Source" then
            dprint2("============Source")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_source_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Message Type" then
            dprint2("============Message Type")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Add the Permission to Request the Floor to the tree
            tree:add(pf_msg_type_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "Transmission Indicator" then
            dprint2("============Transmission Indicator")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Create a new subtree for the Indicators
            local ind_tree = tree:add(pf_indicators_2, tvbuf:range(pos,field_len))

            -- Add the Floor Indicator to the tree
            ind_tree:add(pf_ind_normal_2, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_broad_2, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_sys_2, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_emerg_2, tvbuf:range(pos,field_len))
            ind_tree:add(pf_ind_immin_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

        elseif field_name == "User ID" then --TODO: Not Tested
            dprint2("============User ID")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):le_uint()
            pos = pos +1

            -- Add the User ID to the tree
            tree:add(pf_user_id_2, tvbuf:range(pos,field_len))
            pos = pos + field_len

            -- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end

		
		elseif field_name == "SSRC" then
			dprint2("============SSRC")
			-- Get the field length (8 bits) (it should be always 6)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the SSRC to the tree (only 32 bits, the other 16 are spare) 
			tree:add(pf_ssrc_2, tvbuf:range(pos,4))
            pos = pos + field_len
			
			-- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
			
		
		elseif field_name == "Result" then
			dprint2("============Result")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Result to the tree
			tree:add(pf_result_2, tvbuf:range(pos,field_len))
            pos = pos + field_len
			
			-- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
			
		elseif field_name == "Message Name" then
			dprint2("============Message Name")
			-- Get the field length (8 bits)
			local field_len = tvbuf:range(pos,1):le_uint()
			pos = pos +1
			
			-- Add the Message Name to the tree (only 32 bits, the other 16 are spare) 
			tree:add(pf_msg_name_2, tvbuf:range(pos,4))
            pos = pos + field_len
			
			-- Consume the possible padding
            while pos < pktlen and tvbuf:range(pos,1):uint() == 0 do
                pos = pos +1
            end
			
		elseif field_name == "Reception Priority" then
            dprint2("============RX PRIO")
            -- Get the field length (8 bits)
            local field_len = tvbuf:range(pos,1):uint()
            pos = pos +1

            -- Supposely fixed to 16 bits, and only used the first 8
            -- Table 9.2.3.19-1: Reception Priority field coding
            -- Add the Transmission priority to the tree
            tree:add(pf_rxprio_2, tvbuf:range(pos,1))

            pos = pos + field_len
		end

        pktlen_remaining = pktlen - pos

    end


    dprint2("mcvideo_0.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

	

-- we want to have our protocol dissection invoked for a specific RTCP APP Name,
-- so get the rtcp.app.name dissector table and add our protocol to it

DissectorTable.get("rtcp.app.name"):add("MCV0", mcvideo_0.dissector)
DissectorTable.get("rtcp.app.name"):add("MCV1", mcvideo_1.dissector)
DissectorTable.get("rtcp.app.name"):add("MCV2", mcvideo_2.dissector)

-- we add all new MIME types of MCPTT protocol to the XML dissector
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-info+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-mbms-usage-info+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-location-info+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-affiliation-command+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-floor-request+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-signed+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-ue-init-config+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-ue-config+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt.user-profile+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-service-config+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcvideo-info+xml", Dissector.get("xml"))