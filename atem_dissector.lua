-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_2

local default_settings =
{
    debug_level  = DEBUG,
    port         = 9910,
}

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)

----------------------------------------
-- Unfortunately, the older Wireshark/Tshark versions have bugs, and part of the point
-- of this script is to test those bugs are now fixed.  So we need to check the version
-- end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

----------------------------------------


----------------------------------------
-- creates a Proto object, but doesn't register it yet
local atem_proto = Proto("atem","BMD ATEM Protocol")

----------------------------------------
-- multiple ways to do the same thing: create a protocol field (but not register it yet)
-- the abbreviation should always have "<myproto>." before the specific abbreviation, to avoid collisions
local pf_packet_length        = ProtoField.new   ("Packet length", "atem.packet_length", ftypes.UINT16, nil, base.DEC, 0x07FF)
local pf_flags                     = ProtoField.new   ("Command flags", "atem.flags", ftypes.UINT8, nil, base.HEX, 0xF8)
local pf_session_id             = ProtoField.new   ("Session id", "atem.session_id", ftypes.UINT16, nil, base.HEX)
local pf_switcher_pkt_id      = ProtoField.new   ("Switcher pkt id", "atem.switcher_pkt_id", ftypes.UINT16, nil, base.HEX)
local pf_client_pkt_id         = ProtoField.new   ("Client pkt id", "atem.client_pkt_id", ftypes.UINT16, nil, base.HEX)
local pf_ack_pkt_id            = ProtoField.new   ("ACKed pkt id", "atem.ack_pkt_id", ftypes.UINT16, nil, base.HEX)
local pf_unknown1            = ProtoField.new   ("Unknown", "atem.unknown1", ftypes.UINT16, nil, base.HEX)

local pf_cmd_length           = ProtoField.new   ("Command length", "atem.cmd.length", ftypes.UINT16, nil, base.DEC)
local pf_cmd_name            = ProtoField.new   ("Command name", "atem.cmd.name", ftypes.STRING)

-- within the flags field, we want to parse/show the bits separately
-- note the "base" argument becomes the size of the bitmask'ed field when ftypes.BOOLEAN is used
-- the "mask" argument is which bits we want to use for this field (e.g., base=16 and mask=0x8000 means we want the top bit of a 16-bit field)
-- again the following shows different ways of doing the same thing basically
local pf_flag_ack              = ProtoField.new   ("ACK", "atem.flags.ack", ftypes.BOOLEAN, {"1","0"}, 8, 0x08)
local pf_flag_init              = ProtoField.new   ("INIT", "atem.flags.init", ftypes.BOOLEAN, {"1","0"}, 8, 0x10)
local pf_flag_retransmission    = ProtoField.new   ("RETRANSMISSION", "atem.flags.retransmission", ftypes.BOOLEAN, {"1","0"}, 8, 0x20)
local pf_flag_hello    = ProtoField.new   ("HELLO", "atem.flags.hello", ftypes.BOOLEAN, {"1","0"}, 8, 0x40)
local pf_flag_response    = ProtoField.new   ("RESPONSE", "atem.flags.response", ftypes.BOOLEAN, {"1","0"}, 8, 0x80)

----------------------------------------
-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programmatically
-- and then set atem_proto.fields to it, so as to avoid forgetting a field
atem_proto.fields = { 
  pf_packet_length, pf_flags, pf_session_id, pf_switcher_pkt_id, pf_client_pkt_id,  pf_ack_pkt_id, pf_unknown1, pf_flag_ack, 
  pf_cmd_length, pf_cmd_name,
  pf_flag_init, pf_flag_retransmission, pf_flag_hello, pf_flag_response 
}

----------------------------------------
-- we don't just want to display our protocol's fields, we want to access the value of some of them too!
-- There are several ways to do that.  One is to just parse the buffer contents in Lua code to find
-- the values.  But since ProtoFields actually do the parsing for us, and can be retrieved using Field
-- objects, it's kinda cool to do it that way. So let's create some Fields to extract the values.
-- The following creates the Field objects, but they're not 'registered' until after this script is loaded.
-- Also, these lines can't be before the 'atem_proto.fields = ...' line above, because the Field.new() here is
-- referencing fields we're creating, and they're not "created" until that line above.
-- Furthermore, you cannot put these 'Field.new()' lines inside the dissector function.
-- Before Wireshark version 1.11, you couldn't even do this concept (of using fields you just created).
local packet_length_field	= Field.new("atem.packet_length")
local session_id_field		= Field.new("atem.session_id")
local switcher_pkt_id_field	= Field.new("atem.switcher_pkt_id")
local client_pkt_id_field	= Field.new("atem.client_pkt_id")
local ack_pkt_id_field		= Field.new("atem.ack_pkt_id")
local unkown1_field		= Field.new("atem.unknown1")

local cmd_length_field 	= Field.new("atem.cmd.length")
local cmd_name_field 	= Field.new("atem.cmd.name")


local ef_too_short = ProtoExpert.new("atem.too_short.expert", "ATEM message too short", expert.group.MALFORMED, expert.severity.ERROR)
local ef_length_mismatch = ProtoExpert.new("atem.length_mismatch.expert", "ATEM message length mismatch with header", expert.group.MALFORMED, expert.severity.ERROR)

-- register them
atem_proto.experts = { ef_too_short, ef_length_mismatch }

--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

-- a "enum" table for our enum pref, as required by Pref.enum()
-- having the "index" number makes ZERO sense, and is completely illogical
-- but it's what the code has expected it to be for a long time. Ugh.
local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

atem_proto.prefs.debug = Pref.enum("Debug", default_settings.debug_level, "The debug printing level", debug_pref_enum)
atem_proto.prefs.port  = Pref.uint("Port number", default_settings.port, "The UDP port number for BMD ATEM")

----------------------------------------
-- a function for handling prefs being changed
function atem_proto.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level  = atem_proto.prefs.debug
    reset_debug_level()

    if default_settings.port ~= atem_proto.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            dprint2("removing BMD ATEM from port",default_settings.port)
            DissectorTable.get("udp.port"):remove(default_settings.port, atem_proto)
        end
        -- set our new default
        default_settings.port = atem_proto.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            dprint2("adding BMD ATEM to port",default_settings.port)
            DissectorTable.get("udp.port"):add(default_settings.port, atem_proto)
        end
    end

end

dprint2("BMD ATEM Prefs registered")


----------------------------------------
-- the header size
local ATEM_HDR_LEN = 12


----------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "atem_proto.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function atem_proto.dissector(tvbuf,pktinfo,root)
    dprint2("atem.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("ATEM")
    
    local packet_type = "Unknown"

    -- We want to check that the packet size is rational during dissection, so let's get the length of the
    -- packet buffer (Tvb).
    -- Because DNS has no additional payload data other than itself, and it rides on UDP without padding,
    -- we can use tvb:len() or tvb:reported_len() here; but I prefer tvb:reported_length_remaining() as it's safer.
    local pktlen = tvbuf:reported_length_remaining()

    -- We start by adding our protocol to the dissection display tree.
    -- A call to tree:add() returns the child created, so we can add more "under" it using that return value.
    -- The second argument is how much of the buffer/packet this added tree item covers/represents.
    local tree = root:add(atem_proto, tvbuf:range(0,pktlen))

    -- now let's check it's not too short
    if pktlen < ATEM_HDR_LEN then
        -- since we're going to add this protocol to a specific UDP port, we're going to
        -- assume packets in this port are our protocol, so the packet being too short is an error
        -- the old way: tree:add_expert_info(PI_MALFORMED, PI_ERROR, "packet too short")
        -- the correct way now:
        tree:add_proto_expert_info(ef_too_short)
        dprint("packet length",pktlen,"too short")
        return
    end

    -- now let's add the flags
    local flagrange = tvbuf:range(0,1)

    -- for our flags field, we want a sub-tree
    local flag_tree = tree:add(pf_flags, flagrange)
        -- I'm indenting this for clarity, because it's adding to the flag's child-tree

        -- let's add the type of message (query vs. response)
        flag_tree:add(pf_flag_ack, flagrange)
	flag_tree:add(pf_flag_init, flagrange)
	flag_tree:add(pf_flag_retransmission, flagrange)
	flag_tree:add(pf_flag_hello, flagrange)
	flag_tree:add(pf_flag_response, flagrange)

    tree:add(pf_packet_length, tvbuf:range(0,2))
    local packet_length =  tvbuf:range(1,1):uint() +(tvbuf:range(0,1):bitfield(5, 3) * 256)
    
    -- now let's check it's not too short
    if (pktlen < packet_length) or (pktlen > packet_length) then
        tree:add_proto_expert_info(ef_length_mismatch)
        return
    end

    -- now add more to the main atem_proto tree
    tree:add(pf_session_id, tvbuf:range(2,2))
    tree:add(pf_ack_pkt_id, tvbuf:range(4,2))
    tree:add(pf_unknown1, tvbuf:range(6,2))
    tree:add(pf_client_pkt_id, tvbuf:range(8,2))
    tree:add(pf_switcher_pkt_id, tvbuf(10,2))
    
    local pos = ATEM_HDR_LEN
    local cmd_count = 0
    
    if (pktlen > 12 and tvbuf:range(0,1):bitfield(3, 1) == 0) then
        local commands_tree = tree:add("Commands")
	packet_type = "Commands"
      
        local pktlen_remaining = pktlen - pos
	
	while (pktlen_remaining > 0) do
	    local cmd_name = tvbuf:range(pos + 4, 4):string()
	    local cmd_length = tvbuf:range(pos, 2):uint()
	    
	    local cmd_tree = commands_tree:add(cmd_name, tvbuf:range(pos, cmd_length))
	    
	    cmd_tree:add(pf_cmd_length, tvbuf:range(pos, 2))
	    cmd_tree:add(pf_cmd_name, tvbuf:range(pos + 4, 4))
	    
	    pos = pos + cmd_length
	    pktlen_remaining = pktlen_remaining - cmd_length	    
	    
	    cmd_count = cmd_count + 1
	end
      pktinfo.cols.info:set("(".. packet_type ..", ".. cmd_count .." CMDs, Len ".. packet_length ..")")
    else 
      if tvbuf:range(0,1):bitfield(0, 1) == 1 then
        packet_type = "ACK"
      else
        if tvbuf:range(0,1):bitfield(3, 1) == 1 then
          packet_type = "Init"
	else
	  packet_type = "Ping"
	end
      end
      pktinfo.cols.info:set("(".. packet_type ..", Len ".. packet_length ..")")
    end

    dprint2("atem.dissector returning",pos)

    -- tell wireshark how much of tvbuff we dissected
    return pos
end

----------------------------------------
-- we want to have our protocol dissection invoked for a specific UDP port,
-- so get the udp dissector table and add our protocol to it
DissectorTable.get("udp.port"):add(default_settings.port, atem_proto)

-- We're done!
-- our protocol (Proto) gets automatically registered after this script finishes loading
----------------------------------------