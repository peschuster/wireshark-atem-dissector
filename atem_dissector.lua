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
local pf_packet_length   = ProtoField.new   ("Packet length", "atem.packet_length", ftypes.UINT16, nil, base.DEC, 0x07FF)
local pf_flags           = ProtoField.new   ("Command flags", "atem.flags", ftypes.UINT8, nil, base.HEX, 0xF8)
local pf_session_id      = ProtoField.new   ("Session id", "atem.session_id", ftypes.UINT16, nil, base.HEX)
local pf_switcher_pkt_id = ProtoField.new   ("Switcher pkt id", "atem.switcher_pkt_id", ftypes.UINT16, nil, base.HEX)
local pf_client_pkt_id   = ProtoField.new   ("Client pkt id", "atem.client_pkt_id", ftypes.UINT16, nil, base.HEX)
local pf_ack_pkt_id      = ProtoField.new   ("ACKed pkt id", "atem.ack_pkt_id", ftypes.UINT16, nil, base.HEX)
local pf_unknown1        = ProtoField.new   ("Unknown", "atem.unknown1", ftypes.UINT16, nil, base.HEX)

local pf_cmd_length      = ProtoField.new   ("Command length", "atem.cmd.length", ftypes.UINT16, nil, base.DEC)
local pf_cmd_name        = ProtoField.new   ("Command name", "atem.cmd.name", ftypes.STRING)

-- within the flags field, we want to parse/show the bits separately
-- note the "base" argument becomes the size of the bitmask'ed field when ftypes.BOOLEAN is used
-- the "mask" argument is which bits we want to use for this field (e.g., base=16 and mask=0x8000 means we want the top bit of a 16-bit field)
-- again the following shows different ways of doing the same thing basically
local pf_flag_ack            = ProtoField.new ("ACK", "atem.flags.ack", ftypes.BOOLEAN, {"1","0"}, 8, 0x08)
local pf_flag_init           = ProtoField.new ("INIT", "atem.flags.init", ftypes.BOOLEAN, {"1","0"}, 8, 0x10)
local pf_flag_retransmission = ProtoField.new ("RETRANSMISSION", "atem.flags.retransmission", ftypes.BOOLEAN, {"1","0"}, 8, 0x20)
local pf_flag_hello          = ProtoField.new ("HELLO", "atem.flags.hello", ftypes.BOOLEAN, {"1","0"}, 8, 0x40)
local pf_flag_response       = ProtoField.new ("RESPONSE", "atem.flags.response", ftypes.BOOLEAN, {"1","0"}, 8, 0x80)

local pf_fields = {}
local VALS = {}
pf_fields["pf_cmd__ver_major"]  = ProtoField.new  ("Major", "atem.cmd._ver.major", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd__ver_minor"]  = ProtoField.new  ("Minor", "atem.cmd._ver.minor", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd__pin_name0"]  = ProtoField.new  ("Name", "atem.cmd._pin.name0", ftypes.STRING, nil, base.NONE)
pf_fields["pf_cmd_warn_text"]   = ProtoField.new  ("Text", "atem.cmd.warn.text", ftypes.STRING, nil, base.NONE)
pf_fields["pf_cmd__top_mes"]    = ProtoField.new  ("MEs", "atem.cmd._top.mes", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__top_sources0"]   = ProtoField.new  ("Sources", "atem.cmd._top.sources0", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__top_colorgenerators"]    = ProtoField.new  ("Color Generators", "atem.cmd._top.colorgenerators", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__top_auxbusses"]  = ProtoField.new  ("AUX busses", "atem.cmd._top.auxbusses", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__top_downstreamkeyes"]    = ProtoField.new  ("Downstream Keyes", "atem.cmd._top.downstreamkeyes", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__top_stingers"]   = ProtoField.new  ("Stingers", "atem.cmd._top.stingers", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__top_dves"]   = ProtoField.new  ("DVEs", "atem.cmd._top.dves", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__top_supersources"]   = ProtoField.new  ("SuperSources", "atem.cmd._top.supersources", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_unknown0"]  = ProtoField.new  ("Unknown", "atem.field.unknown0", ftypes.UINT8, nil, base.DEC)
VALS["VALS__TOP_HASSDOUTPUT"] = {[0] = "No", [1] = "Yes"}
pf_fields["pf_cmd__top_hassdoutput"]    = ProtoField.new  ("Has SD Output", "atem.cmd._top.hassdoutput", ftypes.UINT8, VALS["VALS__TOP_HASSDOUTPUT"], base.DEC)

pf_fields["pf_field_padding"]  = ProtoField.new  ("Padding", "atem.field.padding", ftypes.NONE, nil, base.NONE)
pf_fields["pf_field_unknown1"]  = ProtoField.new  ("Unknown", "atem.field.unknown1", ftypes.NONE, nil, base.NONE)
VALS["VALS_ME"] = {[0] = "ME1", [1] = "ME2"}
pf_fields["pf_field_me"]    = ProtoField.new  ("M/E", "atem.field.me", ftypes.UINT8, VALS["VALS_ME"], base.DEC)

pf_fields["pf_cmd__mec_keyersonme"] = ProtoField.new  ("Keyers On ME", "atem.cmd._mec.keyersonme", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__mpl_stillbanks"] = ProtoField.new  ("Still Banks", "atem.cmd._mpl.stillbanks", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__mpl_clipbanks"]  = ProtoField.new  ("Clip Banks", "atem.cmd._mpl.clipbanks", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__mvc_multiviewers"]   = ProtoField.new  ("Multi Viewers", "atem.cmd._mvc.multiviewers", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_unknown2"]  = ProtoField.new  ("Unknown", "atem.field.unknown2", ftypes.NONE, nil, base.NONE)
pf_fields["pf_cmd__ssc_boxes"]  = ProtoField.new  ("Boxes", "atem.cmd._ssc.boxes", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_unknown3"]  = ProtoField.new  ("Unknown", "atem.field.unknown3", ftypes.NONE, nil, base.NONE)
pf_fields["pf_cmd__tlc_tallychannels"]  = ProtoField.new  ("Tally Channels", "atem.cmd._tlc.tallychannels", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd__amc_audiochannels"]  = ProtoField.new  ("Audio Channels", "atem.cmd._amc.audiochannels", ftypes.UINT8, nil, base.DEC)
VALS["VALS__AMC_HASMONITOR"] = {[0] = "No", [1] = "Yes"}
pf_fields["pf_cmd__amc_hasmonitor"] = ProtoField.new  ("Has Monitor", "atem.cmd._amc.hasmonitor", ftypes.UINT8, VALS["VALS__AMC_HASMONITOR"], base.DEC)

pf_fields["pf_cmd__vmc_modes"]  = ProtoField.new  ("Modes", "atem.cmd._vmc.modes", ftypes.UINT24, nil, base.DEC, 0x3FFFF)
pf_fields["pf_flag_cmd__vmc_modes_525i5994ntsc"] = ProtoField.new ("525i59.94 NTSC", "atem.cmd._vmc.modes.flags.525i5994ntsc", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x1)
pf_fields["pf_flag_cmd__vmc_modes_625i50pal"] = ProtoField.new ("625i 50 PAL", "atem.cmd._vmc.modes.flags.625i50pal", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x2)
pf_fields["pf_flag_cmd__vmc_modes_525i5994ntsc169"] = ProtoField.new ("525i59.94 NTSC 16:9", "atem.cmd._vmc.modes.flags.525i5994ntsc169", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x4)
pf_fields["pf_flag_cmd__vmc_modes_625i50pal169"] = ProtoField.new ("625i 50 PAL 16:9", "atem.cmd._vmc.modes.flags.625i50pal169", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x8)
pf_fields["pf_flag_cmd__vmc_modes_720p50"] = ProtoField.new ("720p50", "atem.cmd._vmc.modes.flags.720p50", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x10)
pf_fields["pf_flag_cmd__vmc_modes_720p5994"] = ProtoField.new ("720p59.94", "atem.cmd._vmc.modes.flags.720p5994", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x20)
pf_fields["pf_flag_cmd__vmc_modes_1080i50"] = ProtoField.new ("1080i50", "atem.cmd._vmc.modes.flags.1080i50", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x40)
pf_fields["pf_flag_cmd__vmc_modes_1080i5994"] = ProtoField.new ("1080i59.94", "atem.cmd._vmc.modes.flags.1080i5994", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x80)
pf_fields["pf_flag_cmd__vmc_modes_1080p2398"] = ProtoField.new ("1080p23.98", "atem.cmd._vmc.modes.flags.1080p2398", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x100)
pf_fields["pf_flag_cmd__vmc_modes_1080p24"] = ProtoField.new ("1080p24", "atem.cmd._vmc.modes.flags.1080p24", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x200)
pf_fields["pf_flag_cmd__vmc_modes_1080p25"] = ProtoField.new ("1080p25", "atem.cmd._vmc.modes.flags.1080p25", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x400)
pf_fields["pf_flag_cmd__vmc_modes_1080p2997"] = ProtoField.new ("1080p29.97", "atem.cmd._vmc.modes.flags.1080p2997", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x800)
pf_fields["pf_flag_cmd__vmc_modes_1080p50"] = ProtoField.new ("1080p50", "atem.cmd._vmc.modes.flags.1080p50", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x1000)
pf_fields["pf_flag_cmd__vmc_modes_1080p5994"] = ProtoField.new ("1080p59.94", "atem.cmd._vmc.modes.flags.1080p5994", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x2000)
pf_fields["pf_flag_cmd__vmc_modes_2160p2398"] = ProtoField.new ("2160p23.98", "atem.cmd._vmc.modes.flags.2160p2398", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x4000)
pf_fields["pf_flag_cmd__vmc_modes_2160p24"] = ProtoField.new ("2160p24", "atem.cmd._vmc.modes.flags.2160p24", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x8000)
pf_fields["pf_flag_cmd__vmc_modes_2160p25"] = ProtoField.new ("2160p25", "atem.cmd._vmc.modes.flags.2160p25", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x10000)
pf_fields["pf_flag_cmd__vmc_modes_2160p2997"] = ProtoField.new ("2160p29.97", "atem.cmd._vmc.modes.flags.2160p2997", ftypes.BOOLEAN, {"Yes","No"}, 18, 0x20000)

pf_fields["pf_cmd__mac_banks"]  = ProtoField.new  ("Banks", "atem.cmd._mac.banks", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_powr_status"] = ProtoField.new  ("Status", "atem.cmd.powr.status", ftypes.UINT8, nil, base.DEC, 0x3)
pf_fields["pf_flag_cmd_powr_status_mainpower"] = ProtoField.new ("Main Power", "atem.cmd.powr.status.flags.mainpower", ftypes.BOOLEAN, {"On","Off"}, 2, 0x1)
pf_fields["pf_flag_cmd_powr_status_backuppower"] = ProtoField.new ("Backup Power", "atem.cmd.powr.status.flags.backuppower", ftypes.BOOLEAN, {"On","Off"}, 2, 0x2)

VALS["VALS_MODE"] = {[0] = "Center Cut", [1] = "Letterbox", [2] = "Anamorphic"}
pf_fields["pf_field_mode"]  = ProtoField.new  ("Mode", "atem.field.mode", ftypes.UINT8, VALS["VALS_MODE"], base.DEC)

VALS["VALS_FORMAT"] = {[0] = "525i59.94 NTSC", [1] = "625i 50 PAL", [2] = "525i59.94 NTSC 16:9", [3] = "625i 50 PAL 16:9", [4] = "720p50", [5] = "720p59.94", [6] = "1080i50", [7] = "1080i59.94", [8] = "1080p23.98", [9] = "1080p24", [10] = "1080p25", [11] = "1080p29.97", [12] = "1080p50", [13] = "1080p59.94", [14] = "2160p23.98", [15] = "2160p24", [16] = "2160p25", [17] = "2160p29.97"}
pf_fields["pf_field_format"]    = ProtoField.new  ("Format", "atem.field.format", ftypes.UINT8, VALS["VALS_FORMAT"], base.DEC)

VALS["VALS_VIDEOSOURCE"] = {[0] = "Black", [1] = "Input 1", [2] = "Input 2", [3] = "Input 3", [4] = "Input 4", [5] = "Input 5", [6] = "Input 6", [7] = "Input 7", [8] = "Input 8", [9] = "Input 9", [10] = "Input 10", [11] = "Input 11", [12] = "Input 12", [13] = "Input 13", [14] = "Input 14", [15] = "Input 15", [16] = "Input 16", [17] = "Input 17", [18] = "Input 18", [19] = "Input 19", [20] = "Input 20", [1000] = "Color Bars", [2001] = "Color 1", [2002] = "Color 2", [3010] = "Media Player 1", [3011] = "Media Player 1 Key", [3020] = "Media Player 2", [3021] = "Media Player 2 Key", [4010] = "Key 1 Mask", [4020] = "Key 2 Mask", [4030] = "Key 3 Mask", [4040] = "Key 4 Mask", [5010] = "DSK 1 Mask", [5020] = "DSK 2 Mask", [6000] = "Super Source", [7001] = "Clean Feed 1", [7002] = "Clean Feed 2", [8001] = "Auxilary 1", [8002] = "Auxilary 2", [8003] = "Auxilary 3", [8004] = "Auxilary 4", [8005] = "Auxilary 5", [8006] = "Auxilary 6", [10010] = "ME 1 Prog", [10011] = "ME 1 Prev", [10020] = "ME 2 Prog", [10021] = "ME 2 Prev"}
pf_fields["pf_field_videosource"]   = ProtoField.new  ("Video Source", "atem.field.videosource", ftypes.UINT16, VALS["VALS_VIDEOSOURCE"], base.DEC)

pf_fields["pf_field_longname"]  = ProtoField.new  ("Long Name", "atem.field.longname", ftypes.STRING, nil, base.NONE)
pf_fields["pf_field_shortname"] = ProtoField.new  ("Short Name", "atem.field.shortname", ftypes.STRING, nil, base.NONE)
pf_fields["pf_cmd_inpr_availableexternalporttypes"] = ProtoField.new  ("Available External Port Types", "atem.cmd.inpr.availableexternalporttypes", ftypes.UINT8, nil, base.DEC, 0x1F)
pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_sdi"] = ProtoField.new ("SDI", "atem.cmd.inpr.availableexternalporttypes.flags.sdi", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x1)
pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_hdmi"] = ProtoField.new ("HDMI", "atem.cmd.inpr.availableexternalporttypes.flags.hdmi", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x2)
pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_component"] = ProtoField.new ("Component", "atem.cmd.inpr.availableexternalporttypes.flags.component", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x4)
pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_composite"] = ProtoField.new ("Composite", "atem.cmd.inpr.availableexternalporttypes.flags.composite", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x8)
pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_svideo"] = ProtoField.new ("SVideo", "atem.cmd.inpr.availableexternalporttypes.flags.svideo", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x10)

VALS["VALS_INPR_EXTERNALPORTTYPE0"] = {[0] = "Internal", [1] = "SDI", [2] = "HDMI", [3] = "Composite", [4] = "Component", [5] = "SVideo"}
pf_fields["pf_cmd_inpr_externalporttype0"]  = ProtoField.new  ("External Port Type", "atem.cmd.inpr.externalporttype0", ftypes.UINT8, VALS["VALS_INPR_EXTERNALPORTTYPE0"], base.DEC)

VALS["VALS_INPR_PORTTYPE"] = {[0] = "External", [1] = "Black", [2] = "Color Bars", [3] = "Color Generator", [4] = "Media Player Fill", [5] = "Media Player Key", [6] = "SuperSource", [128] = "ME Output", [129] = "Auxilary", [130] = "Mask"}
pf_fields["pf_cmd_inpr_porttype"]   = ProtoField.new  ("Port Type", "atem.cmd.inpr.porttype", ftypes.UINT8, VALS["VALS_INPR_PORTTYPE"], base.DEC)

pf_fields["pf_cmd_inpr_availability"]   = ProtoField.new  ("Availability", "atem.cmd.inpr.availability", ftypes.UINT8, nil, base.DEC, 0x1F)
pf_fields["pf_flag_cmd_inpr_availability_auxilary"] = ProtoField.new ("Auxilary", "atem.cmd.inpr.availability.flags.auxilary", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x1)
pf_fields["pf_flag_cmd_inpr_availability_multiviewer"] = ProtoField.new ("Multiviewer", "atem.cmd.inpr.availability.flags.multiviewer", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x2)
pf_fields["pf_flag_cmd_inpr_availability_supersourceart"] = ProtoField.new ("Super Source Art", "atem.cmd.inpr.availability.flags.supersourceart", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x4)
pf_fields["pf_flag_cmd_inpr_availability_supersourcebox"] = ProtoField.new ("Super Source Box", "atem.cmd.inpr.availability.flags.supersourcebox", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x8)
pf_fields["pf_flag_cmd_inpr_availability_keysourceseverywhere"] = ProtoField.new ("Key Sources (everywhere)", "atem.cmd.inpr.availability.flags.keysourceseverywhere", ftypes.BOOLEAN, {"Yes","No"}, 5, 0x10)

pf_fields["pf_cmd_inpr_meavailability"] = ProtoField.new  ("ME Availability", "atem.cmd.inpr.meavailability", ftypes.UINT8, nil, base.DEC, 0x3)
pf_fields["pf_flag_cmd_inpr_meavailability_me1fillsources"] = ProtoField.new ("ME1 + Fill Sources", "atem.cmd.inpr.meavailability.flags.me1fillsources", ftypes.BOOLEAN, {"Yes","No"}, 2, 0x1)
pf_fields["pf_flag_cmd_inpr_meavailability_me2fillsources"] = ProtoField.new ("ME2 + Fill Sources", "atem.cmd.inpr.meavailability.flags.me2fillsources", ftypes.BOOLEAN, {"Yes","No"}, 2, 0x2)

VALS["VALS_INPR_AVAILABLE3"] = {[0] = "Off", [1] = "?"}
pf_fields["pf_cmd_inpr_available3"] = ProtoField.new  ("Available 3", "atem.cmd.inpr.available3", ftypes.UINT8, VALS["VALS_INPR_AVAILABLE3"], base.DEC)

pf_fields["pf_cmd_cinl_setmask0"]   = ProtoField.new  ("Set Mask", "atem.cmd.cinl.setmask0", ftypes.UINT8, nil, base.DEC, 0x7)
pf_fields["pf_flag_cmd_cinl_setmask0_longname"] = ProtoField.new ("Long Name", "atem.cmd.cinl.setmask0.flags.longname", ftypes.BOOLEAN, {"On","Off"}, 3, 0x1)
pf_fields["pf_flag_cmd_cinl_setmask0_shortname"] = ProtoField.new ("Short Name", "atem.cmd.cinl.setmask0.flags.shortname", ftypes.BOOLEAN, {"On","Off"}, 3, 0x2)
pf_fields["pf_flag_cmd_cinl_setmask0_externalporttype"] = ProtoField.new ("External Port Type", "atem.cmd.cinl.setmask0.flags.externalporttype", ftypes.BOOLEAN, {"On","Off"}, 3, 0x4)

pf_fields["pf_cmd_cinl_externalporttype1"]  = ProtoField.new  ("External Port Type", "atem.cmd.cinl.externalporttype1", ftypes.UINT16, nil, base.DEC)
VALS["VALS_MULTIVIEWER"] = {[0] = "1", [1] = "2"}
pf_fields["pf_field_multiviewer"]   = ProtoField.new  ("Multi Viewer", "atem.field.multiviewer", ftypes.UINT8, VALS["VALS_MULTIVIEWER"], base.DEC)

VALS["VALS_LAYOUT"] = {[0] = "Top", [1] = "Bottom", [2] = "Left", [3] = "Right"}
pf_fields["pf_field_layout"]    = ProtoField.new  ("Layout", "atem.field.layout", ftypes.UINT8, VALS["VALS_LAYOUT"], base.DEC)

VALS["VALS_CMVP_SETMASK1"] = {[0] = "Layout"}
pf_fields["pf_cmd_cmvp_setmask1"]   = ProtoField.new  ("Set Mask", "atem.cmd.cmvp.setmask1", ftypes.UINT8, VALS["VALS_CMVP_SETMASK1"], base.DEC)

pf_fields["pf_field_windowindex"]   = ProtoField.new  ("Window Index", "atem.field.windowindex", ftypes.UINT8, nil, base.DEC)
VALS["VALS_STYLE0"] = {[0] = "Mix", [1] = "Dip", [2] = "Wipe", [3] = "DVE", [4] = "Sting"}
pf_fields["pf_field_style0"]    = ProtoField.new  ("Style", "atem.field.style0", ftypes.UINT8, VALS["VALS_STYLE0"], base.DEC)

pf_fields["pf_field_nexttransition"]    = ProtoField.new  ("Next Transition", "atem.field.nexttransition", ftypes.UINT8, nil, base.DEC, 0x1F)
pf_fields["pf_flag_field_nexttransition_background"] = ProtoField.new ("Background", "atem.field.nexttransition.flags.background", ftypes.BOOLEAN, {"On","Off"}, 5, 0x1)
pf_fields["pf_flag_field_nexttransition_key1"] = ProtoField.new ("Key 1", "atem.field.nexttransition.flags.key1", ftypes.BOOLEAN, {"On","Off"}, 5, 0x2)
pf_fields["pf_flag_field_nexttransition_key2"] = ProtoField.new ("Key 2", "atem.field.nexttransition.flags.key2", ftypes.BOOLEAN, {"On","Off"}, 5, 0x4)
pf_fields["pf_flag_field_nexttransition_key3"] = ProtoField.new ("Key 3", "atem.field.nexttransition.flags.key3", ftypes.BOOLEAN, {"On","Off"}, 5, 0x8)
pf_fields["pf_flag_field_nexttransition_key4"] = ProtoField.new ("Key 4", "atem.field.nexttransition.flags.key4", ftypes.BOOLEAN, {"On","Off"}, 5, 0x10)

VALS["VALS_TRSS_STYLENEXT"] = {[0] = "Mix", [1] = "Dip", [2] = "Wipe", [3] = "DVE", [4] = "Sting"}
pf_fields["pf_cmd_trss_stylenext"]  = ProtoField.new  ("Style Next", "atem.cmd.trss.stylenext", ftypes.UINT8, VALS["VALS_TRSS_STYLENEXT"], base.DEC)

pf_fields["pf_cmd_trss_nexttransitionnext"] = ProtoField.new  ("Next Transition Next", "atem.cmd.trss.nexttransitionnext", ftypes.UINT8, nil, base.DEC, 0x1F)
pf_fields["pf_flag_cmd_trss_nexttransitionnext_background"] = ProtoField.new ("Background", "atem.cmd.trss.nexttransitionnext.flags.background", ftypes.BOOLEAN, {"On","Off"}, 5, 0x1)
pf_fields["pf_flag_cmd_trss_nexttransitionnext_key1"] = ProtoField.new ("Key 1", "atem.cmd.trss.nexttransitionnext.flags.key1", ftypes.BOOLEAN, {"On","Off"}, 5, 0x2)
pf_fields["pf_flag_cmd_trss_nexttransitionnext_key2"] = ProtoField.new ("Key 2", "atem.cmd.trss.nexttransitionnext.flags.key2", ftypes.BOOLEAN, {"On","Off"}, 5, 0x4)
pf_fields["pf_flag_cmd_trss_nexttransitionnext_key3"] = ProtoField.new ("Key 3", "atem.cmd.trss.nexttransitionnext.flags.key3", ftypes.BOOLEAN, {"On","Off"}, 5, 0x8)
pf_fields["pf_flag_cmd_trss_nexttransitionnext_key4"] = ProtoField.new ("Key 4", "atem.cmd.trss.nexttransitionnext.flags.key4", ftypes.BOOLEAN, {"On","Off"}, 5, 0x10)

pf_fields["pf_cmd_cttp_setmask2"]   = ProtoField.new  ("Set Mask", "atem.cmd.cttp.setmask2", ftypes.UINT8, nil, base.DEC, 0x3)
pf_fields["pf_flag_cmd_cttp_setmask2_transitionstyle"] = ProtoField.new ("Transition Style", "atem.cmd.cttp.setmask2.flags.transitionstyle", ftypes.BOOLEAN, {"On","Off"}, 2, 0x1)
pf_fields["pf_flag_cmd_cttp_setmask2_nexttransition"] = ProtoField.new ("Next Transition", "atem.cmd.cttp.setmask2.flags.nexttransition", ftypes.BOOLEAN, {"On","Off"}, 2, 0x2)

VALS["VALS_ENABLED"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_enabled"]   = ProtoField.new  ("Enabled", "atem.field.enabled", ftypes.UINT8, VALS["VALS_ENABLED"], base.DEC)

VALS["VALS_TRPS_INTRANSITION0"] = {[0] = "No", [1] = "Yes"}
pf_fields["pf_cmd_trps_intransition0"]  = ProtoField.new  ("In Transition", "atem.cmd.trps.intransition0", ftypes.UINT8, VALS["VALS_TRPS_INTRANSITION0"], base.DEC)

pf_fields["pf_field_framesremaining"]   = ProtoField.new  ("Frames Remaining", "atem.field.framesremaining", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_position"]  = ProtoField.new  ("Position", "atem.field.position", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_rate"]  = ProtoField.new  ("Rate", "atem.field.rate", ftypes.UINT8, nil, base.DEC)
VALS["VALS_INPUT0"] = {[0] = "Black", [1] = "Input 1", [2] = "Input 2", [3] = "Input 3", [4] = "Input 4", [5] = "Input 5", [6] = "Input 6", [7] = "Input 7", [8] = "Input 8", [9] = "Input 9", [10] = "Input 10", [11] = "Input 11", [12] = "Input 12", [13] = "Input 13", [14] = "Input 14", [15] = "Input 15", [16] = "Input 16", [17] = "Input 17", [18] = "Input 18", [19] = "Input 19", [20] = "Input 20", [1000] = "Color Bars", [2001] = "Color 1", [2002] = "Color 2", [3010] = "Media Player 1", [3011] = "Media Player 1 Key", [3020] = "Media Player 2", [3021] = "Media Player 2 Key", [4010] = "Key 1 Mask", [4020] = "Key 2 Mask", [4030] = "Key 3 Mask", [4040] = "Key 4 Mask", [5010] = "DSK 1 Mask", [5020] = "DSK 2 Mask", [6000] = "Super Source", [7001] = "Clean Feed 1", [7002] = "Clean Feed 2", [8001] = "Auxilary 1", [8002] = "Auxilary 2", [8003] = "Auxilary 3", [8004] = "Auxilary 4", [8005] = "Auxilary 5", [8006] = "Auxilary 6", [10010] = "ME 1 Prog", [10011] = "ME 1 Prev", [10020] = "ME 2 Prog", [10021] = "ME 2 Prev"}
pf_fields["pf_field_input0"]    = ProtoField.new  ("Input", "atem.field.input0", ftypes.UINT16, VALS["VALS_INPUT0"], base.DEC)

pf_fields["pf_cmd_ctdp_setmask3"]   = ProtoField.new  ("Set Mask", "atem.cmd.ctdp.setmask3", ftypes.UINT8, nil, base.DEC, 0x3)
pf_fields["pf_flag_cmd_ctdp_setmask3_rate"] = ProtoField.new ("Rate", "atem.cmd.ctdp.setmask3.flags.rate", ftypes.BOOLEAN, {"On","Off"}, 2, 0x1)
pf_fields["pf_flag_cmd_ctdp_setmask3_input"] = ProtoField.new ("Input", "atem.cmd.ctdp.setmask3.flags.input", ftypes.BOOLEAN, {"On","Off"}, 2, 0x2)

pf_fields["pf_field_pattern"]   = ProtoField.new  ("Pattern", "atem.field.pattern", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_width"] = ProtoField.new  ("Width", "atem.field.width", ftypes.UINT16, nil, base.DEC)
VALS["VALS_FILLSOURCE"] = {[0] = "Black", [1] = "Input 1", [2] = "Input 2", [3] = "Input 3", [4] = "Input 4", [5] = "Input 5", [6] = "Input 6", [7] = "Input 7", [8] = "Input 8", [9] = "Input 9", [10] = "Input 10", [11] = "Input 11", [12] = "Input 12", [13] = "Input 13", [14] = "Input 14", [15] = "Input 15", [16] = "Input 16", [17] = "Input 17", [18] = "Input 18", [19] = "Input 19", [20] = "Input 20", [1000] = "Color Bars", [2001] = "Color 1", [2002] = "Color 2", [3010] = "Media Player 1", [3011] = "Media Player 1 Key", [3020] = "Media Player 2", [3021] = "Media Player 2 Key", [4010] = "Key 1 Mask", [4020] = "Key 2 Mask", [4030] = "Key 3 Mask", [4040] = "Key 4 Mask", [5010] = "DSK 1 Mask", [5020] = "DSK 2 Mask", [6000] = "Super Source", [7001] = "Clean Feed 1", [7002] = "Clean Feed 2", [8001] = "Auxilary 1", [8002] = "Auxilary 2", [8003] = "Auxilary 3", [8004] = "Auxilary 4", [8005] = "Auxilary 5", [8006] = "Auxilary 6", [10010] = "ME 1 Prog", [10011] = "ME 1 Prev", [10020] = "ME 2 Prog", [10021] = "ME 2 Prev"}
pf_fields["pf_field_ssrc_id"] = ProtoField.new("Super Source ID", "atem.field.ssrc_id", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_fillsource"]    = ProtoField.new  ("Fill Source", "atem.field.fillsource", ftypes.UINT16, VALS["VALS_FILLSOURCE"], base.DEC)

pf_fields["pf_field_symmetry"]  = ProtoField.new  ("Symmetry", "atem.field.symmetry", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_softness"]  = ProtoField.new  ("Softness", "atem.field.softness", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_positionx0"]    = ProtoField.new  ("Position X", "atem.field.positionx0", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_positiony0"]    = ProtoField.new  ("Position Y", "atem.field.positiony0", ftypes.UINT16, nil, base.DEC)
VALS["VALS_REVERSE"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_reverse"]   = ProtoField.new  ("Reverse", "atem.field.reverse", ftypes.UINT8, VALS["VALS_REVERSE"], base.DEC)

VALS["VALS_FLIPFLOP"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_flipflop"]  = ProtoField.new  ("FlipFlop", "atem.field.flipflop", ftypes.UINT8, VALS["VALS_FLIPFLOP"], base.DEC)

pf_fields["pf_cmd_ctwp_setmask4"]   = ProtoField.new  ("Set Mask", "atem.cmd.ctwp.setmask4", ftypes.UINT16, nil, base.DEC, 0x3FF)
pf_fields["pf_flag_cmd_ctwp_setmask4_rate"] = ProtoField.new ("Rate", "atem.cmd.ctwp.setmask4.flags.rate", ftypes.BOOLEAN, {"On","Off"}, 10, 0x1)
pf_fields["pf_flag_cmd_ctwp_setmask4_pattern"] = ProtoField.new ("Pattern", "atem.cmd.ctwp.setmask4.flags.pattern", ftypes.BOOLEAN, {"On","Off"}, 10, 0x2)
pf_fields["pf_flag_cmd_ctwp_setmask4_width"] = ProtoField.new ("Width", "atem.cmd.ctwp.setmask4.flags.width", ftypes.BOOLEAN, {"On","Off"}, 10, 0x4)
pf_fields["pf_flag_cmd_ctwp_setmask4_fillsource"] = ProtoField.new ("Fill Source", "atem.cmd.ctwp.setmask4.flags.fillsource", ftypes.BOOLEAN, {"On","Off"}, 10, 0x8)
pf_fields["pf_flag_cmd_ctwp_setmask4_symmetry"] = ProtoField.new ("Symmetry", "atem.cmd.ctwp.setmask4.flags.symmetry", ftypes.BOOLEAN, {"On","Off"}, 10, 0x10)
pf_fields["pf_flag_cmd_ctwp_setmask4_softness"] = ProtoField.new ("Softness", "atem.cmd.ctwp.setmask4.flags.softness", ftypes.BOOLEAN, {"On","Off"}, 10, 0x20)
pf_fields["pf_flag_cmd_ctwp_setmask4_positionx"] = ProtoField.new ("Position X", "atem.cmd.ctwp.setmask4.flags.positionx", ftypes.BOOLEAN, {"On","Off"}, 10, 0x40)
pf_fields["pf_flag_cmd_ctwp_setmask4_positiony"] = ProtoField.new ("Position Y", "atem.cmd.ctwp.setmask4.flags.positiony", ftypes.BOOLEAN, {"On","Off"}, 10, 0x80)
pf_fields["pf_flag_cmd_ctwp_setmask4_reverse"] = ProtoField.new ("Reverse", "atem.cmd.ctwp.setmask4.flags.reverse", ftypes.BOOLEAN, {"On","Off"}, 10, 0x100)
pf_fields["pf_flag_cmd_ctwp_setmask4_flipflop"] = ProtoField.new ("FlipFlop", "atem.cmd.ctwp.setmask4.flags.flipflop", ftypes.BOOLEAN, {"On","Off"}, 10, 0x200)

pf_fields["pf_field_style1"]    = ProtoField.new  ("Style", "atem.field.style1", ftypes.UINT8, nil, base.DEC)
VALS["VALS_KEYSOURCE"] = {[0] = "Black", [1] = "Input 1", [2] = "Input 2", [3] = "Input 3", [4] = "Input 4", [5] = "Input 5", [6] = "Input 6", [7] = "Input 7", [8] = "Input 8", [9] = "Input 9", [10] = "Input 10", [11] = "Input 11", [12] = "Input 12", [13] = "Input 13", [14] = "Input 14", [15] = "Input 15", [16] = "Input 16", [17] = "Input 17", [18] = "Input 18", [19] = "Input 19", [20] = "Input 20", [1000] = "Color Bars", [2001] = "Color 1", [2002] = "Color 2", [3010] = "Media Player 1", [3011] = "Media Player 1 Key", [3020] = "Media Player 2", [3021] = "Media Player 2 Key", [4010] = "Key 1 Mask", [4020] = "Key 2 Mask", [4030] = "Key 3 Mask", [4040] = "Key 4 Mask", [5010] = "DSK 1 Mask", [5020] = "DSK 2 Mask", [6000] = "Super Source", [7001] = "Clean Feed 1", [7002] = "Clean Feed 2", [8001] = "Auxilary 1", [8002] = "Auxilary 2", [8003] = "Auxilary 3", [8004] = "Auxilary 4", [8005] = "Auxilary 5", [8006] = "Auxilary 6", [10010] = "ME 1 Prog", [10011] = "ME 1 Prev", [10020] = "ME 2 Prog", [10021] = "ME 2 Prev"}
pf_fields["pf_field_keysource"] = ProtoField.new  ("Key Source", "atem.field.keysource", ftypes.UINT16, VALS["VALS_KEYSOURCE"], base.DEC)

VALS["VALS_ENABLEKEY"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_enablekey"] = ProtoField.new  ("Enable Key", "atem.field.enablekey", ftypes.UINT8, VALS["VALS_ENABLEKEY"], base.DEC)

VALS["VALS_PREMULTIPLIED"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_premultiplied"] = ProtoField.new  ("Pre Multiplied", "atem.field.premultiplied", ftypes.UINT8, VALS["VALS_PREMULTIPLIED"], base.DEC)

pf_fields["pf_field_clip"]  = ProtoField.new  ("Clip", "atem.field.clip", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_gain0"] = ProtoField.new  ("Gain", "atem.field.gain0", ftypes.UINT16, nil, base.DEC)
VALS["VALS_INVERTKEY0"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_invertkey0"]    = ProtoField.new  ("Invert Key", "atem.field.invertkey0", ftypes.UINT8, VALS["VALS_INVERTKEY0"], base.DEC)

pf_fields["pf_cmd_ctdv_setmask5"]   = ProtoField.new  ("Set Mask", "atem.cmd.ctdv.setmask5", ftypes.UINT16, nil, base.DEC, 0xFFF)
pf_fields["pf_flag_cmd_ctdv_setmask5_rate"] = ProtoField.new ("Rate", "atem.cmd.ctdv.setmask5.flags.rate", ftypes.BOOLEAN, {"On","Off"}, 12, 0x1)
-- pf_fields["pf_flag_cmd_ctdv_setmask5_"] = ProtoField.new ("?", "atem.cmd.ctdv.setmask5.flags.", ftypes.BOOLEAN, {"On","Off"}, 12, 0x2)
pf_fields["pf_flag_cmd_ctdv_setmask5_style"] = ProtoField.new ("Style", "atem.cmd.ctdv.setmask5.flags.style", ftypes.BOOLEAN, {"On","Off"}, 12, 0x4)
pf_fields["pf_flag_cmd_ctdv_setmask5_fillsource"] = ProtoField.new ("Fill Source", "atem.cmd.ctdv.setmask5.flags.fillsource", ftypes.BOOLEAN, {"On","Off"}, 12, 0x8)
pf_fields["pf_flag_cmd_ctdv_setmask5_keysource"] = ProtoField.new ("Key Source", "atem.cmd.ctdv.setmask5.flags.keysource", ftypes.BOOLEAN, {"On","Off"}, 12, 0x10)
pf_fields["pf_flag_cmd_ctdv_setmask5_enablekey"] = ProtoField.new ("Enable Key", "atem.cmd.ctdv.setmask5.flags.enablekey", ftypes.BOOLEAN, {"On","Off"}, 12, 0x20)
pf_fields["pf_flag_cmd_ctdv_setmask5_premultiplied"] = ProtoField.new ("Pre Multiplied", "atem.cmd.ctdv.setmask5.flags.premultiplied", ftypes.BOOLEAN, {"On","Off"}, 12, 0x40)
pf_fields["pf_flag_cmd_ctdv_setmask5_clip"] = ProtoField.new ("Clip", "atem.cmd.ctdv.setmask5.flags.clip", ftypes.BOOLEAN, {"On","Off"}, 12, 0x80)
pf_fields["pf_flag_cmd_ctdv_setmask5_gain"] = ProtoField.new ("Gain", "atem.cmd.ctdv.setmask5.flags.gain", ftypes.BOOLEAN, {"On","Off"}, 12, 0x100)
pf_fields["pf_flag_cmd_ctdv_setmask5_invertkey"] = ProtoField.new ("Invert Key", "atem.cmd.ctdv.setmask5.flags.invertkey", ftypes.BOOLEAN, {"On","Off"}, 12, 0x200)
pf_fields["pf_flag_cmd_ctdv_setmask5_reverse"] = ProtoField.new ("Reverse", "atem.cmd.ctdv.setmask5.flags.reverse", ftypes.BOOLEAN, {"On","Off"}, 12, 0x400)
pf_fields["pf_flag_cmd_ctdv_setmask5_flipflop"] = ProtoField.new ("FlipFlop", "atem.cmd.ctdv.setmask5.flags.flipflop", ftypes.BOOLEAN, {"On","Off"}, 12, 0x800)

VALS["VALS_SOURCE"] = {[1] = "Media Player 1", [2] = "Media Player 2"}
pf_fields["pf_field_source"]    = ProtoField.new  ("Source", "atem.field.source", ftypes.UINT8, VALS["VALS_SOURCE"], base.DEC)

pf_fields["pf_field_preroll"]   = ProtoField.new  ("Pre Roll", "atem.field.preroll", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_clipduration"]  = ProtoField.new  ("Clip Duration", "atem.field.clipduration", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_triggerpoint"]  = ProtoField.new  ("Trigger Point", "atem.field.triggerpoint", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_mixrate"]   = ProtoField.new  ("Mix Rate", "atem.field.mixrate", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_ctst_setmask6"]   = ProtoField.new  ("Set Mask", "atem.cmd.ctst.setmask6", ftypes.UINT16, nil, base.DEC, 0x1FF)
pf_fields["pf_flag_cmd_ctst_setmask6_source"] = ProtoField.new ("Source", "atem.cmd.ctst.setmask6.flags.source", ftypes.BOOLEAN, {"On","Off"}, 9, 0x1)
pf_fields["pf_flag_cmd_ctst_setmask6_premultiplied"] = ProtoField.new ("Pre Multiplied", "atem.cmd.ctst.setmask6.flags.premultiplied", ftypes.BOOLEAN, {"On","Off"}, 9, 0x2)
pf_fields["pf_flag_cmd_ctst_setmask6_clip"] = ProtoField.new ("Clip", "atem.cmd.ctst.setmask6.flags.clip", ftypes.BOOLEAN, {"On","Off"}, 9, 0x4)
pf_fields["pf_flag_cmd_ctst_setmask6_gain"] = ProtoField.new ("Gain", "atem.cmd.ctst.setmask6.flags.gain", ftypes.BOOLEAN, {"On","Off"}, 9, 0x8)
pf_fields["pf_flag_cmd_ctst_setmask6_invertkey"] = ProtoField.new ("Invert Key", "atem.cmd.ctst.setmask6.flags.invertkey", ftypes.BOOLEAN, {"On","Off"}, 9, 0x10)
pf_fields["pf_flag_cmd_ctst_setmask6_preroll"] = ProtoField.new ("Pre Roll", "atem.cmd.ctst.setmask6.flags.preroll", ftypes.BOOLEAN, {"On","Off"}, 9, 0x20)
pf_fields["pf_flag_cmd_ctst_setmask6_clipduration"] = ProtoField.new ("Clip Duration", "atem.cmd.ctst.setmask6.flags.clipduration", ftypes.BOOLEAN, {"On","Off"}, 9, 0x40)
pf_fields["pf_flag_cmd_ctst_setmask6_triggerpoint"] = ProtoField.new ("Trigger Point", "atem.cmd.ctst.setmask6.flags.triggerpoint", ftypes.BOOLEAN, {"On","Off"}, 9, 0x80)
pf_fields["pf_flag_cmd_ctst_setmask6_mixrate"] = ProtoField.new ("Mix Rate", "atem.cmd.ctst.setmask6.flags.mixrate", ftypes.BOOLEAN, {"On","Off"}, 9, 0x100)

pf_fields["pf_field_keyer0"]    = ProtoField.new  ("Keyer", "atem.field.keyer0", ftypes.UINT8, nil, base.DEC)
VALS["VALS_TYPE0"] = {[0] = "Luma", [1] = "Chroma", [2] = "Pattern", [3] = "DVE"}
pf_fields["pf_field_type0"] = ProtoField.new  ("Type", "atem.field.type0", ftypes.UINT8, VALS["VALS_TYPE0"], base.DEC)

VALS["VALS_KEBP_KEYENABLED"] = {[0] = "Off", [1] = "?"}
pf_fields["pf_cmd_kebp_keyenabled"] = ProtoField.new  ("Key Enabled", "atem.cmd.kebp.keyenabled", ftypes.UINT8, VALS["VALS_KEBP_KEYENABLED"], base.DEC)

VALS["VALS_KEBP_KEYENABLEDAGAIN"] = {[0] = "Off", [1] = "?"}
pf_fields["pf_cmd_kebp_keyenabledagain"]    = ProtoField.new  ("Key Enabled (again?)", "atem.cmd.kebp.keyenabledagain", ftypes.UINT8, VALS["VALS_KEBP_KEYENABLEDAGAIN"], base.DEC)

VALS["VALS_FLYENABLED"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_flyenabled"]    = ProtoField.new  ("Fly Enabled", "atem.field.flyenabled", ftypes.UINT8, VALS["VALS_FLYENABLED"], base.DEC)

VALS["VALS_MASKED"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_masked"]    = ProtoField.new  ("Masked", "atem.field.masked", ftypes.UINT8, VALS["VALS_MASKED"], base.DEC)

pf_fields["pf_field_top"]   = ProtoField.new  ("Top", "atem.field.top", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_bottom"]    = ProtoField.new  ("Bottom", "atem.field.bottom", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_left"]  = ProtoField.new  ("Left", "atem.field.left", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_right"] = ProtoField.new  ("Right", "atem.field.right", ftypes.INT16, nil, base.DEC)
pf_fields["pf_cmd_cktp_setmask7"]   = ProtoField.new  ("Set Mask", "atem.cmd.cktp.setmask7", ftypes.UINT8, nil, base.DEC, 0x3)
pf_fields["pf_flag_cmd_cktp_setmask7_type"] = ProtoField.new ("Type", "atem.cmd.cktp.setmask7.flags.type", ftypes.BOOLEAN, {"On","Off"}, 2, 0x1)
pf_fields["pf_flag_cmd_cktp_setmask7_enabled"] = ProtoField.new ("Enabled", "atem.cmd.cktp.setmask7.flags.enabled", ftypes.BOOLEAN, {"On","Off"}, 2, 0x2)

pf_fields["pf_field_setmask8"]  = ProtoField.new  ("Set Mask", "atem.field.setmask8", ftypes.UINT8, nil, base.DEC, 0x1F)
pf_fields["pf_flag_field_setmask8_masked"] = ProtoField.new ("Masked", "atem.field.setmask8.flags.masked", ftypes.BOOLEAN, {"On","Off"}, 5, 0x1)
pf_fields["pf_flag_field_setmask8_top"] = ProtoField.new ("Top", "atem.field.setmask8.flags.top", ftypes.BOOLEAN, {"On","Off"}, 5, 0x2)
pf_fields["pf_flag_field_setmask8_bottom"] = ProtoField.new ("Bottom", "atem.field.setmask8.flags.bottom", ftypes.BOOLEAN, {"On","Off"}, 5, 0x4)
pf_fields["pf_flag_field_setmask8_left"] = ProtoField.new ("Left", "atem.field.setmask8.flags.left", ftypes.BOOLEAN, {"On","Off"}, 5, 0x8)
pf_fields["pf_flag_field_setmask8_right"] = ProtoField.new ("Right", "atem.field.setmask8.flags.right", ftypes.BOOLEAN, {"On","Off"}, 5, 0x10)

pf_fields["pf_cmd_cklm_setmask9"]   = ProtoField.new  ("Set Mask", "atem.cmd.cklm.setmask9", ftypes.UINT8, nil, base.DEC, 0xF)
pf_fields["pf_flag_cmd_cklm_setmask9_premultiplied"] = ProtoField.new ("Pre Multiplied", "atem.cmd.cklm.setmask9.flags.premultiplied", ftypes.BOOLEAN, {"On","Off"}, 4, 0x1)
pf_fields["pf_flag_cmd_cklm_setmask9_clip"] = ProtoField.new ("Clip", "atem.cmd.cklm.setmask9.flags.clip", ftypes.BOOLEAN, {"On","Off"}, 4, 0x2)
pf_fields["pf_flag_cmd_cklm_setmask9_gain"] = ProtoField.new ("Gain", "atem.cmd.cklm.setmask9.flags.gain", ftypes.BOOLEAN, {"On","Off"}, 4, 0x4)
pf_fields["pf_flag_cmd_cklm_setmask9_invertkey"] = ProtoField.new ("Invert Key", "atem.cmd.cklm.setmask9.flags.invertkey", ftypes.BOOLEAN, {"On","Off"}, 4, 0x8)

pf_fields["pf_field_hue0"]  = ProtoField.new  ("Hue", "atem.field.hue0", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_ysuppress"] = ProtoField.new  ("Y Suppress", "atem.field.ysuppress", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_lift"]  = ProtoField.new  ("Lift", "atem.field.lift", ftypes.UINT16, nil, base.DEC)
VALS["VALS_NARROW"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_narrow"]    = ProtoField.new  ("Narrow", "atem.field.narrow", ftypes.UINT8, VALS["VALS_NARROW"], base.DEC)

pf_fields["pf_cmd_ckck_setmask10"]  = ProtoField.new  ("Set Mask", "atem.cmd.ckck.setmask10", ftypes.UINT8, nil, base.DEC, 0x1F)
pf_fields["pf_flag_cmd_ckck_setmask10_hue"] = ProtoField.new ("Hue", "atem.cmd.ckck.setmask10.flags.hue", ftypes.BOOLEAN, {"On","Off"}, 5, 0x1)
pf_fields["pf_flag_cmd_ckck_setmask10_gain"] = ProtoField.new ("Gain", "atem.cmd.ckck.setmask10.flags.gain", ftypes.BOOLEAN, {"On","Off"}, 5, 0x2)
pf_fields["pf_flag_cmd_ckck_setmask10_ysuppress"] = ProtoField.new ("Y Suppress", "atem.cmd.ckck.setmask10.flags.ysuppress", ftypes.BOOLEAN, {"On","Off"}, 5, 0x4)
pf_fields["pf_flag_cmd_ckck_setmask10_lift"] = ProtoField.new ("Lift", "atem.cmd.ckck.setmask10.flags.lift", ftypes.BOOLEAN, {"On","Off"}, 5, 0x8)
pf_fields["pf_flag_cmd_ckck_setmask10_narrow"] = ProtoField.new ("Narrow", "atem.cmd.ckck.setmask10.flags.narrow", ftypes.BOOLEAN, {"On","Off"}, 5, 0x10)

pf_fields["pf_field_size"]  = ProtoField.new  ("Size", "atem.field.size", ftypes.UINT16, nil, base.DEC)
VALS["VALS_INVERTPATTERN"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_invertpattern"] = ProtoField.new  ("Invert Pattern", "atem.field.invertpattern", ftypes.UINT8, VALS["VALS_INVERTPATTERN"], base.DEC)

pf_fields["pf_cmd_ckpt_setmask11"]  = ProtoField.new  ("Set Mask", "atem.cmd.ckpt.setmask11", ftypes.UINT8, nil, base.DEC, 0x7F)
pf_fields["pf_flag_cmd_ckpt_setmask11_pattern"] = ProtoField.new ("Pattern", "atem.cmd.ckpt.setmask11.flags.pattern", ftypes.BOOLEAN, {"On","Off"}, 7, 0x1)
pf_fields["pf_flag_cmd_ckpt_setmask11_size"] = ProtoField.new ("Size", "atem.cmd.ckpt.setmask11.flags.size", ftypes.BOOLEAN, {"On","Off"}, 7, 0x2)
pf_fields["pf_flag_cmd_ckpt_setmask11_symmetry"] = ProtoField.new ("Symmetry", "atem.cmd.ckpt.setmask11.flags.symmetry", ftypes.BOOLEAN, {"On","Off"}, 7, 0x4)
pf_fields["pf_flag_cmd_ckpt_setmask11_softness"] = ProtoField.new ("Softness", "atem.cmd.ckpt.setmask11.flags.softness", ftypes.BOOLEAN, {"On","Off"}, 7, 0x8)
pf_fields["pf_flag_cmd_ckpt_setmask11_positionx"] = ProtoField.new ("Position X", "atem.cmd.ckpt.setmask11.flags.positionx", ftypes.BOOLEAN, {"On","Off"}, 7, 0x10)
pf_fields["pf_flag_cmd_ckpt_setmask11_positiony"] = ProtoField.new ("Position Y", "atem.cmd.ckpt.setmask11.flags.positiony", ftypes.BOOLEAN, {"On","Off"}, 7, 0x20)
pf_fields["pf_flag_cmd_ckpt_setmask11_invertpattern"] = ProtoField.new ("Invert Pattern", "atem.cmd.ckpt.setmask11.flags.invertpattern", ftypes.BOOLEAN, {"On","Off"}, 7, 0x40)

pf_fields["pf_field_sizex"] = ProtoField.new  ("Size X", "atem.field.sizex", ftypes.INT32, nil, base.DEC)
pf_fields["pf_field_sizey"] = ProtoField.new  ("Size Y", "atem.field.sizey", ftypes.INT32, nil, base.DEC)
pf_fields["pf_field_positionx1"]    = ProtoField.new  ("Position X", "atem.field.positionx1", ftypes.INT32, nil, base.DEC)
pf_fields["pf_field_positiony1"]    = ProtoField.new  ("Position Y", "atem.field.positiony1", ftypes.INT32, nil, base.DEC)
pf_fields["pf_field_rotation"]  = ProtoField.new  ("Rotation", "atem.field.rotation", ftypes.INT32, nil, base.DEC)
VALS["VALS_BORDERENABLED"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_borderenabled"] = ProtoField.new  ("Border Enabled", "atem.field.borderenabled", ftypes.UINT8, VALS["VALS_BORDERENABLED"], base.DEC)

VALS["VALS_SHADOW"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_shadow"]    = ProtoField.new  ("Shadow", "atem.field.shadow", ftypes.UINT8, VALS["VALS_SHADOW"], base.DEC)

VALS["VALS_BORDERBEVEL"] = {[0] = "No", [1] = "In/Out", [2] = "In", [3] = "Out"}
pf_fields["pf_field_borderbevel"]   = ProtoField.new  ("Border Bevel", "atem.field.borderbevel", ftypes.UINT8, VALS["VALS_BORDERBEVEL"], base.DEC)

pf_fields["pf_field_borderouterwidth"]  = ProtoField.new  ("Border Outer Width", "atem.field.borderouterwidth", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_borderinnerwidth"]  = ProtoField.new  ("Border Inner Width", "atem.field.borderinnerwidth", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_borderoutersoftness"]   = ProtoField.new  ("Border Outer Softness", "atem.field.borderoutersoftness", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_borderinnersoftness"]   = ProtoField.new  ("Border Inner Softness", "atem.field.borderinnersoftness", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_borderbevelsoftness"]   = ProtoField.new  ("Border Bevel Softness", "atem.field.borderbevelsoftness", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_borderbevelposition"]   = ProtoField.new  ("Border Bevel Position", "atem.field.borderbevelposition", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_borderopacity"] = ProtoField.new  ("Border Opacity", "atem.field.borderopacity", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_borderhue"] = ProtoField.new  ("Border Hue", "atem.field.borderhue", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_bordersaturation"]  = ProtoField.new  ("Border Saturation", "atem.field.bordersaturation", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_borderluma"]    = ProtoField.new  ("Border Luma", "atem.field.borderluma", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_lightsourcedirection"]  = ProtoField.new  ("Light Source Direction", "atem.field.lightsourcedirection", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_lightsourcealtitude"]   = ProtoField.new  ("Light Source Altitude", "atem.field.lightsourcealtitude", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_ckdv_setmask12"]  = ProtoField.new  ("Set Mask", "atem.cmd.ckdv.setmask12", ftypes.UINT32, nil, base.DEC, 0xFFFFFFFF)
pf_fields["pf_flag_cmd_ckdv_setmask12_sizex"] = ProtoField.new ("Size X", "atem.cmd.ckdv.setmask12.flags.sizex", ftypes.BOOLEAN, {"On","Off"}, 26, 0x1)
pf_fields["pf_flag_cmd_ckdv_setmask12_sizey"] = ProtoField.new ("Size Y", "atem.cmd.ckdv.setmask12.flags.sizey", ftypes.BOOLEAN, {"On","Off"}, 26, 0x2)
pf_fields["pf_flag_cmd_ckdv_setmask12_positionx"] = ProtoField.new ("Position X", "atem.cmd.ckdv.setmask12.flags.positionx", ftypes.BOOLEAN, {"On","Off"}, 26, 0x4)
pf_fields["pf_flag_cmd_ckdv_setmask12_positiony"] = ProtoField.new ("Position Y", "atem.cmd.ckdv.setmask12.flags.positiony", ftypes.BOOLEAN, {"On","Off"}, 26, 0x8)
pf_fields["pf_flag_cmd_ckdv_setmask12_rotation"] = ProtoField.new ("Rotation", "atem.cmd.ckdv.setmask12.flags.rotation", ftypes.BOOLEAN, {"On","Off"}, 26, 0x10)
pf_fields["pf_flag_cmd_ckdv_setmask12_borderenabled"] = ProtoField.new ("Border Enabled", "atem.cmd.ckdv.setmask12.flags.borderenabled", ftypes.BOOLEAN, {"On","Off"}, 26, 0x20)
pf_fields["pf_flag_cmd_ckdv_setmask12_shadow"] = ProtoField.new ("Shadow", "atem.cmd.ckdv.setmask12.flags.shadow", ftypes.BOOLEAN, {"On","Off"}, 26, 0x40)
pf_fields["pf_flag_cmd_ckdv_setmask12_borderbevel"] = ProtoField.new ("Border Bevel", "atem.cmd.ckdv.setmask12.flags.borderbevel", ftypes.BOOLEAN, {"On","Off"}, 26, 0x80)
pf_fields["pf_flag_cmd_ckdv_setmask12_outerwidth"] = ProtoField.new ("Outer Width", "atem.cmd.ckdv.setmask12.flags.outerwidth", ftypes.BOOLEAN, {"On","Off"}, 26, 0x100)
pf_fields["pf_flag_cmd_ckdv_setmask12_innerwidth"] = ProtoField.new ("Inner Width", "atem.cmd.ckdv.setmask12.flags.innerwidth", ftypes.BOOLEAN, {"On","Off"}, 26, 0x200)
pf_fields["pf_flag_cmd_ckdv_setmask12_outersoftness"] = ProtoField.new ("Outer Softness", "atem.cmd.ckdv.setmask12.flags.outersoftness", ftypes.BOOLEAN, {"On","Off"}, 26, 0x400)
pf_fields["pf_flag_cmd_ckdv_setmask12_innersoftness"] = ProtoField.new ("Inner Softness", "atem.cmd.ckdv.setmask12.flags.innersoftness", ftypes.BOOLEAN, {"On","Off"}, 26, 0x800)
pf_fields["pf_flag_cmd_ckdv_setmask12_bevelsoftness"] = ProtoField.new ("Bevel Softness", "atem.cmd.ckdv.setmask12.flags.bevelsoftness", ftypes.BOOLEAN, {"On","Off"}, 26, 0x1000)
pf_fields["pf_flag_cmd_ckdv_setmask12_bevelposition"] = ProtoField.new ("Bevel Position", "atem.cmd.ckdv.setmask12.flags.bevelposition", ftypes.BOOLEAN, {"On","Off"}, 26, 0x2000)
pf_fields["pf_flag_cmd_ckdv_setmask12_borderopacity"] = ProtoField.new ("Border Opacity", "atem.cmd.ckdv.setmask12.flags.borderopacity", ftypes.BOOLEAN, {"On","Off"}, 26, 0x4000)
pf_fields["pf_flag_cmd_ckdv_setmask12_borderhue"] = ProtoField.new ("Border Hue", "atem.cmd.ckdv.setmask12.flags.borderhue", ftypes.BOOLEAN, {"On","Off"}, 26, 0x8000)
pf_fields["pf_flag_cmd_ckdv_setmask12_bordersaturation"] = ProtoField.new ("Border Saturation", "atem.cmd.ckdv.setmask12.flags.bordersaturation", ftypes.BOOLEAN, {"On","Off"}, 26, 0x10000)
pf_fields["pf_flag_cmd_ckdv_setmask12_borderluma"] = ProtoField.new ("Border Luma", "atem.cmd.ckdv.setmask12.flags.borderluma", ftypes.BOOLEAN, {"On","Off"}, 26, 0x20000)
pf_fields["pf_flag_cmd_ckdv_setmask12_direction"] = ProtoField.new ("Direction", "atem.cmd.ckdv.setmask12.flags.direction", ftypes.BOOLEAN, {"On","Off"}, 26, 0x40000)
pf_fields["pf_flag_cmd_ckdv_setmask12_altitude"] = ProtoField.new ("Altitude", "atem.cmd.ckdv.setmask12.flags.altitude", ftypes.BOOLEAN, {"On","Off"}, 26, 0x80000)
pf_fields["pf_flag_cmd_ckdv_setmask12_masked"] = ProtoField.new ("Masked", "atem.cmd.ckdv.setmask12.flags.masked", ftypes.BOOLEAN, {"On","Off"}, 26, 0x100000)
pf_fields["pf_flag_cmd_ckdv_setmask12_top"] = ProtoField.new ("Top", "atem.cmd.ckdv.setmask12.flags.top", ftypes.BOOLEAN, {"On","Off"}, 26, 0x200000)
pf_fields["pf_flag_cmd_ckdv_setmask12_bottom"] = ProtoField.new ("Bottom", "atem.cmd.ckdv.setmask12.flags.bottom", ftypes.BOOLEAN, {"On","Off"}, 26, 0x400000)
pf_fields["pf_flag_cmd_ckdv_setmask12_left"] = ProtoField.new ("Left", "atem.cmd.ckdv.setmask12.flags.left", ftypes.BOOLEAN, {"On","Off"}, 26, 0x800000)
pf_fields["pf_flag_cmd_ckdv_setmask12_right"] = ProtoField.new ("Right", "atem.cmd.ckdv.setmask12.flags.right", ftypes.BOOLEAN, {"On","Off"}, 26, 0x1000000)
pf_fields["pf_flag_cmd_ckdv_setmask12_rate"] = ProtoField.new ("Rate", "atem.cmd.ckdv.setmask12.flags.rate", ftypes.BOOLEAN, {"On","Off"}, 26, 0x2000000)

VALS["VALS_KEFS_ISASET"] = {[0] = "No", [1] = "Yes"}
pf_fields["pf_cmd_kefs_isaset"] = ProtoField.new  ("IsASet", "atem.cmd.kefs.isaset", ftypes.UINT8, VALS["VALS_KEFS_ISASET"], base.DEC)

VALS["VALS_KEFS_ISBSET"] = {[0] = "No", [1] = "Yes"}
pf_fields["pf_cmd_kefs_isbset"] = ProtoField.new  ("IsBSet", "atem.cmd.kefs.isbset", ftypes.UINT8, VALS["VALS_KEFS_ISBSET"], base.DEC)

pf_fields["pf_cmd_kefs_isatkeyframe"]   = ProtoField.new  ("Is At Key Frame", "atem.cmd.kefs.isatkeyframe", ftypes.UINT8, nil, base.DEC, 0xF)
pf_fields["pf_flag_cmd_kefs_isatkeyframe_a"] = ProtoField.new ("A", "atem.cmd.kefs.isatkeyframe.flags.a", ftypes.BOOLEAN, {"Yes","No"}, 4, 0x1)
pf_fields["pf_flag_cmd_kefs_isatkeyframe_b"] = ProtoField.new ("B", "atem.cmd.kefs.isatkeyframe.flags.b", ftypes.BOOLEAN, {"Yes","No"}, 4, 0x2)
pf_fields["pf_flag_cmd_kefs_isatkeyframe_full"] = ProtoField.new ("Full", "atem.cmd.kefs.isatkeyframe.flags.full", ftypes.BOOLEAN, {"Yes","No"}, 4, 0x4)
pf_fields["pf_flag_cmd_kefs_isatkeyframe_runtoinfinite"] = ProtoField.new ("Run-to-infinite", "atem.cmd.kefs.isatkeyframe.flags.runtoinfinite", ftypes.BOOLEAN, {"Yes","No"}, 4, 0x8)

pf_fields["pf_field_runtoinfiniteindex"]    = ProtoField.new  ("Run-to-Infinite-index", "atem.field.runtoinfiniteindex", ftypes.UINT8, nil, base.DEC)
VALS["VALS_KEYFRAME0"] = {[1] = "A", [2] = "B"}
pf_fields["pf_field_keyframe0"] = ProtoField.new  ("Key Frame", "atem.field.keyframe0", ftypes.UINT8, VALS["VALS_KEYFRAME0"], base.DEC)

pf_fields["pf_cmd_rflk_setmask13"]  = ProtoField.new  ("Set Mask", "atem.cmd.rflk.setmask13", ftypes.UINT8, nil, base.DEC, 0x3)
pf_fields["pf_flag_cmd_rflk_setmask13_onoff"] = ProtoField.new ("On/Off", "atem.cmd.rflk.setmask13.flags.onoff", ftypes.BOOLEAN, {"On","Off"}, 2, 0x1)
pf_fields["pf_flag_cmd_rflk_setmask13_runtoinfinite"] = ProtoField.new ("Run-To-Infinite", "atem.cmd.rflk.setmask13.flags.runtoinfinite", ftypes.BOOLEAN, {"On","Off"}, 2, 0x2)

VALS["VALS_RFLK_KEYFRAME1"] = {[1] = "A", [2] = "B", [3] = "Full", [4] = "Run-To-Infinite"}
pf_fields["pf_cmd_rflk_keyframe1"]  = ProtoField.new  ("Key Frame", "atem.cmd.rflk.keyframe1", ftypes.UINT8, VALS["VALS_RFLK_KEYFRAME1"], base.DEC)

VALS["VALS_KEYER1"] = {[0] = "DSK1", [1] = "DSK2"}
pf_fields["pf_field_keyer1"]    = ProtoField.new  ("Keyer", "atem.field.keyer1", ftypes.UINT8, VALS["VALS_KEYER1"], base.DEC)

VALS["VALS_TIE"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_tie"]   = ProtoField.new  ("Tie", "atem.field.tie", ftypes.UINT8, VALS["VALS_TIE"], base.DEC)

pf_fields["pf_cmd_cdsg_setmask14"]  = ProtoField.new  ("Set Mask", "atem.cmd.cdsg.setmask14", ftypes.UINT8, nil, base.DEC, 0x7)
pf_fields["pf_flag_cmd_cdsg_setmask14_premultiplied"] = ProtoField.new ("Pre Multiplied", "atem.cmd.cdsg.setmask14.flags.premultiplied", ftypes.BOOLEAN, {"On","Off"}, 3, 0x1)
pf_fields["pf_flag_cmd_cdsg_setmask14_clip"] = ProtoField.new ("Clip", "atem.cmd.cdsg.setmask14.flags.clip", ftypes.BOOLEAN, {"On","Off"}, 3, 0x2)
pf_fields["pf_flag_cmd_cdsg_setmask14_gain"] = ProtoField.new ("Gain", "atem.cmd.cdsg.setmask14.flags.gain", ftypes.BOOLEAN, {"On","Off"}, 3, 0x4)

VALS["VALS_CDSG_INVERTKEY1"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_cmd_cdsg_invertkey1"] = ProtoField.new  ("Invert Key(??)", "atem.cmd.cdsg.invertkey1", ftypes.UINT8, VALS["VALS_CDSG_INVERTKEY1"], base.DEC)

VALS["VALS_ONAIR"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_onair"] = ProtoField.new  ("On Air", "atem.field.onair", ftypes.UINT8, VALS["VALS_ONAIR"], base.DEC)

VALS["VALS_INTRANSITION1"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_intransition1"] = ProtoField.new  ("In Transition", "atem.field.intransition1", ftypes.UINT8, VALS["VALS_INTRANSITION1"], base.DEC)

VALS["VALS_DSKS_ISAUTOTRANSITIONING"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_cmd_dsks_isautotransitioning"]    = ProtoField.new  ("Is Auto Transitioning", "atem.cmd.dsks.isautotransitioning", ftypes.UINT8, VALS["VALS_DSKS_ISAUTOTRANSITIONING"], base.DEC)

VALS["VALS_FTBC_SETMASK15"] = {[0] = "Rate"}
pf_fields["pf_cmd_ftbc_setmask15"]  = ProtoField.new  ("Set Mask", "atem.cmd.ftbc.setmask15", ftypes.UINT8, VALS["VALS_FTBC_SETMASK15"], base.DEC)

VALS["VALS_FTBS_FULLYBLACK"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_cmd_ftbs_fullyblack"] = ProtoField.new  ("Fully Black", "atem.cmd.ftbs.fullyblack", ftypes.UINT8, VALS["VALS_FTBS_FULLYBLACK"], base.DEC)

VALS["VALS_COLORGENERATOR"] = {[0] = "Color Generator 1", [1] = "Color Generator 2"}
pf_fields["pf_field_colorgenerator"]    = ProtoField.new  ("Color Generator", "atem.field.colorgenerator", ftypes.UINT8, VALS["VALS_COLORGENERATOR"], base.DEC)

pf_fields["pf_field_saturation0"]   = ProtoField.new  ("Saturation", "atem.field.saturation0", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_luma"]  = ProtoField.new  ("Luma", "atem.field.luma", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_cclv_setmask16"]  = ProtoField.new  ("Set Mask", "atem.cmd.cclv.setmask16", ftypes.UINT8, nil, base.DEC, 0x7)
pf_fields["pf_flag_cmd_cclv_setmask16_hue"] = ProtoField.new ("Hue", "atem.cmd.cclv.setmask16.flags.hue", ftypes.BOOLEAN, {"On","Off"}, 3, 0x1)
pf_fields["pf_flag_cmd_cclv_setmask16_saturation"] = ProtoField.new ("Saturation", "atem.cmd.cclv.setmask16.flags.saturation", ftypes.BOOLEAN, {"On","Off"}, 3, 0x2)
pf_fields["pf_flag_cmd_cclv_setmask16_luma"] = ProtoField.new ("Luma", "atem.cmd.cclv.setmask16.flags.luma", ftypes.BOOLEAN, {"On","Off"}, 3, 0x4)

VALS["VALS_AUXCHANNEL"] = {[0] = "AUX 1", [1] = "AUX 2", [2] = "AUX 3", [3] = "AUX 4", [4] = "AUX 5", [5] = "AUX 6"}
pf_fields["pf_field_auxchannel"]    = ProtoField.new  ("AUX Channel", "atem.field.auxchannel", ftypes.UINT8, VALS["VALS_AUXCHANNEL"], base.DEC)

VALS["VALS_SETMASK17"] = {[0] = "Source"}
pf_fields["pf_field_setmask17"] = ProtoField.new  ("Set Mask", "atem.field.setmask17", ftypes.UINT8, VALS["VALS_SETMASK17"], base.DEC)

pf_fields["pf_field_input1"]    = ProtoField.new  ("Input", "atem.field.input1", ftypes.UINT8, nil, base.DEC)
VALS["VALS_ADJUSTMENTDOMAIN"] = {[0] = "Lens", [1] = "Camera", [8] = "Chip"}
pf_fields["pf_field_adjustmentdomain"]  = ProtoField.new  ("Adjustment Domain", "atem.field.adjustmentdomain", ftypes.UINT8, VALS["VALS_ADJUSTMENTDOMAIN"], base.DEC)

VALS["VALS_CCDO_LENSFEATURE0"] = {[0] = "Focus", [1] = "Auto Focused", [3] = "Iris"}
pf_fields["pf_cmd_ccdo_lensfeature0"]   = ProtoField.new  ("Lens feature", "atem.cmd.ccdo.lensfeature0", ftypes.UINT8, VALS["VALS_CCDO_LENSFEATURE0"], base.DEC)

VALS["VALS_CCDO_CAMERAFEATURE0"] = {[1] = "Gain", [5] = "Shutter"}
pf_fields["pf_cmd_ccdo_camerafeature0"] = ProtoField.new  ("Camera feature", "atem.cmd.ccdo.camerafeature0", ftypes.UINT8, VALS["VALS_CCDO_CAMERAFEATURE0"], base.DEC)

VALS["VALS_CHIPFEATURE"] = {[0] = "Lift", [1] = "Gamma", [2] = "Gain", [3] = "Aperture", [4] = "Contrast", [5] = "Lum", [6] = "Hue-Saturation"}
pf_fields["pf_field_chipfeature"]   = ProtoField.new  ("Chip feature", "atem.field.chipfeature", ftypes.UINT8, VALS["VALS_CHIPFEATURE"], base.DEC)

VALS["VALS_CCDO_AVAILABLE"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_cmd_ccdo_available"]  = ProtoField.new  ("Available", "atem.cmd.ccdo.available", ftypes.UINT8, VALS["VALS_CCDO_AVAILABLE"], base.DEC)

VALS["VALS_LENSFEATURE1"] = {[0] = "Focus", [1] = "Auto Focused", [3] = "Iris", [9] = "Zoom"}
pf_fields["pf_field_lensfeature1"]  = ProtoField.new  ("Lens feature", "atem.field.lensfeature1", ftypes.UINT8, VALS["VALS_LENSFEATURE1"], base.DEC)

VALS["VALS_CAMERAFEATURE1"] = {[1] = "Gain", [2] = "White Balance", [5] = "Shutter"}
pf_fields["pf_field_camerafeature1"]    = ProtoField.new  ("Camera feature", "atem.field.camerafeature1", ftypes.UINT8, VALS["VALS_CAMERAFEATURE1"], base.DEC)

pf_fields["pf_cmd_ccdp_unknown4"]   = ProtoField.new  ("Unknown", "atem.cmd.ccdp.unknown4", ftypes.NONE, nil, base.NONE)
pf_fields["pf_field_iris"]  = ProtoField.new  ("Iris", "atem.field.iris", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_focus"] = ProtoField.new  ("Focus", "atem.field.focus", ftypes.INT16, nil, base.DEC)
VALS["VALS_GAIN1"] = {[512] = "0db", [1024] = "6db", [2048] = "12db", [4096] = "18db"}
pf_fields["pf_field_gain1"] = ProtoField.new  ("Gain", "atem.field.gain1", ftypes.INT16, VALS["VALS_GAIN1"], base.DEC)

VALS["VALS_WHITEBALANCE"] = {[3200] = "3200K", [4500] = "4500K", [5000] = "5000K", [5600] = "5600K", [6500] = "6500K", [7500] = "7500K"}
pf_fields["pf_field_whitebalance"]  = ProtoField.new  ("White Balance", "atem.field.whitebalance", ftypes.INT16, VALS["VALS_WHITEBALANCE"], base.DEC)

pf_fields["pf_field_zoomspeed"] = ProtoField.new  ("Zoom Speed", "atem.field.zoomspeed", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_liftr"] = ProtoField.new  ("Lift R", "atem.field.liftr", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_gammar"]    = ProtoField.new  ("Gamma R", "atem.field.gammar", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_gainr"] = ProtoField.new  ("Gain R", "atem.field.gainr", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_lummix"]    = ProtoField.new  ("Lum Mix", "atem.field.lummix", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_hue1"]  = ProtoField.new  ("Hue", "atem.field.hue1", ftypes.INT16, nil, base.DEC)
VALS["VALS_SHUTTER"] = {[20000] = "1/50", [16667] = "1/60", [13333] = "1/75", [11111] = "1/90", [10000] = "1/100", [8333] = "1/120", [6667] = "1/150", [5556] = "1/180", [4000] = "1/250", [2778] = "1/360", [2000] = "1/500", [1379] = "1/725", [1000] = "1/1000", [690] = "1/1450", [500] = "1/2000"}
pf_fields["pf_field_shutter"]   = ProtoField.new  ("Shutter", "atem.field.shutter", ftypes.INT16, VALS["VALS_SHUTTER"], base.DEC)

pf_fields["pf_field_liftg"] = ProtoField.new  ("Lift G", "atem.field.liftg", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_gammag"]    = ProtoField.new  ("Gamma G", "atem.field.gammag", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_gaing"] = ProtoField.new  ("Gain G", "atem.field.gaing", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_contrast"]  = ProtoField.new  ("Contrast", "atem.field.contrast", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_saturation1"]   = ProtoField.new  ("Saturation", "atem.field.saturation1", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_liftb"] = ProtoField.new  ("Lift B", "atem.field.liftb", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_gammab"]    = ProtoField.new  ("Gamma B", "atem.field.gammab", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_gainb"] = ProtoField.new  ("Gain B", "atem.field.gainb", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_lifty"] = ProtoField.new  ("Lift Y", "atem.field.lifty", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_gammay"]    = ProtoField.new  ("Gamma Y", "atem.field.gammay", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_gainy"] = ProtoField.new  ("Gain Y", "atem.field.gainy", ftypes.INT16, nil, base.DEC)
VALS["VALS_CCMD_RELATIVE"] = {[0] = "Off", [1] = "?"}
pf_fields["pf_cmd_ccmd_relative"]   = ProtoField.new  ("Relative", "atem.cmd.ccmd.relative", ftypes.UINT8, VALS["VALS_CCMD_RELATIVE"], base.DEC)

pf_fields["pf_field_unknown5"]  = ProtoField.new  ("Unknown", "atem.field.unknown5", ftypes.NONE, nil, base.NONE)
VALS["VALS_MEDIAPLAYER"] = {[0] = "Media Player 1", [1] = "Media Player 2"}
pf_fields["pf_field_mediaplayer"]   = ProtoField.new  ("Media Player", "atem.field.mediaplayer", ftypes.UINT8, VALS["VALS_MEDIAPLAYER"], base.DEC)

VALS["VALS_PLAYING"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_playing"]   = ProtoField.new  ("Playing", "atem.field.playing", ftypes.UINT8, VALS["VALS_PLAYING"], base.DEC)

VALS["VALS_LOOP"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_loop"]  = ProtoField.new  ("Loop", "atem.field.loop", ftypes.UINT8, VALS["VALS_LOOP"], base.DEC)

VALS["VALS_ATBEGINNING"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_atbeginning"]   = ProtoField.new  ("At Beginning", "atem.field.atbeginning", ftypes.UINT8, VALS["VALS_ATBEGINNING"], base.DEC)

pf_fields["pf_field_clipframe"] = ProtoField.new  ("Clip Frame", "atem.field.clipframe", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_scps_setmask18"]  = ProtoField.new  ("Set Mask", "atem.cmd.scps.setmask18", ftypes.UINT8, nil, base.DEC, 0xF)
pf_fields["pf_flag_cmd_scps_setmask18_playing"] = ProtoField.new ("Playing", "atem.cmd.scps.setmask18.flags.playing", ftypes.BOOLEAN, {"On","Off"}, 4, 0x1)
pf_fields["pf_flag_cmd_scps_setmask18_loop"] = ProtoField.new ("Loop", "atem.cmd.scps.setmask18.flags.loop", ftypes.BOOLEAN, {"On","Off"}, 4, 0x2)
pf_fields["pf_flag_cmd_scps_setmask18_beginning"] = ProtoField.new ("Beginning", "atem.cmd.scps.setmask18.flags.beginning", ftypes.BOOLEAN, {"On","Off"}, 4, 0x4)
pf_fields["pf_flag_cmd_scps_setmask18_frame"] = ProtoField.new ("Frame", "atem.cmd.scps.setmask18.flags.frame", ftypes.BOOLEAN, {"On","Off"}, 4, 0x8)

VALS["VALS_TYPE1"] = {[1] = "Still", [2] = "Clip"}
pf_fields["pf_field_type1"] = ProtoField.new  ("Type", "atem.field.type1", ftypes.UINT8, VALS["VALS_TYPE1"], base.DEC)

pf_fields["pf_field_stillindex"]    = ProtoField.new  ("Still Index", "atem.field.stillindex", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_clipindex"] = ProtoField.new  ("Clip Index", "atem.field.clipindex", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_mpss_setmask19"]  = ProtoField.new  ("Set Mask", "atem.cmd.mpss.setmask19", ftypes.UINT8, nil, base.DEC, 0x7)
pf_fields["pf_flag_cmd_mpss_setmask19_type"] = ProtoField.new ("Type", "atem.cmd.mpss.setmask19.flags.type", ftypes.BOOLEAN, {"On","Off"}, 3, 0x1)
pf_fields["pf_flag_cmd_mpss_setmask19_still"] = ProtoField.new ("Still", "atem.cmd.mpss.setmask19.flags.still", ftypes.BOOLEAN, {"On","Off"}, 3, 0x2)
pf_fields["pf_flag_cmd_mpss_setmask19_clip"] = ProtoField.new ("Clip", "atem.cmd.mpss.setmask19.flags.clip", ftypes.BOOLEAN, {"On","Off"}, 3, 0x4)

pf_fields["pf_field_clip1maxlength"]    = ProtoField.new  ("Clip 1 Max Length", "atem.field.clip1maxlength", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_mpsp_clip2maxlength"] = ProtoField.new  ("Clip 2 Max Length", "atem.cmd.mpsp.clip2maxlength", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_clipbank"]  = ProtoField.new  ("Clip Bank", "atem.field.clipbank", ftypes.UINT8, nil, base.DEC)
VALS["VALS_ISUSED"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_isused"]    = ProtoField.new  ("Is Used", "atem.field.isused", ftypes.UINT8, VALS["VALS_ISUSED"], base.DEC)

VALS["VALS_TRANSFER_TYPE"] = {[0] = "Still", [1] = "Clip 1", [2] = "Clip 2", [3] = "MV labels", [255] = "Macro"}

pf_fields["pf_field_filename"]  = ProtoField.new  ("File Name", "atem.field.filename", ftypes.STRING, nil, base.NONE)
pf_fields["pf_field_frames"]    = ProtoField.new  ("Frames", "atem.field.frames", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_mpas_hash"]    = ProtoField.new  ("Hash (of audio)", "atem.cmd.mpas.hash", ftypes.BYTES)
pf_fields["pf_cmd_mpfe_type"]    = ProtoField.new  ("Type", "atem.cmd.mpfe.type", ftypes.UINT8, VALS["VALS_TRANSFER_TYPE"], base.DEC)
pf_fields["pf_cmd_mpfe_index"]  = ProtoField.new  ("Index", "atem.cmd.mpfe.index", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_mpfe_hash"]    = ProtoField.new  ("Hash (of still)", "atem.cmd.mpfe.hash", ftypes.BYTES)
pf_fields["pf_cmd_mpfe_filenamestringlength"]   = ProtoField.new  ("(File Name String Length)", "atem.cmd.mpfe.filenamestringlength", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_mrpr_state"]  = ProtoField.new  ("State", "atem.cmd.mrpr.state", ftypes.UINT8, nil, base.DEC, 0x3)
pf_fields["pf_flag_cmd_mrpr_state_running"] = ProtoField.new ("Running", "atem.cmd.mrpr.state.flags.running", ftypes.BOOLEAN, {"On","Off"}, 2, 0x1)
pf_fields["pf_flag_cmd_mrpr_state_waiting"] = ProtoField.new ("Waiting", "atem.cmd.mrpr.state.flags.waiting", ftypes.BOOLEAN, {"On","Off"}, 2, 0x2)

VALS["VALS_MRPR_ISLOOPING"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_cmd_mrpr_islooping"]  = ProtoField.new  ("Is Looping", "atem.cmd.mrpr.islooping", ftypes.UINT8, VALS["VALS_MRPR_ISLOOPING"], base.DEC)

pf_fields["pf_field_index0"]    = ProtoField.new  ("Index", "atem.field.index0", ftypes.UINT16, nil, base.DEC)
VALS["VALS_MACT_ACTION"] = {[0] = "Run Macro", [1] = "Stop (w/Index 0xFFFF)", [2] = "Stop Recording (w/Index 0xFFFF)", [3] = "Insert Wait for User (w/Index 0xFFFF)", [4] = "Continue (w/Index 0xFFFF)", [5] = "Delete Macro"}
pf_fields["pf_cmd_mact_action"] = ProtoField.new  ("Action", "atem.cmd.mact.action", ftypes.UINT8, VALS["VALS_MACT_ACTION"], base.DEC)

VALS["VALS_MRCP_SETMASK20"] = {[0] = "Looping"}
pf_fields["pf_cmd_mrcp_setmask20"]  = ProtoField.new  ("Set Mask", "atem.cmd.mrcp.setmask20", ftypes.UINT8, VALS["VALS_MRCP_SETMASK20"], base.DEC)

VALS["VALS_MRCP_LOOPING"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_cmd_mrcp_looping"]    = ProtoField.new  ("Looping", "atem.cmd.mrcp.looping", ftypes.UINT8, VALS["VALS_MRCP_LOOPING"], base.DEC)

pf_fields["pf_cmd_mprp_macroindex"] = ProtoField.new  ("Macro Index", "atem.cmd.mprp.macroindex", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_field_namestringlength"]  = ProtoField.new  ("(Name String Length)", "atem.field.namestringlength", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_descriptionstringlength"]   = ProtoField.new  ("(Description String Length)", "atem.field.descriptionstringlength", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_mprp_name1"]  = ProtoField.new  ("Name", "atem.cmd.mprp.name1", ftypes.STRING, nil, base.NONE)
pf_fields["pf_field_description"]   = ProtoField.new  ("Description", "atem.field.description", ftypes.STRING, nil, base.NONE)
pf_fields["pf_cmd_cmpr_setmask21"]  = ProtoField.new  ("Set Mask", "atem.cmd.cmpr.setmask21", ftypes.UINT8, nil, base.DEC, 0xFF)
pf_fields["pf_flag_cmd_cmpr_setmask21_name"] = ProtoField.new ("Name", "atem.cmd.cmpr.setmask21.flags.name", ftypes.BOOLEAN, {"On","Off"}, 2, 0x1)
pf_fields["pf_flag_cmd_cmpr_setmask21_description"] = ProtoField.new ("Description", "atem.cmd.cmpr.setmask21.flags.description", ftypes.BOOLEAN, {"On","Off"}, 2, 0x2)

pf_fields["pf_field_name2"] = ProtoField.new  ("Name", "atem.field.name2", ftypes.STRING, nil, base.NONE)
pf_fields["pf_cmd_msrc_index1"] = ProtoField.new  ("Index", "atem.cmd.msrc.index1", ftypes.UINT8, nil, base.DEC)
VALS["VALS_MRCS_ISRECORDING"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_cmd_mrcs_isrecording"]    = ProtoField.new  ("Is Recording", "atem.cmd.mrcs.isrecording", ftypes.UINT8, VALS["VALS_MRCS_ISRECORDING"], base.DEC)

VALS["VALS_FOREGROUND"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_foreground"]    = ProtoField.new  ("Foreground", "atem.field.foreground", ftypes.UINT8, VALS["VALS_FOREGROUND"], base.DEC)

pf_fields["pf_cmd_cssc_setmask22"]  = ProtoField.new  ("Set Mask", "atem.cmd.cssc.setmask22", ftypes.UINT8, nil, base.DEC, 0xFF)
pf_fields["pf_flag_cmd_cssc_setmask22_fillsource"] = ProtoField.new ("Fill Source", "atem.cmd.cssc.setmask22.flags.fillsource", ftypes.BOOLEAN, {"On","Off"}, 20, 0x1)
pf_fields["pf_flag_cmd_cssc_setmask22_keysource"] = ProtoField.new ("Key Source", "atem.cmd.cssc.setmask22.flags.keysource", ftypes.BOOLEAN, {"On","Off"}, 20, 0x2)
pf_fields["pf_flag_cmd_cssc_setmask22_foreground"] = ProtoField.new ("Foreground", "atem.cmd.cssc.setmask22.flags.foreground", ftypes.BOOLEAN, {"On","Off"}, 20, 0x4)
pf_fields["pf_flag_cmd_cssc_setmask22_premultiplied"] = ProtoField.new ("Pre Multiplied", "atem.cmd.cssc.setmask22.flags.premultiplied", ftypes.BOOLEAN, {"On","Off"}, 20, 0x8)
pf_fields["pf_flag_cmd_cssc_setmask22_clip"] = ProtoField.new ("Clip", "atem.cmd.cssc.setmask22.flags.clip", ftypes.BOOLEAN, {"On","Off"}, 20, 0x10)
pf_fields["pf_flag_cmd_cssc_setmask22_gain"] = ProtoField.new ("Gain", "atem.cmd.cssc.setmask22.flags.gain", ftypes.BOOLEAN, {"On","Off"}, 20, 0x20)
pf_fields["pf_flag_cmd_cssc_setmask22_invert"] = ProtoField.new ("Invert", "atem.cmd.cssc.setmask22.flags.invert", ftypes.BOOLEAN, {"On","Off"}, 20, 0x40)

pf_fields["pf_cmd_csbd_setmask22"]  = ProtoField.new  ("Set Mask", "atem.cmd.csbd.setmask22", ftypes.UINT16, nil, base.DEC, 0xFFFF)
pf_fields["pf_flag_cmd_cssc_setmask22_enabled"] = ProtoField.new ("Enabled", "atem.cmd.csbd.setmask22.flags.enabled", ftypes.BOOLEAN, {"On","Off"}, 20, 0x1)
pf_fields["pf_flag_cmd_cssc_setmask22_bevel"] = ProtoField.new ("Bevel", "atem.cmd.cssc.setmask22.flags.bevel", ftypes.BOOLEAN, {"On","Off"}, 20, 0x2)
pf_fields["pf_flag_cmd_cssc_setmask22_outerwidth"] = ProtoField.new ("Outer Width", "atem.cmd.cssc.setmask22.flags.outerwidth", ftypes.BOOLEAN, {"On","Off"}, 20, 0x4)
pf_fields["pf_flag_cmd_cssc_setmask22_innerwidth"] = ProtoField.new ("Inner Width", "atem.cmd.cssc.setmask22.flags.innerwidth", ftypes.BOOLEAN, {"On","Off"}, 20, 0x8)
pf_fields["pf_flag_cmd_cssc_setmask22_outersoftness"] = ProtoField.new ("Outer Softness", "atem.cmd.cssc.setmask22.flags.outersoftness", ftypes.BOOLEAN, {"On","Off"}, 20, 0x10)
pf_fields["pf_flag_cmd_cssc_setmask22_innersoftness"] = ProtoField.new ("Inner Softness", "atem.cmd.cssc.setmask22.flags.innersoftness", ftypes.BOOLEAN, {"On","Off"}, 20, 0x20)
pf_fields["pf_flag_cmd_cssc_setmask22_bevelsoftness"] = ProtoField.new ("Bevel Softness", "atem.cmd.cssc.setmask22.flags.bevelsoftness", ftypes.BOOLEAN, {"On","Off"}, 20, 0x40)
pf_fields["pf_flag_cmd_cssc_setmask22_bevelpos"] = ProtoField.new ("Bevel Pos", "atem.cmd.cssc.setmask22.flags.bevelpos", ftypes.BOOLEAN, {"On","Off"}, 20, 0x80)
pf_fields["pf_flag_cmd_cssc_setmask22_hue"] = ProtoField.new ("Hue", "atem.cmd.cssc.setmask22.flags.hue", ftypes.BOOLEAN, {"On","Off"}, 20, 0x100)
pf_fields["pf_flag_cmd_cssc_setmask22_saturation"] = ProtoField.new ("Saturation", "atem.cmd.cssc.setmask22.flags.saturation", ftypes.BOOLEAN, {"On","Off"}, 20, 0x200)
pf_fields["pf_flag_cmd_cssc_setmask22_luma"] = ProtoField.new ("Luma", "atem.cmd.cssc.setmask22.flags.luma", ftypes.BOOLEAN, {"On","Off"}, 20, 0x400)
pf_fields["pf_flag_cmd_cssc_setmask22_direction"] = ProtoField.new ("Direction", "atem.cmd.cssc.setmask22.flags.direction", ftypes.BOOLEAN, {"On","Off"}, 20, 0x800)
pf_fields["pf_flag_cmd_cssc_setmask22_altitude"] = ProtoField.new ("Altitude", "atem.cmd.cssc.setmask22.flags.altitude", ftypes.BOOLEAN, {"On","Off"}, 20, 0x1000)

VALS["VALS_BOX"] = {[0] = "Box 1", [1] = "Box 2", [2] = "Box 3", [3] = "Box 4"}
pf_fields["pf_field_box"]   = ProtoField.new  ("Box", "atem.field.box", ftypes.UINT8, VALS["VALS_BOX"], base.DEC)

VALS["VALS_INPUTSOURCE0"] = {[0] = "Black", [1] = "Input 1", [2] = "Input 2", [3] = "Input 3", [4] = "Input 4", [5] = "Input 5", [6] = "Input 6", [7] = "Input 7", [8] = "Input 8", [9] = "Input 9", [10] = "Input 10", [11] = "Input 11", [12] = "Input 12", [13] = "Input 13", [14] = "Input 14", [15] = "Input 15", [16] = "Input 16", [17] = "Input 17", [18] = "Input 18", [19] = "Input 19", [20] = "Input 20", [1000] = "Color Bars", [2001] = "Color 1", [2002] = "Color 2", [3010] = "Media Player 1", [3011] = "Media Player 1 Key", [3020] = "Media Player 2", [3021] = "Media Player 2 Key", [4010] = "Key 1 Mask", [4020] = "Key 2 Mask", [4030] = "Key 3 Mask", [4040] = "Key 4 Mask", [5010] = "DSK 1 Mask", [5020] = "DSK 2 Mask", [6000] = "Super Source", [7001] = "Clean Feed 1", [7002] = "Clean Feed 2", [8001] = "Auxilary 1", [8002] = "Auxilary 2", [8003] = "Auxilary 3", [8004] = "Auxilary 4", [8005] = "Auxilary 5", [8006] = "Auxilary 6", [10010] = "ME 1 Prog", [10011] = "ME 1 Prev", [10020] = "ME 2 Prog", [10021] = "ME 2 Prev"}
pf_fields["pf_field_inputsource0"]  = ProtoField.new  ("Input Source", "atem.field.inputsource0", ftypes.UINT16, VALS["VALS_INPUTSOURCE0"], base.DEC)

pf_fields["pf_field_positionx2"]    = ProtoField.new  ("Position X", "atem.field.positionx2", ftypes.INT16, nil, base.DEC)
pf_fields["pf_field_positiony2"]    = ProtoField.new  ("Position Y", "atem.field.positiony2", ftypes.INT16, nil, base.DEC)
VALS["VALS_CROPPED"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_cropped"]   = ProtoField.new  ("Cropped", "atem.field.cropped", ftypes.UINT8, VALS["VALS_CROPPED"], base.DEC)

pf_fields["pf_field_croptop"]   = ProtoField.new  ("Crop Top", "atem.field.croptop", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_cropbottom"]    = ProtoField.new  ("Crop Bottom", "atem.field.cropbottom", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_cropleft"]  = ProtoField.new  ("Crop Left", "atem.field.cropleft", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_cropright"] = ProtoField.new  ("Crop Right", "atem.field.cropright", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_csbp_setmask23"]  = ProtoField.new  ("Set Mask", "atem.cmd.csbp.setmask23", ftypes.UINT16, nil, base.DEC, 0x3FF)
pf_fields["pf_flag_cmd_csbp_setmask23_enabled"] = ProtoField.new ("Enabled", "atem.cmd.csbp.setmask23.flags.enabled", ftypes.BOOLEAN, {"On","Off"}, 10, 0x1)
pf_fields["pf_flag_cmd_csbp_setmask23_inputsource"] = ProtoField.new ("Input Source", "atem.cmd.csbp.setmask23.flags.inputsource", ftypes.BOOLEAN, {"On","Off"}, 10, 0x2)
pf_fields["pf_flag_cmd_csbp_setmask23_positionx"] = ProtoField.new ("Position X", "atem.cmd.csbp.setmask23.flags.positionx", ftypes.BOOLEAN, {"On","Off"}, 10, 0x4)
pf_fields["pf_flag_cmd_csbp_setmask23_positiony"] = ProtoField.new ("Position Y", "atem.cmd.csbp.setmask23.flags.positiony", ftypes.BOOLEAN, {"On","Off"}, 10, 0x8)
pf_fields["pf_flag_cmd_csbp_setmask23_size"] = ProtoField.new ("Size", "atem.cmd.csbp.setmask23.flags.size", ftypes.BOOLEAN, {"On","Off"}, 10, 0x10)
pf_fields["pf_flag_cmd_csbp_setmask23_cropped"] = ProtoField.new ("Cropped", "atem.cmd.csbp.setmask23.flags.cropped", ftypes.BOOLEAN, {"On","Off"}, 10, 0x20)
pf_fields["pf_flag_cmd_csbp_setmask23_croptop"] = ProtoField.new ("Crop Top", "atem.cmd.csbp.setmask23.flags.croptop", ftypes.BOOLEAN, {"On","Off"}, 10, 0x40)
pf_fields["pf_flag_cmd_csbp_setmask23_cropbottom"] = ProtoField.new ("Crop Bottom", "atem.cmd.csbp.setmask23.flags.cropbottom", ftypes.BOOLEAN, {"On","Off"}, 10, 0x80)
pf_fields["pf_flag_cmd_csbp_setmask23_cropleft"] = ProtoField.new ("Crop Left", "atem.cmd.csbp.setmask23.flags.cropleft", ftypes.BOOLEAN, {"On","Off"}, 10, 0x100)
pf_fields["pf_flag_cmd_csbp_setmask23_cropright"] = ProtoField.new ("Crop Right", "atem.cmd.csbp.setmask23.flags.cropright", ftypes.BOOLEAN, {"On","Off"}, 10, 0x200)

VALS["VALS_AUDIOSOURCE"] = {[1] = "Input 1", [2] = "Input 2", [3] = "Input 3", [4] = "Input 4", [5] = "Input 5", [6] = "Input 6", [7] = "Input 7", [8] = "Input 8", [9] = "Input 9", [10] = "Input 10", [11] = "Input 11", [12] = "Input 12", [13] = "Input 13", [14] = "Input 14", [15] = "Input 15", [16] = "Input 16", [17] = "Input 17", [18] = "Input 18", [19] = "Input 19", [20] = "Input 20", [1001] = "XLR", [1101] = "AES/EBU", [1201] = "RCA", [2001] = "MP1", [2002] = "MP2"}
pf_fields["pf_field_audiosource"]   = ProtoField.new  ("Audio Source", "atem.field.audiosource", ftypes.UINT16, VALS["VALS_AUDIOSOURCE"], base.DEC)

VALS["VALS_AMIP_TYPE2"] = {[0] = "External Video", [1] = "Media Player", [2] = "External Audio"}
pf_fields["pf_cmd_amip_type2"]  = ProtoField.new  ("Type", "atem.cmd.amip.type2", ftypes.UINT8, VALS["VALS_AMIP_TYPE2"], base.DEC)

VALS["VALS_AMIP_FROMMEDIAPLAYER"] = {[0] = "No", [1] = "Yes"}
pf_fields["pf_cmd_amip_frommediaplayer"]    = ProtoField.new  ("From Media Player", "atem.cmd.amip.frommediaplayer", ftypes.UINT8, VALS["VALS_AMIP_FROMMEDIAPLAYER"], base.DEC)

VALS["VALS_AMIP_PLUGTYPE"] = {[0] = "Internal", [1] = "SDI", [2] = "HDMI", [3] = "Component", [4] = "Composite", [5] = "SVideo", [32] = "XLR", [64] = "AES/EBU", [128] = "RCA"}
pf_fields["pf_cmd_amip_plugtype"]   = ProtoField.new  ("Plug type", "atem.cmd.amip.plugtype", ftypes.UINT8, VALS["VALS_AMIP_PLUGTYPE"], base.DEC)

VALS["VALS_MIXOPTION"] = {[0] = "Off", [1] = "On", [2] = "AFV"}
pf_fields["pf_field_mixoption"] = ProtoField.new  ("Mix Option", "atem.field.mixoption", ftypes.UINT8, VALS["VALS_MIXOPTION"], base.DEC)

pf_fields["pf_field_volume"]    = ProtoField.new  ("Volume", "atem.field.volume", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_field_balance"]   = ProtoField.new  ("Balance", "atem.field.balance", ftypes.INT16, nil, base.DEC)
pf_fields["pf_cmd_cami_setmask24"]  = ProtoField.new  ("Set Mask", "atem.cmd.cami.setmask24", ftypes.UINT8, nil, base.DEC, 0xF)
pf_fields["pf_flag_cmd_cami_setmask24_mixoption"] = ProtoField.new ("Mix Option", "atem.cmd.cami.setmask24.flags.mixoption", ftypes.BOOLEAN, {"On","Off"}, 3, 0x1)
pf_fields["pf_flag_cmd_cami_setmask24_volume"] = ProtoField.new ("Volume", "atem.cmd.cami.setmask24.flags.volume", ftypes.BOOLEAN, {"On","Off"}, 3, 0x2)
pf_fields["pf_flag_cmd_cami_setmask24_balance"] = ProtoField.new ("Balance", "atem.cmd.cami.setmask24.flags.balance", ftypes.BOOLEAN, {"On","Off"}, 3, 0x4)

pf_fields["pf_cmd_ammo_unknown9"]   = ProtoField.new  ("Unknown", "atem.cmd.ammo.unknown9", ftypes.NONE, nil, base.NONE)
VALS["VALS_CAMM_SETMASK25"] = {[0] = "Volume"}
pf_fields["pf_cmd_camm_setmask25"]  = ProtoField.new  ("Set Mask", "atem.cmd.camm.setmask25", ftypes.UINT8, VALS["VALS_CAMM_SETMASK25"], base.DEC)

VALS["VALS_MONITORAUDIO"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_monitoraudio"]  = ProtoField.new  ("Monitor Audio", "atem.field.monitoraudio", ftypes.UINT8, VALS["VALS_MONITORAUDIO"], base.DEC)

VALS["VALS_MUTE"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_mute"]  = ProtoField.new  ("Mute", "atem.field.mute", ftypes.UINT8, VALS["VALS_MUTE"], base.DEC)

VALS["VALS_SOLO"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_solo"]  = ProtoField.new  ("Solo", "atem.field.solo", ftypes.UINT8, VALS["VALS_SOLO"], base.DEC)

VALS["VALS_SOLOINPUT"] = {[1] = "Input 1", [2] = "Input 2", [3] = "Input 3", [4] = "Input 4", [5] = "Input 5", [6] = "Input 6", [7] = "Input 7", [8] = "Input 8", [9] = "Input 9", [10] = "Input 10", [11] = "Input 11", [12] = "Input 12", [13] = "Input 13", [14] = "Input 14", [15] = "Input 15", [16] = "Input 16", [17] = "Input 17", [18] = "Input 18", [19] = "Input 19", [20] = "Input 20", [1001] = "XLR", [1101] = "AES/EBU", [1201] = "RCA", [2001] = "MP1", [2002] = "MP2"}
pf_fields["pf_field_soloinput"] = ProtoField.new  ("Solo Input", "atem.field.soloinput", ftypes.UINT16, VALS["VALS_SOLOINPUT"], base.DEC)

VALS["VALS_DIM"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_field_dim"]   = ProtoField.new  ("Dim", "atem.field.dim", ftypes.UINT8, VALS["VALS_DIM"], base.DEC)

pf_fields["pf_cmd_camm_setmask26"]  = ProtoField.new  ("Set Mask", "atem.cmd.camm.setmask26", ftypes.UINT8, nil, base.DEC, 0x3F)
pf_fields["pf_flag_cmd_camm_setmask26_monitoraudio"] = ProtoField.new ("Monitor Audio", "atem.cmd.camm.setmask26.flags.monitoraudio", ftypes.BOOLEAN, {"On","Off"}, 6, 0x1)
pf_fields["pf_flag_cmd_camm_setmask26_volume"] = ProtoField.new ("Volume", "atem.cmd.camm.setmask26.flags.volume", ftypes.BOOLEAN, {"On","Off"}, 6, 0x2)
pf_fields["pf_flag_cmd_camm_setmask26_mute"] = ProtoField.new ("Mute", "atem.cmd.camm.setmask26.flags.mute", ftypes.BOOLEAN, {"On","Off"}, 6, 0x4)
pf_fields["pf_flag_cmd_camm_setmask26_solo"] = ProtoField.new ("Solo", "atem.cmd.camm.setmask26.flags.solo", ftypes.BOOLEAN, {"On","Off"}, 6, 0x8)
pf_fields["pf_flag_cmd_camm_setmask26_soloinput"] = ProtoField.new ("Solo Input", "atem.cmd.camm.setmask26.flags.soloinput", ftypes.BOOLEAN, {"On","Off"}, 6, 0x10)
pf_fields["pf_flag_cmd_camm_setmask26_dim"] = ProtoField.new ("Dim", "atem.cmd.camm.setmask26.flags.dim", ftypes.BOOLEAN, {"On","Off"}, 6, 0x20)

VALS["VALS_SALN_ENABLE"] = {[0] = "Off", [1] = "On"}
pf_fields["pf_cmd_saln_enable"] = ProtoField.new  ("Enable", "atem.cmd.saln.enable", ftypes.UINT8, VALS["VALS_SALN_ENABLE"], base.DEC)

pf_fields["pf_field_sources1"]  = ProtoField.new  ("Sources", "atem.field.sources1", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_amlv_sourcesagain"]   = ProtoField.new  ("Sources (again?)", "atem.cmd.amlv.sourcesagain", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_amlv_masterleft"] = ProtoField.new  ("Master Left", "atem.cmd.amlv.masterleft", ftypes.INT32, nil, base.DEC)
pf_fields["pf_cmd_amlv_masterright"]    = ProtoField.new  ("Master Right", "atem.cmd.amlv.masterright", ftypes.INT32, nil, base.DEC)
pf_fields["pf_cmd_amlv_masterpeakleft"] = ProtoField.new  ("Master Peak Left", "atem.cmd.amlv.masterpeakleft", ftypes.INT32, nil, base.DEC)
pf_fields["pf_cmd_amlv_masterpeakright"]    = ProtoField.new  ("Master Peak Right", "atem.cmd.amlv.masterpeakright", ftypes.INT32, nil, base.DEC)
pf_fields["pf_cmd_amlv_monitor"]    = ProtoField.new  ("Monitor", "atem.cmd.amlv.monitor", ftypes.INT32, nil, base.DEC)
pf_fields["pf_cmd_ramp_setmask27"]  = ProtoField.new  ("Set Mask", "atem.cmd.ramp.setmask27", ftypes.UINT8, nil, base.DEC, 0x7)
-- pf_fields["pf_flag_cmd_ramp_setmask27_"] = ProtoField.new ("?", "atem.cmd.ramp.setmask27.flags.", ftypes.BOOLEAN, {"On","Off"}, 3, 0x1)
pf_fields["pf_flag_cmd_ramp_setmask27_inputs"] = ProtoField.new ("Inputs", "atem.cmd.ramp.setmask27.flags.inputs", ftypes.BOOLEAN, {"On","Off"}, 3, 0x2)
pf_fields["pf_flag_cmd_ramp_setmask27_master"] = ProtoField.new ("Master", "atem.cmd.ramp.setmask27.flags.master", ftypes.BOOLEAN, {"On","Off"}, 3, 0x4)

VALS["VALS_RAMP_INPUTSOURCE1"] = {[1] = "Input 1", [2] = "Input 2", [3] = "Input 3", [4] = "Input 4", [5] = "Input 5", [6] = "Input 6", [7] = "Input 7", [8] = "Input 8", [9] = "Input 9", [10] = "Input 10", [11] = "Input 11", [12] = "Input 12", [13] = "Input 13", [14] = "Input 14", [15] = "Input 15", [16] = "Input 16", [17] = "Input 17", [18] = "Input 18", [19] = "Input 19", [20] = "Input 20", [1001] = "XLR", [1101] = "AES/EBU", [1201] = "RCA", [2001] = "MP1", [2002] = "MP2"}
pf_fields["pf_cmd_ramp_inputsource1"]   = ProtoField.new  ("Input Source", "atem.cmd.ramp.inputsource1", ftypes.UINT16, VALS["VALS_RAMP_INPUTSOURCE1"], base.DEC)

VALS["VALS_RAMP_MASTER"] = {[0] = "No", [1] = "Yes"}
pf_fields["pf_cmd_ramp_master"] = ProtoField.new  ("Master", "atem.cmd.ramp.master", ftypes.UINT8, VALS["VALS_RAMP_MASTER"], base.DEC)

pf_fields["pf_cmd_time_hour"]   = ProtoField.new  ("Hour", "atem.cmd.time.hour", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_time_minute"] = ProtoField.new  ("Minute", "atem.cmd.time.minute", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_time_second"] = ProtoField.new  ("Second", "atem.cmd.time.second", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_time_frame"]  = ProtoField.new  ("Frame", "atem.cmd.time.frame", ftypes.UINT8, nil, base.DEC)

pf_fields["pf_cmd_lokb_storeId"]    = ProtoField.new  ("Store ID", "atem.cmd.lokb.storeId", ftypes.UINT16, VALS["VALS_TRANSFER_TYPE"], base.DEC)
pf_fields["pf_cmd_lock_storeId"]    = ProtoField.new  ("Store ID", "atem.cmd.lock.storeId", ftypes.UINT16, VALS["VALS_TRANSFER_TYPE"], base.DEC)

VALS["VALS_LOCK_STATE"] = {[0] = "Unlock", [1] = "Lock"}
pf_fields["pf_cmd_lock_state"]      = ProtoField.new  ("State", "atem.cmd.lock.state", ftypes.UINT8, VALS["VALS_LOCK_STATE"], base.DEC)

pf_fields["pf_cmd_lkst_storeId"]    = ProtoField.new  ("Store ID", "atem.cmd.lkst.storeId", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_lkst_state"]      = ProtoField.new  ("State", "atem.cmd.lkst.state", ftypes.UINT8, VALS["VALS_LOCK_STATE"], base.DEC)

pf_fields["pf_cmd_incm_state1"]     = ProtoField.new  ("State 1", "atem.cmd.incm.state1", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_incm_state2"]     = ProtoField.new  ("State 2", "atem.cmd.incm.state2", ftypes.UINT8, nil, base.DEC)

pf_fields["pf_cmd_ftsd_id"]         = ProtoField.new  ("Transfer ID", "atem.cmd.ftsd.id", ftypes.UINT16, nil, base.DEC)

pf_fields["pf_cmd_ftsd_storeId"]    = ProtoField.new  ("Transfer Store ID", "atem.cmd.ftsd.storeId", ftypes.UINT16, VALS["VALS_TRANSFER_TYPE"], base.DEC)
pf_fields["pf_cmd_ftsd_index"]      = ProtoField.new  ("Transfer Index", "atem.cmd.ftsd.index", ftypes.UINT8, nil, base.DEC)
pf_fields["pf_cmd_ftsd_size"]       = ProtoField.new  ("Size", "atem.cmd.ftsd.size", ftypes.UINT16, nil, base.DEC)

VALS["VALS_FTSD_OP"] = {[1] = "Write", [2] = "Clear"}
pf_fields["pf_cmd_ftsd_op"]         = ProtoField.new  ("Operation", "atem.cmd.ftsd.op", ftypes.UINT16, VALS["VALS_FTSD_OP"], base.DEC)

pf_fields["pf_cmd_ftcd_id"]         = ProtoField.new  ("Transfer ID", "atem.cmd.ftcd.id", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_ftcd_chunk_size"] = ProtoField.new  ("Chunk Size", "atem.cmd.ftcd.chunkSize", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_ftcd_chunk_count"]= ProtoField.new  ("Chunk Count", "atem.cmd.ftcd.chunkCount", ftypes.UINT16, nil, base.DEC)

pf_fields["pf_cmd_ftda_id"]         = ProtoField.new  ("Transfer ID", "atem.cmd.ftda.id", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_ftda_size"]       = ProtoField.new  ("Size", "atem.cmd.ftda.size", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_ftda_data"]       = ProtoField.new  ("Data", "atem.cmd.ftda.data", ftypes.BYTES)

pf_fields["pf_cmd_ftsu_id"]         = ProtoField.new  ("Transfer ID", "atem.cmd.ftsu.id", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_ftsu_storeId"]    = ProtoField.new  ("Transfer Store ID", "atem.cmd.ftsu.storeId", ftypes.UINT8, VALS["VALS_TRANSFER_TYPE"], base.DEC)
pf_fields["pf_cmd_ftsu_index"]      = ProtoField.new  ("Transfer Index", "atem.cmd.ftsu.index", ftypes.UINT8, nil, base.DEC)

pf_fields["pf_cmd_ftua_id"]         = ProtoField.new  ("Transfer ID", "atem.cmd.ftua.id", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_ftua_index"]      = ProtoField.new  ("Transfer Index", "atem.cmd.ftua.index", ftypes.UINT8, nil, base.DEC)

pf_fields["pf_cmd_ftdc_id"]         = ProtoField.new  ("Transfer ID", "atem.cmd.ftdc.id", ftypes.UINT16, nil, base.DEC)

pf_fields["pf_cmd_ftfd_id"]         = ProtoField.new  ("Transfer ID", "atem.cmd.ftfd.id", ftypes.UINT16, nil, base.DEC)
pf_fields["pf_cmd_ftfd_filename"]   = ProtoField.new  ("Filename", "atem.cmd.ftfd.filename", ftypes.STRING, nil, base.NONE)
pf_fields["pf_cmd_ftfd_hash"]       = ProtoField.new  ("File hash (MD5)", "atem.cmd.ftfd.hash", ftypes.BYTES)


local cmd_labels = {}
cmd_labels["_ver"] = "Protocol Version"
cmd_labels["_pin"] = "Product Id"
cmd_labels["Warn"] = "Warning"
cmd_labels["_top"] = "Topology"
cmd_labels["_MeC"] = "Mix Effect Config"
cmd_labels["_mpl"] = "Media Players"
cmd_labels["_MvC"] = "Multi View Config"
cmd_labels["_SSC"] = "Super Source Config"
cmd_labels["_TlC"] = "Tally Channel Config"
cmd_labels["_AMC"] = "Audio Mixer Config"
cmd_labels["_VMC"] = "Video Mixer Config"
cmd_labels["_MAC"] = "Macro Pool"
cmd_labels["Powr"] = "Power"
cmd_labels["DcOt"] = "Down Converter"
cmd_labels["CDcO"] = "Down Converter"
cmd_labels["VidM"] = "Video Mode"
cmd_labels["CVdM"] = "Video Mode"
cmd_labels["InPr"] = "Input Properties"
cmd_labels["CInL"] = "Input Properties"
cmd_labels["MvPr"] = "Multi Viewer Properties"
cmd_labels["CMvP"] = "Multi Viewer Properties"
cmd_labels["MvIn"] = "Multi Viewer Input"
cmd_labels["CMvI"] = "Multi Viewer Input"
cmd_labels["PrgI"] = "Program Input"
cmd_labels["CPgI"] = "Program Input"
cmd_labels["PrvI"] = "Preview Input"
cmd_labels["CPvI"] = "Preview Input"
cmd_labels["DCut"] = "Cut"
cmd_labels["DAut"] = "Auto"
cmd_labels["TrSS"] = "Transition"
cmd_labels["CTTp"] = "Transition"
cmd_labels["TrPr"] = "Transition Preview"
cmd_labels["CTPr"] = "Transition Preview"
cmd_labels["TrPs"] = "Transition Position"
cmd_labels["CTPs"] = "Transition Position"
cmd_labels["TMxP"] = "Transition Mix"
cmd_labels["CTMx"] = "Transition Mix"
cmd_labels["TDpP"] = "Transition Dip"
cmd_labels["CTDp"] = "Transition Dip"
cmd_labels["TWpP"] = "Transition Wipe"
cmd_labels["CTWp"] = "Transition Wipe"
cmd_labels["TDvP"] = "Transition DVE"
cmd_labels["CTDv"] = "Transition DVE"
cmd_labels["TStP"] = "Transition Stinger"
cmd_labels["CTSt"] = "Transition Stinger"
cmd_labels["KeOn"] = "Keyer On Air"
cmd_labels["CKOn"] = "Keyer On Air"
cmd_labels["KeBP"] = "Keyer Base"
cmd_labels["CKTp"] = "Key Type"
cmd_labels["CKMs"] = "Key Mask"
cmd_labels["CKeF"] = "Key Fill"
cmd_labels["CKeC"] = "Key Cut"
cmd_labels["KeLm"] = "Key Luma"
cmd_labels["CKLm"] = "Key Luma"
cmd_labels["KeCk"] = "Key Chroma"
cmd_labels["CKCk"] = "Key Chroma"
cmd_labels["KePt"] = "Key Pattern"
cmd_labels["CKPt"] = "Key Pattern"
cmd_labels["KeDV"] = "Key DVE"
cmd_labels["CKDV"] = "Key DVE"
cmd_labels["KeFS"] = "Keyer Fly"
cmd_labels["SFKF"] = "Keyer Fly"
cmd_labels["RFlK"] = "Run Flying Key"
cmd_labels["KKFP"] = "Keyer Fly Key Frame"
cmd_labels["DskB"] = "Downstream Keyer"
cmd_labels["CDsF"] = "Downstream Keyer"
cmd_labels["CDsC"] = "Downstream Keyer"
cmd_labels["DskP"] = "Downstream Keyer"
cmd_labels["CDsT"] = "Downstream Keyer"
cmd_labels["CDsR"] = "Downstream Keyer"
cmd_labels["CDsG"] = "Downstream Keyer"
cmd_labels["CDsM"] = "Downstream Keyer"
cmd_labels["DDsA"] = "Downstream Keyer Auto"
cmd_labels["DskS"] = "Downstream Keyer"
cmd_labels["CDsL"] = "Downstream Keyer"
cmd_labels["FtbP"] = "Fade-To-Black"
cmd_labels["FtbC"] = "Fade-To-Black"
cmd_labels["FtbS"] = "Fade-To-Black State"
cmd_labels["FtbA"] = "Fade-To-Black"
cmd_labels["ColV"] = "Color Generator"
cmd_labels["CClV"] = "Color Generator"
cmd_labels["AuxS"] = "Aux Source"
cmd_labels["CAuS"] = "Aux Source"
cmd_labels["CCdo"] = "Camera Control Options(?)"
cmd_labels["CCdP"] = "Camera Control"
cmd_labels["CCmd"] = "Camera Control"
cmd_labels["RCPS"] = "Clip Player"
cmd_labels["SCPS"] = "Clip Player"
cmd_labels["MPCE"] = "Media Player Source"
cmd_labels["MPSS"] = "Media Player Source"
cmd_labels["MPSp"] = "Media Pool Storage"
cmd_labels["CMPS"] = "Media Pool Storage"
cmd_labels["CSTL"] = "Media Pool Clear Still"
cmd_labels["CMPC"] = "Media Pool Clear Clip"
cmd_labels["CMPA"] = "Media Pool Clear Audio"
cmd_labels["MPCS"] = "Media Player Clip Description"
cmd_labels["SMPC"] = "Set Media Player Clip Description"
cmd_labels["MPAS"] = "Media Player Audio Description"
cmd_labels["MPfe"] = "Media Player Frame Description"
cmd_labels["MRPr"] = "Macro Run Status"
cmd_labels["MAct"] = "Macro Action"
cmd_labels["MRCP"] = "Macro Run Change Properties"
cmd_labels["MPrp"] = "Macro Properties"
cmd_labels["CMPr"] = "Change Macro Properties"
cmd_labels["MSRc"] = "Macro Start Recording"
cmd_labels["MSlp"] = "Macro Add Pause"
cmd_labels["MRcS"] = "Macro Recording Status"
cmd_labels["SSrc"] = "Super Source"
cmd_labels["SSBd"] = "Super Source Border"
cmd_labels["CSSc"] = "Super Source"
cmd_labels["CSBd"] = "Super Source Border"
cmd_labels["SSBP"] = "Super Source Box Parameters"
cmd_labels["CSBP"] = "Super Source Box Parameters"
cmd_labels["AMIP"] = "Audio Mixer Input"
cmd_labels["CAMI"] = "Audio Mixer Input"
cmd_labels["AMMO"] = "Audio Mixer Master"
cmd_labels["CAMM"] = "Audio Mixer Master"
cmd_labels["AMmO"] = "Audio Mixer Monitor"
cmd_labels["CAMm"] = "Audio Mixer Monitor"
cmd_labels["SALN"] = "Audio Levels"
cmd_labels["AMLv"] = "Audio Mixer Levels"
cmd_labels["RAMP"] = "Reset Audio Mixer Peaks"
cmd_labels["AMTl"] = "Audio Mixer Tally"
cmd_labels["TlIn"] = "Tally By Index"
cmd_labels["TlSr"] = "Tally By Source"
cmd_labels["Time"] = "Last State Change Time Code"
cmd_labels["SRsv"] = "Save Startup State"
cmd_labels["SRcl"] = "Clear Startup State"
cmd_labels["LOCK"] = "Set Lock State"
cmd_labels["LKOB"] = "Lock Obtained"
cmd_labels["LKST"] = "Lock State Changed"
cmd_labels["InCm"] = "Initialization Completed"
cmd_labels["FTSD"] = "Data Transfer to Switcher"
cmd_labels["FTFD"] = "Data File Description"
cmd_labels["FTDC"] = "Data Transfer Completed"
cmd_labels["FTSU"] = "Data Transfer Request"
cmd_labels["FTDa"] = "Data Transfer"
cmd_labels["FTUA"] = "Data Transfer Ack"
cmd_labels["FTDE"] = "Data Transfer Error"


----------------------------------------
-- this actually registers the ProtoFields above, into our new Protocol
-- in a real script I wouldn't do it this way; I'd build a table of fields programmatically
-- and then set atem_proto.fields to it, so as to avoid forgetting a field
atem_proto.fields = { 
  pf_packet_length, pf_flags, pf_session_id, pf_switcher_pkt_id, pf_client_pkt_id,  pf_ack_pkt_id, pf_unknown1, pf_flag_ack, 
  pf_cmd_length, pf_cmd_name,
  pf_flag_init, pf_flag_retransmission, pf_flag_hello, pf_flag_response,
  pf_fields["pf_cmd__ver_major"],pf_fields["pf_cmd__ver_minor"],pf_fields["pf_cmd__pin_name0"],pf_fields["pf_cmd_warn_text"],pf_fields["pf_cmd__top_mes"],pf_fields["pf_cmd__top_sources0"],pf_fields["pf_cmd__top_colorgenerators"],pf_fields["pf_cmd__top_auxbusses"],pf_fields["pf_cmd__top_downstreamkeyes"],pf_fields["pf_cmd__top_stingers"],pf_fields["pf_cmd__top_dves"],pf_fields["pf_cmd__top_supersources"],pf_fields["pf_field_unknown0"],pf_fields["pf_cmd__top_hassdoutput"],pf_fields["pf_field_unknown1"],pf_fields["pf_field_me"],pf_fields["pf_cmd__mec_keyersonme"],pf_fields["pf_cmd__mpl_stillbanks"],pf_fields["pf_cmd__mpl_clipbanks"],pf_fields["pf_cmd__mvc_multiviewers"],pf_fields["pf_field_unknown2"],pf_fields["pf_cmd__ssc_boxes"],pf_fields["pf_field_unknown3"],pf_fields["pf_cmd__tlc_tallychannels"],pf_fields["pf_cmd__amc_audiochannels"],pf_fields["pf_cmd__amc_hasmonitor"],pf_fields["pf_cmd__vmc_modes"],pf_fields["pf_flag_cmd__vmc_modes_525i5994ntsc"],pf_fields["pf_flag_cmd__vmc_modes_625i50pal"],pf_fields["pf_flag_cmd__vmc_modes_525i5994ntsc169"],pf_fields["pf_flag_cmd__vmc_modes_625i50pal169"],pf_fields["pf_flag_cmd__vmc_modes_720p50"],pf_fields["pf_flag_cmd__vmc_modes_720p5994"],pf_fields["pf_flag_cmd__vmc_modes_1080i50"],pf_fields["pf_flag_cmd__vmc_modes_1080i5994"],pf_fields["pf_flag_cmd__vmc_modes_1080p2398"],pf_fields["pf_flag_cmd__vmc_modes_1080p24"],pf_fields["pf_flag_cmd__vmc_modes_1080p25"],pf_fields["pf_flag_cmd__vmc_modes_1080p2997"],pf_fields["pf_flag_cmd__vmc_modes_1080p50"],pf_fields["pf_flag_cmd__vmc_modes_1080p5994"],pf_fields["pf_flag_cmd__vmc_modes_2160p2398"],pf_fields["pf_flag_cmd__vmc_modes_2160p24"],pf_fields["pf_flag_cmd__vmc_modes_2160p25"],pf_fields["pf_flag_cmd__vmc_modes_2160p2997"],pf_fields["pf_cmd__mac_banks"],pf_fields["pf_cmd_powr_status"],pf_fields["pf_flag_cmd_powr_status_mainpower"],pf_fields["pf_flag_cmd_powr_status_backuppower"],pf_fields["pf_field_mode"],pf_fields["pf_field_format"],pf_fields["pf_field_videosource"],pf_fields["pf_field_longname"],pf_fields["pf_field_shortname"],pf_fields["pf_cmd_inpr_availableexternalporttypes"],pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_sdi"],pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_hdmi"],pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_component"],pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_composite"],pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_svideo"],pf_fields["pf_cmd_inpr_externalporttype0"],pf_fields["pf_cmd_inpr_porttype"],pf_fields["pf_cmd_inpr_availability"],pf_fields["pf_flag_cmd_inpr_availability_auxilary"],pf_fields["pf_flag_cmd_inpr_availability_multiviewer"],pf_fields["pf_flag_cmd_inpr_availability_supersourceart"],pf_fields["pf_flag_cmd_inpr_availability_supersourcebox"],pf_fields["pf_flag_cmd_inpr_availability_keysourceseverywhere"],pf_fields["pf_cmd_inpr_meavailability"],pf_fields["pf_flag_cmd_inpr_meavailability_me1fillsources"],pf_fields["pf_flag_cmd_inpr_meavailability_me2fillsources"],pf_fields["pf_cmd_inpr_available3"],pf_fields["pf_cmd_cinl_setmask0"],pf_fields["pf_flag_cmd_cinl_setmask0_longname"],pf_fields["pf_flag_cmd_cinl_setmask0_shortname"],pf_fields["pf_flag_cmd_cinl_setmask0_externalporttype"],pf_fields["pf_cmd_cinl_externalporttype1"],pf_fields["pf_field_multiviewer"],pf_fields["pf_field_layout"],pf_fields["pf_cmd_cmvp_setmask1"],pf_fields["pf_field_windowindex"],pf_fields["pf_field_style0"],pf_fields["pf_field_nexttransition"],pf_fields["pf_flag_field_nexttransition_background"],pf_fields["pf_flag_field_nexttransition_key1"],pf_fields["pf_flag_field_nexttransition_key2"],pf_fields["pf_flag_field_nexttransition_key3"],pf_fields["pf_flag_field_nexttransition_key4"],pf_fields["pf_cmd_trss_stylenext"],pf_fields["pf_cmd_trss_nexttransitionnext"],pf_fields["pf_flag_cmd_trss_nexttransitionnext_background"],pf_fields["pf_flag_cmd_trss_nexttransitionnext_key1"],pf_fields["pf_flag_cmd_trss_nexttransitionnext_key2"],pf_fields["pf_flag_cmd_trss_nexttransitionnext_key3"],pf_fields["pf_flag_cmd_trss_nexttransitionnext_key4"],pf_fields["pf_cmd_cttp_setmask2"],pf_fields["pf_flag_cmd_cttp_setmask2_transitionstyle"],pf_fields["pf_flag_cmd_cttp_setmask2_nexttransition"],pf_fields["pf_field_enabled"],pf_fields["pf_cmd_trps_intransition0"],pf_fields["pf_field_framesremaining"],pf_fields["pf_field_position"],pf_fields["pf_field_rate"],pf_fields["pf_field_input0"],pf_fields["pf_cmd_ctdp_setmask3"],pf_fields["pf_flag_cmd_ctdp_setmask3_rate"],pf_fields["pf_flag_cmd_ctdp_setmask3_input"],pf_fields["pf_field_pattern"],pf_fields["pf_field_width"],pf_fields["pf_field_fillsource"],pf_fields["pf_field_symmetry"],pf_fields["pf_field_softness"],pf_fields["pf_field_positionx0"],pf_fields["pf_field_positiony0"],pf_fields["pf_field_reverse"],pf_fields["pf_field_flipflop"],pf_fields["pf_cmd_ctwp_setmask4"],pf_fields["pf_flag_cmd_ctwp_setmask4_rate"],pf_fields["pf_flag_cmd_ctwp_setmask4_pattern"],pf_fields["pf_flag_cmd_ctwp_setmask4_width"],pf_fields["pf_flag_cmd_ctwp_setmask4_fillsource"],pf_fields["pf_flag_cmd_ctwp_setmask4_symmetry"],pf_fields["pf_flag_cmd_ctwp_setmask4_softness"],pf_fields["pf_flag_cmd_ctwp_setmask4_positionx"],pf_fields["pf_flag_cmd_ctwp_setmask4_positiony"],pf_fields["pf_flag_cmd_ctwp_setmask4_reverse"],pf_fields["pf_flag_cmd_ctwp_setmask4_flipflop"],pf_fields["pf_field_style1"],pf_fields["pf_field_keysource"],pf_fields["pf_field_enablekey"],pf_fields["pf_field_premultiplied"],pf_fields["pf_field_clip"],pf_fields["pf_field_gain0"],pf_fields["pf_field_invertkey0"],pf_fields["pf_cmd_ctdv_setmask5"],pf_fields["pf_flag_cmd_ctdv_setmask5_rate"],pf_fields["pf_flag_cmd_ctdv_setmask5_"],pf_fields["pf_flag_cmd_ctdv_setmask5_style"],pf_fields["pf_flag_cmd_ctdv_setmask5_fillsource"],pf_fields["pf_flag_cmd_ctdv_setmask5_keysource"],pf_fields["pf_flag_cmd_ctdv_setmask5_enablekey"],pf_fields["pf_flag_cmd_ctdv_setmask5_premultiplied"],pf_fields["pf_flag_cmd_ctdv_setmask5_clip"],pf_fields["pf_flag_cmd_ctdv_setmask5_gain"],pf_fields["pf_flag_cmd_ctdv_setmask5_invertkey"],pf_fields["pf_flag_cmd_ctdv_setmask5_reverse"],pf_fields["pf_flag_cmd_ctdv_setmask5_flipflop"],pf_fields["pf_field_source"],pf_fields["pf_field_preroll"],pf_fields["pf_field_clipduration"],pf_fields["pf_field_triggerpoint"],pf_fields["pf_field_mixrate"],pf_fields["pf_cmd_ctst_setmask6"],pf_fields["pf_flag_cmd_ctst_setmask6_source"],pf_fields["pf_flag_cmd_ctst_setmask6_premultiplied"],pf_fields["pf_flag_cmd_ctst_setmask6_clip"],pf_fields["pf_flag_cmd_ctst_setmask6_gain"],pf_fields["pf_flag_cmd_ctst_setmask6_invertkey"],pf_fields["pf_flag_cmd_ctst_setmask6_preroll"],pf_fields["pf_flag_cmd_ctst_setmask6_clipduration"],pf_fields["pf_flag_cmd_ctst_setmask6_triggerpoint"],pf_fields["pf_flag_cmd_ctst_setmask6_mixrate"],pf_fields["pf_field_keyer0"],pf_fields["pf_field_type0"],pf_fields["pf_cmd_kebp_keyenabled"],pf_fields["pf_cmd_kebp_keyenabledagain"],pf_fields["pf_field_flyenabled"],pf_fields["pf_field_masked"],pf_fields["pf_field_top"],pf_fields["pf_field_bottom"],pf_fields["pf_field_left"],pf_fields["pf_field_right"],pf_fields["pf_cmd_cktp_setmask7"],pf_fields["pf_flag_cmd_cktp_setmask7_type"],pf_fields["pf_flag_cmd_cktp_setmask7_enabled"],pf_fields["pf_field_setmask8"],pf_fields["pf_flag_field_setmask8_masked"],pf_fields["pf_flag_field_setmask8_top"],pf_fields["pf_flag_field_setmask8_bottom"],pf_fields["pf_flag_field_setmask8_left"],pf_fields["pf_flag_field_setmask8_right"],pf_fields["pf_cmd_cklm_setmask9"],pf_fields["pf_flag_cmd_cklm_setmask9_premultiplied"],pf_fields["pf_flag_cmd_cklm_setmask9_clip"],pf_fields["pf_flag_cmd_cklm_setmask9_gain"],pf_fields["pf_flag_cmd_cklm_setmask9_invertkey"],pf_fields["pf_field_hue0"],pf_fields["pf_field_ysuppress"],pf_fields["pf_field_lift"],pf_fields["pf_field_narrow"],pf_fields["pf_cmd_ckck_setmask10"],pf_fields["pf_flag_cmd_ckck_setmask10_hue"],pf_fields["pf_flag_cmd_ckck_setmask10_gain"],pf_fields["pf_flag_cmd_ckck_setmask10_ysuppress"],pf_fields["pf_flag_cmd_ckck_setmask10_lift"],pf_fields["pf_flag_cmd_ckck_setmask10_narrow"],pf_fields["pf_field_size"],pf_fields["pf_field_invertpattern"],pf_fields["pf_cmd_ckpt_setmask11"],pf_fields["pf_flag_cmd_ckpt_setmask11_pattern"],pf_fields["pf_flag_cmd_ckpt_setmask11_size"],pf_fields["pf_flag_cmd_ckpt_setmask11_symmetry"],pf_fields["pf_flag_cmd_ckpt_setmask11_softness"],pf_fields["pf_flag_cmd_ckpt_setmask11_positionx"],pf_fields["pf_flag_cmd_ckpt_setmask11_positiony"],pf_fields["pf_flag_cmd_ckpt_setmask11_invertpattern"],pf_fields["pf_field_sizex"],pf_fields["pf_field_sizey"],pf_fields["pf_field_positionx1"],pf_fields["pf_field_positiony1"],pf_fields["pf_field_rotation"],pf_fields["pf_field_borderenabled"],pf_fields["pf_field_shadow"],pf_fields["pf_field_borderbevel"],pf_fields["pf_field_borderouterwidth"],pf_fields["pf_field_borderinnerwidth"],pf_fields["pf_field_borderoutersoftness"],pf_fields["pf_field_borderinnersoftness"],pf_fields["pf_field_borderbevelsoftness"],pf_fields["pf_field_borderbevelposition"],pf_fields["pf_field_borderopacity"],pf_fields["pf_field_borderhue"],pf_fields["pf_field_bordersaturation"],pf_fields["pf_field_borderluma"],pf_fields["pf_field_lightsourcedirection"],pf_fields["pf_field_lightsourcealtitude"],pf_fields["pf_cmd_ckdv_setmask12"],pf_fields["pf_flag_cmd_ckdv_setmask12_sizex"],pf_fields["pf_flag_cmd_ckdv_setmask12_sizey"],pf_fields["pf_flag_cmd_ckdv_setmask12_positionx"],pf_fields["pf_flag_cmd_ckdv_setmask12_positiony"],pf_fields["pf_flag_cmd_ckdv_setmask12_rotation"],pf_fields["pf_flag_cmd_ckdv_setmask12_borderenabled"],pf_fields["pf_flag_cmd_ckdv_setmask12_shadow"],pf_fields["pf_flag_cmd_ckdv_setmask12_borderbevel"],pf_fields["pf_flag_cmd_ckdv_setmask12_outerwidth"],pf_fields["pf_flag_cmd_ckdv_setmask12_innerwidth"],pf_fields["pf_flag_cmd_ckdv_setmask12_outersoftness"],pf_fields["pf_flag_cmd_ckdv_setmask12_innersoftness"],pf_fields["pf_flag_cmd_ckdv_setmask12_bevelsoftness"],pf_fields["pf_flag_cmd_ckdv_setmask12_bevelposition"],pf_fields["pf_flag_cmd_ckdv_setmask12_borderopacity"],pf_fields["pf_flag_cmd_ckdv_setmask12_borderhue"],pf_fields["pf_flag_cmd_ckdv_setmask12_bordersaturation"],pf_fields["pf_flag_cmd_ckdv_setmask12_borderluma"],pf_fields["pf_flag_cmd_ckdv_setmask12_direction"],pf_fields["pf_flag_cmd_ckdv_setmask12_altitude"],pf_fields["pf_flag_cmd_ckdv_setmask12_masked"],pf_fields["pf_flag_cmd_ckdv_setmask12_top"],pf_fields["pf_flag_cmd_ckdv_setmask12_bottom"],pf_fields["pf_flag_cmd_ckdv_setmask12_left"],pf_fields["pf_flag_cmd_ckdv_setmask12_right"],pf_fields["pf_flag_cmd_ckdv_setmask12_rate"],pf_fields["pf_cmd_kefs_isaset"],pf_fields["pf_cmd_kefs_isbset"],pf_fields["pf_cmd_kefs_isatkeyframe"],pf_fields["pf_flag_cmd_kefs_isatkeyframe_a"],pf_fields["pf_flag_cmd_kefs_isatkeyframe_b"],pf_fields["pf_flag_cmd_kefs_isatkeyframe_full"],pf_fields["pf_flag_cmd_kefs_isatkeyframe_runtoinfinite"],pf_fields["pf_field_runtoinfiniteindex"],pf_fields["pf_field_keyframe0"],pf_fields["pf_cmd_rflk_setmask13"],pf_fields["pf_flag_cmd_rflk_setmask13_onoff"],pf_fields["pf_flag_cmd_rflk_setmask13_runtoinfinite"],pf_fields["pf_cmd_rflk_keyframe1"],pf_fields["pf_field_keyer1"],pf_fields["pf_field_tie"],pf_fields["pf_cmd_cdsg_setmask14"],pf_fields["pf_flag_cmd_cdsg_setmask14_premultiplied"],pf_fields["pf_flag_cmd_cdsg_setmask14_clip"],pf_fields["pf_flag_cmd_cdsg_setmask14_gain"],pf_fields["pf_cmd_cdsg_invertkey1"],pf_fields["pf_field_onair"],pf_fields["pf_field_intransition1"],pf_fields["pf_cmd_dsks_isautotransitioning"],pf_fields["pf_cmd_ftbc_setmask15"],pf_fields["pf_cmd_ftbs_fullyblack"],pf_fields["pf_field_colorgenerator"],pf_fields["pf_field_saturation0"],pf_fields["pf_field_luma"],pf_fields["pf_cmd_cclv_setmask16"],pf_fields["pf_flag_cmd_cclv_setmask16_hue"],pf_fields["pf_flag_cmd_cclv_setmask16_saturation"],pf_fields["pf_flag_cmd_cclv_setmask16_luma"],pf_fields["pf_field_auxchannel"],pf_fields["pf_field_setmask17"],pf_fields["pf_field_input1"],pf_fields["pf_field_adjustmentdomain"],pf_fields["pf_cmd_ccdo_lensfeature0"],pf_fields["pf_cmd_ccdo_camerafeature0"],pf_fields["pf_field_chipfeature"],pf_fields["pf_cmd_ccdo_available"],pf_fields["pf_field_lensfeature1"],pf_fields["pf_field_camerafeature1"],pf_fields["pf_cmd_ccdp_unknown4"],pf_fields["pf_field_iris"],pf_fields["pf_field_focus"],pf_fields["pf_field_gain1"],pf_fields["pf_field_whitebalance"],pf_fields["pf_field_zoomspeed"],pf_fields["pf_field_liftr"],pf_fields["pf_field_gammar"],pf_fields["pf_field_gainr"],pf_fields["pf_field_lummix"],pf_fields["pf_field_hue1"],pf_fields["pf_field_shutter"],pf_fields["pf_field_liftg"],pf_fields["pf_field_gammag"],pf_fields["pf_field_gaing"],pf_fields["pf_field_contrast"],pf_fields["pf_field_saturation1"],pf_fields["pf_field_liftb"],pf_fields["pf_field_gammab"],pf_fields["pf_field_gainb"],pf_fields["pf_field_lifty"],pf_fields["pf_field_gammay"],pf_fields["pf_field_gainy"],pf_fields["pf_cmd_ccmd_relative"],pf_fields["pf_field_unknown5"],pf_fields["pf_field_mediaplayer"],pf_fields["pf_field_playing"],pf_fields["pf_field_loop"],pf_fields["pf_field_atbeginning"],pf_fields["pf_field_clipframe"],pf_fields["pf_cmd_scps_setmask18"],pf_fields["pf_flag_cmd_scps_setmask18_playing"],pf_fields["pf_flag_cmd_scps_setmask18_loop"],pf_fields["pf_flag_cmd_scps_setmask18_beginning"],pf_fields["pf_flag_cmd_scps_setmask18_frame"],pf_fields["pf_field_type1"],pf_fields["pf_field_stillindex"],pf_fields["pf_field_clipindex"],pf_fields["pf_cmd_mpss_setmask19"],pf_fields["pf_flag_cmd_mpss_setmask19_type"],pf_fields["pf_flag_cmd_mpss_setmask19_still"],pf_fields["pf_flag_cmd_mpss_setmask19_clip"],pf_fields["pf_field_clip1maxlength"],pf_fields["pf_cmd_mpsp_clip2maxlength"],pf_fields["pf_field_clipbank"],pf_fields["pf_field_isused"],pf_fields["pf_field_filename"],pf_fields["pf_field_frames"],pf_fields["pf_cmd_mpas_hash"],pf_fields["pf_cmd_mpfe_type"],pf_fields["pf_cmd_mpfe_index"],pf_fields["pf_cmd_mpfe_hash"],pf_fields["pf_cmd_mpfe_filenamestringlength"],pf_fields["pf_cmd_mrpr_state"],pf_fields["pf_flag_cmd_mrpr_state_running"],pf_fields["pf_flag_cmd_mrpr_state_waiting"],pf_fields["pf_cmd_mrpr_islooping"],pf_fields["pf_field_index0"],pf_fields["pf_cmd_mact_action"],pf_fields["pf_cmd_mrcp_setmask20"],pf_fields["pf_cmd_mrcp_looping"],pf_fields["pf_cmd_mprp_macroindex"],pf_fields["pf_field_namestringlength"],pf_fields["pf_field_descriptionstringlength"],pf_fields["pf_cmd_mprp_name1"],pf_fields["pf_field_description"],pf_fields["pf_cmd_cmpr_setmask21"],pf_fields["pf_flag_cmd_cmpr_setmask21_name"],pf_fields["pf_flag_cmd_cmpr_setmask21_description"],pf_fields["pf_field_name2"],pf_fields["pf_cmd_msrc_index1"],pf_fields["pf_cmd_mrcs_isrecording"],pf_fields["pf_field_foreground"],pf_fields["pf_cmd_cssc_setmask22"],pf_fields["pf_flag_cmd_cssc_setmask22_fillsource"],pf_fields["pf_flag_cmd_cssc_setmask22_keysource"],pf_fields["pf_flag_cmd_cssc_setmask22_foreground"],pf_fields["pf_flag_cmd_cssc_setmask22_premultiplied"],pf_fields["pf_flag_cmd_cssc_setmask22_clip"],pf_fields["pf_flag_cmd_cssc_setmask22_gain"],pf_fields["pf_flag_cmd_cssc_setmask22_invert"],pf_fields["pf_flag_cmd_cssc_setmask22_enabled"],pf_fields["pf_flag_cmd_cssc_setmask22_bevel"],pf_fields["pf_flag_cmd_cssc_setmask22_outerwidth"],pf_fields["pf_flag_cmd_cssc_setmask22_innerwidth"],pf_fields["pf_flag_cmd_cssc_setmask22_outersoftness"],pf_fields["pf_flag_cmd_cssc_setmask22_innersoftness"],pf_fields["pf_flag_cmd_cssc_setmask22_bevelsoftness"],pf_fields["pf_flag_cmd_cssc_setmask22_bevelpos"],pf_fields["pf_flag_cmd_cssc_setmask22_hue"],pf_fields["pf_flag_cmd_cssc_setmask22_saturation"],pf_fields["pf_flag_cmd_cssc_setmask22_luma"],pf_fields["pf_flag_cmd_cssc_setmask22_direction"],pf_fields["pf_flag_cmd_cssc_setmask22_altitude"],pf_fields["pf_field_box"],pf_fields["pf_field_inputsource0"],pf_fields["pf_field_positionx2"],pf_fields["pf_field_positiony2"],pf_fields["pf_field_cropped"],pf_fields["pf_field_croptop"],pf_fields["pf_field_cropbottom"],pf_fields["pf_field_cropleft"],pf_fields["pf_field_cropright"],pf_fields["pf_cmd_csbp_setmask23"],pf_fields["pf_flag_cmd_csbp_setmask23_enabled"],pf_fields["pf_flag_cmd_csbp_setmask23_inputsource"],pf_fields["pf_flag_cmd_csbp_setmask23_positionx"],pf_fields["pf_flag_cmd_csbp_setmask23_positiony"],pf_fields["pf_flag_cmd_csbp_setmask23_size"],pf_fields["pf_flag_cmd_csbp_setmask23_cropped"],pf_fields["pf_flag_cmd_csbp_setmask23_croptop"],pf_fields["pf_flag_cmd_csbp_setmask23_cropbottom"],pf_fields["pf_flag_cmd_csbp_setmask23_cropleft"],pf_fields["pf_flag_cmd_csbp_setmask23_cropright"],pf_fields["pf_field_audiosource"],pf_fields["pf_cmd_amip_type2"],pf_fields["pf_cmd_amip_frommediaplayer"],pf_fields["pf_cmd_amip_plugtype"],pf_fields["pf_field_mixoption"],pf_fields["pf_field_volume"],pf_fields["pf_field_balance"],pf_fields["pf_cmd_cami_setmask24"],pf_fields["pf_flag_cmd_cami_setmask24_mixoption"],pf_fields["pf_flag_cmd_cami_setmask24_volume"],pf_fields["pf_flag_cmd_cami_setmask24_balance"],pf_fields["pf_cmd_ammo_unknown9"],pf_fields["pf_cmd_camm_setmask25"],pf_fields["pf_field_monitoraudio"],pf_fields["pf_field_mute"],pf_fields["pf_field_solo"],pf_fields["pf_field_soloinput"],pf_fields["pf_field_dim"],pf_fields["pf_cmd_camm_setmask26"],pf_fields["pf_flag_cmd_camm_setmask26_monitoraudio"],pf_fields["pf_flag_cmd_camm_setmask26_volume"],pf_fields["pf_flag_cmd_camm_setmask26_mute"],pf_fields["pf_flag_cmd_camm_setmask26_solo"],pf_fields["pf_flag_cmd_camm_setmask26_soloinput"],pf_fields["pf_flag_cmd_camm_setmask26_dim"],pf_fields["pf_cmd_saln_enable"],pf_fields["pf_field_sources1"],pf_fields["pf_cmd_amlv_sourcesagain"],pf_fields["pf_cmd_amlv_masterleft"],pf_fields["pf_cmd_amlv_masterright"],pf_fields["pf_cmd_amlv_masterpeakleft"],pf_fields["pf_cmd_amlv_masterpeakright"],pf_fields["pf_cmd_amlv_monitor"],pf_fields["pf_cmd_ramp_setmask27"],pf_fields["pf_flag_cmd_ramp_setmask27_"],pf_fields["pf_flag_cmd_ramp_setmask27_inputs"],pf_fields["pf_flag_cmd_ramp_setmask27_master"],pf_fields["pf_cmd_ramp_inputsource1"],pf_fields["pf_cmd_ramp_master"],pf_fields["pf_cmd_time_hour"],pf_fields["pf_cmd_time_minute"],pf_fields["pf_cmd_time_second"],pf_fields["pf_cmd_time_frame"],pf_fields["pf_field_ssrc_id"],pf_fields["pf_field_padding"], pf_fields["pf_cmd_csbd_setmask22"]
  , pf_fields["pf_cmd_lokb_storeId"], pf_fields["pf_cmd_lock_storeId"], pf_fields["pf_cmd_lock_state"]
  , pf_fields["pf_cmd_lkst_storeId"], pf_fields["pf_cmd_lkst_state"]
  , pf_fields["pf_cmd_incm_state1"], pf_fields["pf_cmd_incm_state2"]
  , pf_fields["pf_cmd_ftsd_id"], pf_fields["pf_cmd_ftsd_storeId"], pf_fields["pf_cmd_ftsd_index"], pf_fields["pf_cmd_ftsd_size"], pf_fields["pf_cmd_ftsd_op"]
  , pf_fields["pf_cmd_ftcd_id"], pf_fields["pf_cmd_ftcd_chunk_count"], pf_fields["pf_cmd_ftcd_chunk_size"]  
  , pf_fields["pf_cmd_ftda_id"], pf_fields["pf_cmd_ftda_size"], pf_fields["pf_cmd_ftda_data"]
  , pf_fields["pf_cmd_ftsu_id"], pf_fields["pf_cmd_ftsu_storeId"], pf_fields["pf_cmd_ftsu_index"]
  , pf_fields["pf_cmd_ftua_id"], pf_fields["pf_cmd_ftua_index"]
  , pf_fields["pf_cmd_ftdc_id"]
  , pf_fields["pf_cmd_ftfd_id"], pf_fields["pf_cmd_ftfd_filename"], pf_fields["pf_cmd_ftfd_hash"]
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
local packet_length_field   = Field.new("atem.packet_length")
local session_id_field      = Field.new("atem.session_id")
local switcher_pkt_id_field = Field.new("atem.switcher_pkt_id")
local client_pkt_id_field   = Field.new("atem.client_pkt_id")
local ack_pkt_id_field      = Field.new("atem.ack_pkt_id")
local unkown1_field         = Field.new("atem.unknown1")

local cmd_length_field      = Field.new("atem.cmd.length")
local cmd_name_field        = Field.new("atem.cmd.name")

local ef_too_short       = ProtoExpert.new("atem.too_short.expert", "ATEM message too short", expert.group.MALFORMED, expert.severity.ERROR)
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
	local cmd_name = ""
	
	if (pktlen > 12 and tvbuf:range(0,1):bitfield(3, 1) == 0) then
		local commands_tree = tree:add("Commands")
		packet_type = "Commands"
	  
		local pktlen_remaining = pktlen - pos
	
	while (pktlen_remaining > 0) do
		cmd_name = tvbuf:range(pos + 4, 4):string()
		local cmd_length = tvbuf:range(pos, 2):uint()
		
		local cmd_label = cmd_labels[cmd_name]
		if (cmd_label ~= nil) then
			cmd_label = "(" .. cmd_label .. ")"
		end
		
		local cmd_tree = commands_tree:add(cmd_name, tvbuf:range(pos, cmd_length), nil, cmd_label)
		
		cmd_tree:add(pf_cmd_length, tvbuf:range(pos, 2))
		cmd_tree:add(pf_cmd_name, tvbuf:range(pos + 4, 4))
		
		if (cmd_name == "_ver") then
			cmd_tree:add(pf_fields["pf_cmd__ver_major"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd__ver_minor"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "_pin") then
			cmd_tree:add(pf_fields["pf_cmd__pin_name0"], tvbuf:range(pos+8, 44))
		elseif (cmd_name == "Warn") then
			cmd_tree:add(pf_fields["pf_cmd_warn_text"], tvbuf:range(pos+8, 44))
		elseif (cmd_name == "_top") then
			cmd_tree:add(pf_fields["pf_cmd__top_mes"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd__top_sources0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_cmd__top_colorgenerators"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_cmd__top_auxbusses"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_cmd__top_downstreamkeyes"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_cmd__top_stingers"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_cmd__top_dves"], tvbuf:range(pos+14, 1))
			cmd_tree:add(pf_fields["pf_cmd__top_supersources"], tvbuf:range(pos+15, 1))
			cmd_tree:add(pf_fields["pf_field_unknown0"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_cmd__top_hassdoutput"], tvbuf:range(pos+17, 1))
			cmd_tree:add(pf_fields["pf_field_unknown0"], tvbuf:range(pos+18, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+19, 1))
		elseif (cmd_name == "_MeC") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd__mec_keyersonme"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "_mpl") then
			cmd_tree:add(pf_fields["pf_cmd__mpl_stillbanks"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd__mpl_clipbanks"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "_MvC") then
			cmd_tree:add(pf_fields["pf_cmd__mvc_multiviewers"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "_SSC") then
			cmd_tree:add(pf_fields["pf_cmd__ssc_boxes"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "_TlC") then
			cmd_tree:add(pf_fields["pf_field_unknown3"], tvbuf:range(pos+8, 4))
			cmd_tree:add(pf_fields["pf_cmd__tlc_tallychannels"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+13, 3))
		elseif (cmd_name == "_AMC") then
			cmd_tree:add(pf_fields["pf_cmd__amc_audiochannels"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd__amc_hasmonitor"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "_VMC") then
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+8, 1))
			local cmd__vmc_modes_tree = cmd_tree:add(pf_fields["pf_cmd__vmc_modes"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_525i5994ntsc"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_625i50pal"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_525i5994ntsc169"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_625i50pal169"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_720p50"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_720p5994"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_1080i50"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_1080i5994"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_1080p2398"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_1080p24"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_1080p25"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_1080p2997"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_1080p50"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_1080p5994"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_2160p2398"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_2160p24"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_2160p25"], tvbuf:range(pos+9, 3))
			cmd__vmc_modes_tree:add(pf_fields["pf_flag_cmd__vmc_modes_2160p2997"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "_MAC") then
			cmd_tree:add(pf_fields["pf_cmd__mac_banks"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "Powr") then
			local cmd_powr_status_tree = cmd_tree:add(pf_fields["pf_cmd_powr_status"], tvbuf:range(pos+8, 1))
			cmd_powr_status_tree:add(pf_fields["pf_flag_cmd_powr_status_mainpower"], tvbuf:range(pos+8, 1))
			cmd_powr_status_tree:add(pf_fields["pf_flag_cmd_powr_status_backuppower"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "DcOt") then
			cmd_tree:add(pf_fields["pf_field_mode"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "CDcO") then
			cmd_tree:add(pf_fields["pf_field_mode"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "VidM") then
			cmd_tree:add(pf_fields["pf_field_format"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "CVdM") then
			cmd_tree:add(pf_fields["pf_field_format"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "InPr") then
			cmd_tree:add(pf_fields["pf_field_videosource"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_field_longname"], tvbuf:range(pos+10, 20))
			cmd_tree:add(pf_fields["pf_field_shortname"], tvbuf:range(pos+30, 4))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+34, 1))
			local cmd_inpr_availableexternalporttypes_tree = cmd_tree:add(pf_fields["pf_cmd_inpr_availableexternalporttypes"], tvbuf:range(pos+35, 1))
			cmd_inpr_availableexternalporttypes_tree:add(pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_sdi"], tvbuf:range(pos+35, 1))
			cmd_inpr_availableexternalporttypes_tree:add(pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_hdmi"], tvbuf:range(pos+35, 1))
			cmd_inpr_availableexternalporttypes_tree:add(pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_component"], tvbuf:range(pos+35, 1))
			cmd_inpr_availableexternalporttypes_tree:add(pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_composite"], tvbuf:range(pos+35, 1))
			cmd_inpr_availableexternalporttypes_tree:add(pf_fields["pf_flag_cmd_inpr_availableexternalporttypes_svideo"], tvbuf:range(pos+35, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+36, 1))
			cmd_tree:add(pf_fields["pf_cmd_inpr_externalporttype0"], tvbuf:range(pos+37, 1))
			cmd_tree:add(pf_fields["pf_cmd_inpr_porttype"], tvbuf:range(pos+38, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+39, 1))
			local cmd_inpr_availability_tree = cmd_tree:add(pf_fields["pf_cmd_inpr_availability"], tvbuf:range(pos+40, 1))
			cmd_inpr_availability_tree:add(pf_fields["pf_flag_cmd_inpr_availability_auxilary"], tvbuf:range(pos+40, 1))
			cmd_inpr_availability_tree:add(pf_fields["pf_flag_cmd_inpr_availability_multiviewer"], tvbuf:range(pos+40, 1))
			cmd_inpr_availability_tree:add(pf_fields["pf_flag_cmd_inpr_availability_supersourceart"], tvbuf:range(pos+40, 1))
			cmd_inpr_availability_tree:add(pf_fields["pf_flag_cmd_inpr_availability_supersourcebox"], tvbuf:range(pos+40, 1))
			cmd_inpr_availability_tree:add(pf_fields["pf_flag_cmd_inpr_availability_keysourceseverywhere"], tvbuf:range(pos+40, 1))
			local cmd_inpr_meavailability_tree = cmd_tree:add(pf_fields["pf_cmd_inpr_meavailability"], tvbuf:range(pos+41, 1))
			cmd_inpr_meavailability_tree:add(pf_fields["pf_flag_cmd_inpr_meavailability_me1fillsources"], tvbuf:range(pos+41, 1))
			cmd_inpr_meavailability_tree:add(pf_fields["pf_flag_cmd_inpr_meavailability_me2fillsources"], tvbuf:range(pos+41, 1))
			cmd_tree:add(pf_fields["pf_cmd_inpr_available3"], tvbuf:range(pos+42, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+43, 1))
		elseif (cmd_name == "CInL") then
			local cmd_cinl_setmask0_tree = cmd_tree:add(pf_fields["pf_cmd_cinl_setmask0"], tvbuf:range(pos+8, 1))
			cmd_cinl_setmask0_tree:add(pf_fields["pf_flag_cmd_cinl_setmask0_longname"], tvbuf:range(pos+8, 1))
			cmd_cinl_setmask0_tree:add(pf_fields["pf_flag_cmd_cinl_setmask0_shortname"], tvbuf:range(pos+8, 1))
			cmd_cinl_setmask0_tree:add(pf_fields["pf_flag_cmd_cinl_setmask0_externalporttype"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_videosource"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_longname"], tvbuf:range(pos+12, 20))
			cmd_tree:add(pf_fields["pf_field_shortname"], tvbuf:range(pos+32, 4))
			cmd_tree:add(pf_fields["pf_cmd_cinl_externalporttype1"], tvbuf:range(pos+36, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+38, 1))
		elseif (cmd_name == "MvPr") then
			cmd_tree:add(pf_fields["pf_field_multiviewer"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_layout"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "CMvP") then
			cmd_tree:add(pf_fields["pf_cmd_cmvp_setmask1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_multiviewer"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_layout"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "MvIn") then
			cmd_tree:add(pf_fields["pf_field_multiviewer"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_windowindex"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_videosource"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "CMvI") then
			cmd_tree:add(pf_fields["pf_field_multiviewer"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_windowindex"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_videosource"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "PrgI") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_videosource"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "CPgI") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_videosource"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "PrvI") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_videosource"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_unknown3"], tvbuf:range(pos+12, 4))
		elseif (cmd_name == "CPvI") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_videosource"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "DCut") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "DAut") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "TrSS") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_style0"], tvbuf:range(pos+9, 1))
			local field_nexttransition_tree = cmd_tree:add(pf_fields["pf_field_nexttransition"], tvbuf:range(pos+10, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_background"], tvbuf:range(pos+10, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_key1"], tvbuf:range(pos+10, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_key2"], tvbuf:range(pos+10, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_key3"], tvbuf:range(pos+10, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_key4"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_cmd_trss_stylenext"], tvbuf:range(pos+11, 1))
			local cmd_trss_nexttransitionnext_tree = cmd_tree:add(pf_fields["pf_cmd_trss_nexttransitionnext"], tvbuf:range(pos+12, 1))
			cmd_trss_nexttransitionnext_tree:add(pf_fields["pf_flag_cmd_trss_nexttransitionnext_background"], tvbuf:range(pos+12, 1))
			cmd_trss_nexttransitionnext_tree:add(pf_fields["pf_flag_cmd_trss_nexttransitionnext_key1"], tvbuf:range(pos+12, 1))
			cmd_trss_nexttransitionnext_tree:add(pf_fields["pf_flag_cmd_trss_nexttransitionnext_key2"], tvbuf:range(pos+12, 1))
			cmd_trss_nexttransitionnext_tree:add(pf_fields["pf_flag_cmd_trss_nexttransitionnext_key3"], tvbuf:range(pos+12, 1))
			cmd_trss_nexttransitionnext_tree:add(pf_fields["pf_flag_cmd_trss_nexttransitionnext_key4"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+13, 3))
		elseif (cmd_name == "CTTp") then
			local cmd_cttp_setmask2_tree = cmd_tree:add(pf_fields["pf_cmd_cttp_setmask2"], tvbuf:range(pos+8, 1))
			cmd_cttp_setmask2_tree:add(pf_fields["pf_flag_cmd_cttp_setmask2_transitionstyle"], tvbuf:range(pos+8, 1))
			cmd_cttp_setmask2_tree:add(pf_fields["pf_flag_cmd_cttp_setmask2_nexttransition"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_style0"], tvbuf:range(pos+10, 1))
			local field_nexttransition_tree = cmd_tree:add(pf_fields["pf_field_nexttransition"], tvbuf:range(pos+11, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_background"], tvbuf:range(pos+11, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_key1"], tvbuf:range(pos+11, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_key2"], tvbuf:range(pos+11, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_key3"], tvbuf:range(pos+11, 1))
			field_nexttransition_tree:add(pf_fields["pf_flag_field_nexttransition_key4"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "TrPr") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_enabled"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "CTPr") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_enabled"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "TrPs") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd_trps_intransition0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_framesremaining"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_position"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+14, 1))
		elseif (cmd_name == "CTPs") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_position"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "TMxP") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "CTMx") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "TDpP") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_input0"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "CTDp") then
			local cmd_ctdp_setmask3_tree = cmd_tree:add(pf_fields["pf_cmd_ctdp_setmask3"], tvbuf:range(pos+8, 1))
			cmd_ctdp_setmask3_tree:add(pf_fields["pf_flag_cmd_ctdp_setmask3_rate"], tvbuf:range(pos+8, 1))
			cmd_ctdp_setmask3_tree:add(pf_fields["pf_flag_cmd_ctdp_setmask3_input"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_input0"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+14, 1))
		elseif (cmd_name == "TWpP") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_pattern"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_width"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_symmetry"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_softness"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_positionx0"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_positiony0"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_reverse"], tvbuf:range(pos+24, 1))
			cmd_tree:add(pf_fields["pf_field_flipflop"], tvbuf:range(pos+25, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+26, 1))
		elseif (cmd_name == "CTWp") then
			local cmd_ctwp_setmask4_tree = cmd_tree:add(pf_fields["pf_cmd_ctwp_setmask4"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_rate"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_pattern"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_width"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_fillsource"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_symmetry"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_softness"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_positionx"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_positiony"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_reverse"], tvbuf:range(pos+8, 2))
			cmd_ctwp_setmask4_tree:add(pf_fields["pf_flag_cmd_ctwp_setmask4_flipflop"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_pattern"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_width"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_symmetry"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_softness"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_positionx0"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_positiony0"], tvbuf:range(pos+24, 2))
			cmd_tree:add(pf_fields["pf_field_reverse"], tvbuf:range(pos+26, 1))
			cmd_tree:add(pf_fields["pf_field_flipflop"], tvbuf:range(pos+27, 1))
		elseif (cmd_name == "TDvP") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_style1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_keysource"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_enablekey"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+17, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_invertkey0"], tvbuf:range(pos+22, 1))
			cmd_tree:add(pf_fields["pf_field_reverse"], tvbuf:range(pos+23, 1))
			cmd_tree:add(pf_fields["pf_field_flipflop"], tvbuf:range(pos+24, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+25, 3))
		elseif (cmd_name == "CTDv") then
			local cmd_ctdv_setmask5_tree = cmd_tree:add(pf_fields["pf_cmd_ctdv_setmask5"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_rate"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_style"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_fillsource"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_keysource"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_enablekey"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_premultiplied"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_clip"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_gain"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_invertkey"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_reverse"], tvbuf:range(pos+8, 2))
			cmd_ctdv_setmask5_tree:add(pf_fields["pf_flag_cmd_ctdv_setmask5_flipflop"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_style1"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_keysource"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_enablekey"], tvbuf:range(pos+18, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+19, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_invertkey0"], tvbuf:range(pos+24, 1))
			cmd_tree:add(pf_fields["pf_field_reverse"], tvbuf:range(pos+25, 1))
			cmd_tree:add(pf_fields["pf_field_flipflop"], tvbuf:range(pos+26, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+27, 1))
		elseif (cmd_name == "TStP") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_source"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_invertkey0"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+17, 1))
			cmd_tree:add(pf_fields["pf_field_preroll"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_clipduration"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_triggerpoint"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_mixrate"], tvbuf:range(pos+24, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+26, 1))
		elseif (cmd_name == "CTSt") then
			local cmd_ctst_setmask6_tree = cmd_tree:add(pf_fields["pf_cmd_ctst_setmask6"], tvbuf:range(pos+8, 2))
			cmd_ctst_setmask6_tree:add(pf_fields["pf_flag_cmd_ctst_setmask6_source"], tvbuf:range(pos+8, 2))
			cmd_ctst_setmask6_tree:add(pf_fields["pf_flag_cmd_ctst_setmask6_premultiplied"], tvbuf:range(pos+8, 2))
			cmd_ctst_setmask6_tree:add(pf_fields["pf_flag_cmd_ctst_setmask6_clip"], tvbuf:range(pos+8, 2))
			cmd_ctst_setmask6_tree:add(pf_fields["pf_flag_cmd_ctst_setmask6_gain"], tvbuf:range(pos+8, 2))
			cmd_ctst_setmask6_tree:add(pf_fields["pf_flag_cmd_ctst_setmask6_invertkey"], tvbuf:range(pos+8, 2))
			cmd_ctst_setmask6_tree:add(pf_fields["pf_flag_cmd_ctst_setmask6_preroll"], tvbuf:range(pos+8, 2))
			cmd_ctst_setmask6_tree:add(pf_fields["pf_flag_cmd_ctst_setmask6_clipduration"], tvbuf:range(pos+8, 2))
			cmd_ctst_setmask6_tree:add(pf_fields["pf_flag_cmd_ctst_setmask6_triggerpoint"], tvbuf:range(pos+8, 2))
			cmd_ctst_setmask6_tree:add(pf_fields["pf_flag_cmd_ctst_setmask6_mixrate"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_source"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_invertkey0"], tvbuf:range(pos+18, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+19, 1))
			cmd_tree:add(pf_fields["pf_field_preroll"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_clipduration"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_triggerpoint"], tvbuf:range(pos+24, 2))
			cmd_tree:add(pf_fields["pf_field_mixrate"], tvbuf:range(pos+26, 2))
		elseif (cmd_name == "KeOn") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_enabled"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "CKOn") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_enabled"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "KeBP") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_type0"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_cmd_kebp_keyenabled"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_cmd_kebp_keyenabledagain"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_flyenabled"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_keysource"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_masked"], tvbuf:range(pos+18, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+19, 1))
			cmd_tree:add(pf_fields["pf_field_top"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_bottom"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_left"], tvbuf:range(pos+24, 2))
			cmd_tree:add(pf_fields["pf_field_right"], tvbuf:range(pos+26, 2))
		elseif (cmd_name == "CKTp") then
			local cmd_cktp_setmask7_tree = cmd_tree:add(pf_fields["pf_cmd_cktp_setmask7"], tvbuf:range(pos+8, 1))
			cmd_cktp_setmask7_tree:add(pf_fields["pf_flag_cmd_cktp_setmask7_type"], tvbuf:range(pos+8, 1))
			cmd_cktp_setmask7_tree:add(pf_fields["pf_flag_cmd_cktp_setmask7_enabled"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_type0"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_flyenabled"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+13, 3))
		elseif (cmd_name == "CKMs") then
			local field_setmask8_tree = cmd_tree:add(pf_fields["pf_field_setmask8"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_masked"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_top"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_bottom"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_left"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_right"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_masked"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_top"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_bottom"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_left"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_right"], tvbuf:range(pos+18, 2))
		elseif (cmd_name == "CKeF") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "CKeC") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keysource"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "KeLm") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_invertkey0"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+17, 3))
		elseif (cmd_name == "CKLm") then
			local cmd_cklm_setmask9_tree = cmd_tree:add(pf_fields["pf_cmd_cklm_setmask9"], tvbuf:range(pos+8, 1))
			cmd_cklm_setmask9_tree:add(pf_fields["pf_flag_cmd_cklm_setmask9_premultiplied"], tvbuf:range(pos+8, 1))
			cmd_cklm_setmask9_tree:add(pf_fields["pf_flag_cmd_cklm_setmask9_clip"], tvbuf:range(pos+8, 1))
			cmd_cklm_setmask9_tree:add(pf_fields["pf_flag_cmd_cklm_setmask9_gain"], tvbuf:range(pos+8, 1))
			cmd_cklm_setmask9_tree:add(pf_fields["pf_flag_cmd_cklm_setmask9_invertkey"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_invertkey0"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+17, 3))
		elseif (cmd_name == "KeCk") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_hue0"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_ysuppress"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_lift"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_narrow"], tvbuf:range(pos+18, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+19, 1))
		elseif (cmd_name == "CKCk") then
			local cmd_ckck_setmask10_tree = cmd_tree:add(pf_fields["pf_cmd_ckck_setmask10"], tvbuf:range(pos+8, 1))
			cmd_ckck_setmask10_tree:add(pf_fields["pf_flag_cmd_ckck_setmask10_hue"], tvbuf:range(pos+8, 1))
			cmd_ckck_setmask10_tree:add(pf_fields["pf_flag_cmd_ckck_setmask10_gain"], tvbuf:range(pos+8, 1))
			cmd_ckck_setmask10_tree:add(pf_fields["pf_flag_cmd_ckck_setmask10_ysuppress"], tvbuf:range(pos+8, 1))
			cmd_ckck_setmask10_tree:add(pf_fields["pf_flag_cmd_ckck_setmask10_lift"], tvbuf:range(pos+8, 1))
			cmd_ckck_setmask10_tree:add(pf_fields["pf_flag_cmd_ckck_setmask10_narrow"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_hue0"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_ysuppress"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_lift"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_narrow"], tvbuf:range(pos+20, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+21, 3))
		elseif (cmd_name == "KePt") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_pattern"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_size"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_symmetry"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_softness"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_positionx0"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_positiony0"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_invertpattern"], tvbuf:range(pos+22, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+23, 1))
		elseif (cmd_name == "CKPt") then
			local cmd_ckpt_setmask11_tree = cmd_tree:add(pf_fields["pf_cmd_ckpt_setmask11"], tvbuf:range(pos+8, 1))
			cmd_ckpt_setmask11_tree:add(pf_fields["pf_flag_cmd_ckpt_setmask11_pattern"], tvbuf:range(pos+8, 1))
			cmd_ckpt_setmask11_tree:add(pf_fields["pf_flag_cmd_ckpt_setmask11_size"], tvbuf:range(pos+8, 1))
			cmd_ckpt_setmask11_tree:add(pf_fields["pf_flag_cmd_ckpt_setmask11_symmetry"], tvbuf:range(pos+8, 1))
			cmd_ckpt_setmask11_tree:add(pf_fields["pf_flag_cmd_ckpt_setmask11_softness"], tvbuf:range(pos+8, 1))
			cmd_ckpt_setmask11_tree:add(pf_fields["pf_flag_cmd_ckpt_setmask11_positionx"], tvbuf:range(pos+8, 1))
			cmd_ckpt_setmask11_tree:add(pf_fields["pf_flag_cmd_ckpt_setmask11_positiony"], tvbuf:range(pos+8, 1))
			cmd_ckpt_setmask11_tree:add(pf_fields["pf_flag_cmd_ckpt_setmask11_invertpattern"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_pattern"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_size"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_symmetry"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_softness"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_positionx0"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_positiony0"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_invertpattern"], tvbuf:range(pos+22, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+23, 1))
		elseif (cmd_name == "KeDV") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_sizex"], tvbuf:range(pos+12, 4))
			cmd_tree:add(pf_fields["pf_field_sizey"], tvbuf:range(pos+16, 4))
			cmd_tree:add(pf_fields["pf_field_positionx1"], tvbuf:range(pos+20, 4))
			cmd_tree:add(pf_fields["pf_field_positiony1"], tvbuf:range(pos+24, 4))
			cmd_tree:add(pf_fields["pf_field_rotation"], tvbuf:range(pos+28, 4))
			cmd_tree:add(pf_fields["pf_field_borderenabled"], tvbuf:range(pos+32, 1))
			cmd_tree:add(pf_fields["pf_field_shadow"], tvbuf:range(pos+33, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevel"], tvbuf:range(pos+34, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+35, 1))
			cmd_tree:add(pf_fields["pf_field_borderouterwidth"], tvbuf:range(pos+36, 2))
			cmd_tree:add(pf_fields["pf_field_borderinnerwidth"], tvbuf:range(pos+38, 2))
			cmd_tree:add(pf_fields["pf_field_borderoutersoftness"], tvbuf:range(pos+40, 1))
			cmd_tree:add(pf_fields["pf_field_borderinnersoftness"], tvbuf:range(pos+41, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelsoftness"], tvbuf:range(pos+42, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelposition"], tvbuf:range(pos+43, 1))
			cmd_tree:add(pf_fields["pf_field_borderopacity"], tvbuf:range(pos+44, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+45, 1))
			cmd_tree:add(pf_fields["pf_field_borderhue"], tvbuf:range(pos+46, 2))
			cmd_tree:add(pf_fields["pf_field_bordersaturation"], tvbuf:range(pos+48, 2))
			cmd_tree:add(pf_fields["pf_field_borderluma"], tvbuf:range(pos+50, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcedirection"], tvbuf:range(pos+52, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcealtitude"], tvbuf:range(pos+54, 1))
			cmd_tree:add(pf_fields["pf_field_masked"], tvbuf:range(pos+55, 1))
			cmd_tree:add(pf_fields["pf_field_top"], tvbuf:range(pos+56, 2))
			cmd_tree:add(pf_fields["pf_field_bottom"], tvbuf:range(pos+58, 2))
			cmd_tree:add(pf_fields["pf_field_left"], tvbuf:range(pos+60, 2))
			cmd_tree:add(pf_fields["pf_field_right"], tvbuf:range(pos+62, 2))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+64, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+65, 3))
		elseif (cmd_name == "CKDV") then
			local cmd_ckdv_setmask12_tree = cmd_tree:add(pf_fields["pf_cmd_ckdv_setmask12"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_sizex"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_sizey"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_positionx"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_positiony"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_rotation"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_borderenabled"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_shadow"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_borderbevel"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_outerwidth"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_innerwidth"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_outersoftness"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_innersoftness"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_bevelsoftness"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_bevelposition"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_borderopacity"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_borderhue"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_bordersaturation"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_borderluma"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_direction"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_altitude"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_masked"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_top"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_bottom"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_left"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_right"], tvbuf:range(pos+8, 4))
			cmd_ckdv_setmask12_tree:add(pf_fields["pf_flag_cmd_ckdv_setmask12_rate"], tvbuf:range(pos+8, 4))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+14, 1))
			cmd_tree:add(pf_fields["pf_field_sizex"], tvbuf:range(pos+16, 4))
			cmd_tree:add(pf_fields["pf_field_sizey"], tvbuf:range(pos+20, 4))
			cmd_tree:add(pf_fields["pf_field_positionx1"], tvbuf:range(pos+24, 4))
			cmd_tree:add(pf_fields["pf_field_positiony1"], tvbuf:range(pos+28, 4))
			cmd_tree:add(pf_fields["pf_field_rotation"], tvbuf:range(pos+32, 4))
			cmd_tree:add(pf_fields["pf_field_borderenabled"], tvbuf:range(pos+36, 1))
			cmd_tree:add(pf_fields["pf_field_shadow"], tvbuf:range(pos+37, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevel"], tvbuf:range(pos+38, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+39, 1))
			cmd_tree:add(pf_fields["pf_field_borderouterwidth"], tvbuf:range(pos+40, 2))
			cmd_tree:add(pf_fields["pf_field_borderinnerwidth"], tvbuf:range(pos+42, 2))
			cmd_tree:add(pf_fields["pf_field_borderoutersoftness"], tvbuf:range(pos+44, 1))
			cmd_tree:add(pf_fields["pf_field_borderinnersoftness"], tvbuf:range(pos+45, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelsoftness"], tvbuf:range(pos+46, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelposition"], tvbuf:range(pos+47, 1))
			cmd_tree:add(pf_fields["pf_field_borderopacity"], tvbuf:range(pos+48, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+49, 1))
			cmd_tree:add(pf_fields["pf_field_borderhue"], tvbuf:range(pos+50, 2))
			cmd_tree:add(pf_fields["pf_field_bordersaturation"], tvbuf:range(pos+52, 2))
			cmd_tree:add(pf_fields["pf_field_borderluma"], tvbuf:range(pos+54, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcedirection"], tvbuf:range(pos+56, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcealtitude"], tvbuf:range(pos+58, 1))
			cmd_tree:add(pf_fields["pf_field_masked"], tvbuf:range(pos+59, 1))
			cmd_tree:add(pf_fields["pf_field_top"], tvbuf:range(pos+60, 2))
			cmd_tree:add(pf_fields["pf_field_bottom"], tvbuf:range(pos+62, 2))
			cmd_tree:add(pf_fields["pf_field_left"], tvbuf:range(pos+64, 2))
			cmd_tree:add(pf_fields["pf_field_right"], tvbuf:range(pos+66, 2))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+68, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+69, 3))
		elseif (cmd_name == "KeFS") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_cmd_kefs_isaset"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_cmd_kefs_isbset"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+12, 1))
			local cmd_kefs_isatkeyframe_tree = cmd_tree:add(pf_fields["pf_cmd_kefs_isatkeyframe"], tvbuf:range(pos+14, 1))
			cmd_kefs_isatkeyframe_tree:add(pf_fields["pf_flag_cmd_kefs_isatkeyframe_a"], tvbuf:range(pos+14, 1))
			cmd_kefs_isatkeyframe_tree:add(pf_fields["pf_flag_cmd_kefs_isatkeyframe_b"], tvbuf:range(pos+14, 1))
			cmd_kefs_isatkeyframe_tree:add(pf_fields["pf_flag_cmd_kefs_isatkeyframe_full"], tvbuf:range(pos+14, 1))
			cmd_kefs_isatkeyframe_tree:add(pf_fields["pf_flag_cmd_kefs_isatkeyframe_runtoinfinite"], tvbuf:range(pos+14, 1))
			cmd_tree:add(pf_fields["pf_field_runtoinfiniteindex"], tvbuf:range(pos+15, 1))
		elseif (cmd_name == "SFKF") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keyframe0"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "RFlK") then
			local cmd_rflk_setmask13_tree = cmd_tree:add(pf_fields["pf_cmd_rflk_setmask13"], tvbuf:range(pos+8, 1))
			cmd_rflk_setmask13_tree:add(pf_fields["pf_flag_cmd_rflk_setmask13_onoff"], tvbuf:range(pos+8, 1))
			cmd_rflk_setmask13_tree:add(pf_fields["pf_flag_cmd_rflk_setmask13_runtoinfinite"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_cmd_rflk_keyframe1"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_runtoinfiniteindex"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+14, 1))
		elseif (cmd_name == "KKFP") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keyframe0"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_sizex"], tvbuf:range(pos+12, 4))
			cmd_tree:add(pf_fields["pf_field_sizey"], tvbuf:range(pos+16, 4))
			cmd_tree:add(pf_fields["pf_field_positionx1"], tvbuf:range(pos+20, 4))
			cmd_tree:add(pf_fields["pf_field_positiony1"], tvbuf:range(pos+24, 4))
			cmd_tree:add(pf_fields["pf_field_rotation"], tvbuf:range(pos+28, 4))
			cmd_tree:add(pf_fields["pf_field_borderouterwidth"], tvbuf:range(pos+32, 2))
			cmd_tree:add(pf_fields["pf_field_borderinnerwidth"], tvbuf:range(pos+34, 2))
			cmd_tree:add(pf_fields["pf_field_borderoutersoftness"], tvbuf:range(pos+36, 1))
			cmd_tree:add(pf_fields["pf_field_borderinnersoftness"], tvbuf:range(pos+37, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelsoftness"], tvbuf:range(pos+38, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelposition"], tvbuf:range(pos+39, 1))
			cmd_tree:add(pf_fields["pf_field_borderopacity"], tvbuf:range(pos+40, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+41, 1))
			cmd_tree:add(pf_fields["pf_field_borderhue"], tvbuf:range(pos+42, 2))
			cmd_tree:add(pf_fields["pf_field_bordersaturation"], tvbuf:range(pos+44, 2))
			cmd_tree:add(pf_fields["pf_field_borderluma"], tvbuf:range(pos+46, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcedirection"], tvbuf:range(pos+48, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcealtitude"], tvbuf:range(pos+50, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+51, 1))
			cmd_tree:add(pf_fields["pf_field_top"], tvbuf:range(pos+52, 2))
			cmd_tree:add(pf_fields["pf_field_bottom"], tvbuf:range(pos+54, 2))
			cmd_tree:add(pf_fields["pf_field_left"], tvbuf:range(pos+56, 2))
			cmd_tree:add(pf_fields["pf_field_right"], tvbuf:range(pos+58, 2))
		elseif (cmd_name == "DskB") then
			cmd_tree:add(pf_fields["pf_field_keyer1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_keysource"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+14, 1))
		elseif (cmd_name == "CDsF") then
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "CDsC") then
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_keysource"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "DskP") then
			cmd_tree:add(pf_fields["pf_field_keyer1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_tie"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_invertkey0"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_masked"], tvbuf:range(pos+17, 1))
			cmd_tree:add(pf_fields["pf_field_top"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_bottom"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_left"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_right"], tvbuf:range(pos+24, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+26, 1))
		elseif (cmd_name == "CDsT") then
			cmd_tree:add(pf_fields["pf_field_keyer1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_tie"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "CDsR") then
			cmd_tree:add(pf_fields["pf_field_keyer1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "CDsG") then
			local cmd_cdsg_setmask14_tree = cmd_tree:add(pf_fields["pf_cmd_cdsg_setmask14"], tvbuf:range(pos+8, 1))
			cmd_cdsg_setmask14_tree:add(pf_fields["pf_flag_cmd_cdsg_setmask14_premultiplied"], tvbuf:range(pos+8, 1))
			cmd_cdsg_setmask14_tree:add(pf_fields["pf_flag_cmd_cdsg_setmask14_clip"], tvbuf:range(pos+8, 1))
			cmd_cdsg_setmask14_tree:add(pf_fields["pf_flag_cmd_cdsg_setmask14_gain"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_cmd_cdsg_invertkey1"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+17, 3))
		elseif (cmd_name == "CDsM") then
			local field_setmask8_tree = cmd_tree:add(pf_fields["pf_field_setmask8"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_masked"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_top"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_bottom"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_left"], tvbuf:range(pos+8, 1))
			field_setmask8_tree:add(pf_fields["pf_flag_field_setmask8_right"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_keyer0"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_masked"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_top"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_bottom"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_left"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_right"], tvbuf:range(pos+18, 2))
		elseif (cmd_name == "DDsA") then
			cmd_tree:add(pf_fields["pf_field_keyer1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "DskS") then
			cmd_tree:add(pf_fields["pf_field_keyer1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_onair"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_intransition1"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_cmd_dsks_isautotransitioning"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_framesremaining"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+13, 3))
		elseif (cmd_name == "CDsL") then
			cmd_tree:add(pf_fields["pf_field_keyer1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_onair"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "FtbP") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "FtbC") then
			cmd_tree:add(pf_fields["pf_cmd_ftbc_setmask15"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_rate"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "FtbS") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd_ftbs_fullyblack"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_intransition1"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_framesremaining"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "FtbA") then
			cmd_tree:add(pf_fields["pf_field_me"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "ColV") then
			cmd_tree:add(pf_fields["pf_field_colorgenerator"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_hue0"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_saturation0"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_luma"], tvbuf:range(pos+14, 2))
		elseif (cmd_name == "CClV") then
			local cmd_cclv_setmask16_tree = cmd_tree:add(pf_fields["pf_cmd_cclv_setmask16"], tvbuf:range(pos+8, 1))
			cmd_cclv_setmask16_tree:add(pf_fields["pf_flag_cmd_cclv_setmask16_hue"], tvbuf:range(pos+8, 1))
			cmd_cclv_setmask16_tree:add(pf_fields["pf_flag_cmd_cclv_setmask16_saturation"], tvbuf:range(pos+8, 1))
			cmd_cclv_setmask16_tree:add(pf_fields["pf_flag_cmd_cclv_setmask16_luma"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_colorgenerator"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_hue0"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_saturation0"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_luma"], tvbuf:range(pos+14, 2))
		elseif (cmd_name == "AuxS") then
			cmd_tree:add(pf_fields["pf_field_auxchannel"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_input0"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "CAuS") then
			cmd_tree:add(pf_fields["pf_field_setmask17"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_auxchannel"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_input0"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "CCdo") then
			cmd_tree:add(pf_fields["pf_field_setmask17"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_input1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_adjustmentdomain"], tvbuf:range(pos+10, 1))
			-- Adjustment Domain = 0
			if (tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_cmd_ccdo_lensfeature0"], tvbuf:range(pos+11, 1))
			end
			-- Adjustment Domain = 1
			if (tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_cmd_ccdo_camerafeature0"], tvbuf:range(pos+11, 1))
			end
			-- Adjustment Domain = 8
			if (tvbuf:range(pos+10, 1):uint() == 8) then
				cmd_tree:add(pf_fields["pf_field_chipfeature"], tvbuf:range(pos+11, 1))
			end
			cmd_tree:add(pf_fields["pf_cmd_ccdo_available"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+13, 3))
		elseif (cmd_name == "CCdP") then
			cmd_tree:add(pf_fields["pf_field_input1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_adjustmentdomain"], tvbuf:range(pos+9, 1))
			-- Adjustment Domain = 0
			if (tvbuf:range(pos+9, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_lensfeature1"], tvbuf:range(pos+10, 1))
			end
			-- Adjustment Domain = 1
			if (tvbuf:range(pos+9, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_camerafeature1"], tvbuf:range(pos+10, 1))
			end
			-- Adjustment Domain = 8
			if (tvbuf:range(pos+9, 1):uint() == 8) then
				cmd_tree:add(pf_fields["pf_field_chipfeature"], tvbuf:range(pos+10, 1))
			end
			cmd_tree:add(pf_fields["pf_cmd_ccdp_unknown4"], tvbuf:range(pos+11, 13))
			-- Adjustment Domain = 0 and Lens feature = 3
			if (tvbuf:range(pos+9, 1):uint() == 0 and tvbuf:range(pos+10, 1):uint() == 3) then
				cmd_tree:add(pf_fields["pf_field_iris"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 0 and Lens feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 0 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_focus"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 1 and Camera feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 1 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gain1"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 1 and Camera feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 1 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_whitebalance"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 0 and Lens feature = 9
			if (tvbuf:range(pos+9, 1):uint() == 0 and tvbuf:range(pos+10, 1):uint() == 9) then
				cmd_tree:add(pf_fields["pf_field_zoomspeed"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_liftr"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gammar"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_gainr"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 5
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 5) then
				cmd_tree:add(pf_fields["pf_field_lummix"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 6
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 6) then
				cmd_tree:add(pf_fields["pf_field_hue1"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 1 and Camera feature = 5
			if (tvbuf:range(pos+9, 1):uint() == 1 and tvbuf:range(pos+10, 1):uint() == 5) then
				cmd_tree:add(pf_fields["pf_field_shutter"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_liftg"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gammag"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_gaing"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 4
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 4) then
				cmd_tree:add(pf_fields["pf_field_contrast"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 6
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 6) then
				cmd_tree:add(pf_fields["pf_field_saturation1"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_liftb"], tvbuf:range(pos+28, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gammab"], tvbuf:range(pos+28, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_gainb"], tvbuf:range(pos+28, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_lifty"], tvbuf:range(pos+30, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gammay"], tvbuf:range(pos+30, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_gainy"], tvbuf:range(pos+30, 2))
			end
		elseif (cmd_name == "CCmd") then
			cmd_tree:add(pf_fields["pf_field_input1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_adjustmentdomain"], tvbuf:range(pos+9, 1))
			-- Adjustment Domain = 0
			if (tvbuf:range(pos+9, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_lensfeature1"], tvbuf:range(pos+10, 1))
			end
			-- Adjustment Domain = 1
			if (tvbuf:range(pos+9, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_camerafeature1"], tvbuf:range(pos+10, 1))
			end
			-- Adjustment Domain = 8
			if (tvbuf:range(pos+9, 1):uint() == 8) then
				cmd_tree:add(pf_fields["pf_field_chipfeature"], tvbuf:range(pos+10, 1))
			end
			cmd_tree:add(pf_fields["pf_cmd_ccmd_relative"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_unknown5"], tvbuf:range(pos+12, 12))
			-- Adjustment Domain = 0 and Lens feature = 3
			if (tvbuf:range(pos+9, 1):uint() == 0 and tvbuf:range(pos+10, 1):uint() == 3) then
				cmd_tree:add(pf_fields["pf_field_iris"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 0 and Lens feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 0 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_focus"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 1 and Camera feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 1 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gain1"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 1 and Camera feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 1 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_whitebalance"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 0 and Lens feature = 9
			if (tvbuf:range(pos+9, 1):uint() == 0 and tvbuf:range(pos+10, 1):uint() == 9) then
				cmd_tree:add(pf_fields["pf_field_zoomspeed"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_liftr"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gammar"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_gainr"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 5
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 5) then
				cmd_tree:add(pf_fields["pf_field_lummix"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 6
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 6) then
				cmd_tree:add(pf_fields["pf_field_hue1"], tvbuf:range(pos+24, 2))
			end
			-- Adjustment Domain = 1 and Camera feature = 5
			if (tvbuf:range(pos+9, 1):uint() == 1 and tvbuf:range(pos+10, 1):uint() == 5) then
				cmd_tree:add(pf_fields["pf_field_shutter"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_liftg"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gammag"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_gaing"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 4
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 4) then
				cmd_tree:add(pf_fields["pf_field_contrast"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 6
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 6) then
				cmd_tree:add(pf_fields["pf_field_saturation1"], tvbuf:range(pos+26, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_liftb"], tvbuf:range(pos+28, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gammab"], tvbuf:range(pos+28, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_gainb"], tvbuf:range(pos+28, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 0
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 0) then
				cmd_tree:add(pf_fields["pf_field_lifty"], tvbuf:range(pos+30, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 1
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 1) then
				cmd_tree:add(pf_fields["pf_field_gammay"], tvbuf:range(pos+30, 2))
			end
			-- Adjustment Domain = 8 and Chip feature = 2
			if (tvbuf:range(pos+9, 1):uint() == 8 and tvbuf:range(pos+10, 1):uint() == 2) then
				cmd_tree:add(pf_fields["pf_field_gainy"], tvbuf:range(pos+30, 2))
			end
		elseif (cmd_name == "RCPS") then
			cmd_tree:add(pf_fields["pf_field_mediaplayer"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_playing"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_loop"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_atbeginning"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_clipframe"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+14, 1))
		elseif (cmd_name == "SCPS") then
			local cmd_scps_setmask18_tree = cmd_tree:add(pf_fields["pf_cmd_scps_setmask18"], tvbuf:range(pos+8, 1))
			cmd_scps_setmask18_tree:add(pf_fields["pf_flag_cmd_scps_setmask18_playing"], tvbuf:range(pos+8, 1))
			cmd_scps_setmask18_tree:add(pf_fields["pf_flag_cmd_scps_setmask18_loop"], tvbuf:range(pos+8, 1))
			cmd_scps_setmask18_tree:add(pf_fields["pf_flag_cmd_scps_setmask18_beginning"], tvbuf:range(pos+8, 1))
			cmd_scps_setmask18_tree:add(pf_fields["pf_flag_cmd_scps_setmask18_frame"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_mediaplayer"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_playing"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_loop"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_atbeginning"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_clipframe"], tvbuf:range(pos+14, 2))
		elseif (cmd_name == "MPCE") then
			cmd_tree:add(pf_fields["pf_field_mediaplayer"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_type1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_stillindex"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_clipindex"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "MPSS") then
			local cmd_mpss_setmask19_tree = cmd_tree:add(pf_fields["pf_cmd_mpss_setmask19"], tvbuf:range(pos+8, 1))
			cmd_mpss_setmask19_tree:add(pf_fields["pf_flag_cmd_mpss_setmask19_type"], tvbuf:range(pos+8, 1))
			cmd_mpss_setmask19_tree:add(pf_fields["pf_flag_cmd_mpss_setmask19_still"], tvbuf:range(pos+8, 1))
			cmd_mpss_setmask19_tree:add(pf_fields["pf_flag_cmd_mpss_setmask19_clip"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_mediaplayer"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_type1"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_stillindex"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_clipindex"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+13, 3))
		elseif (cmd_name == "MPSp") then
			cmd_tree:add(pf_fields["pf_field_clip1maxlength"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_mpsp_clip2maxlength"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "CMPS") then
			cmd_tree:add(pf_fields["pf_field_clip1maxlength"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "CMPA") then
			cmd_tree:add(pf_fields["pf_field_clipindex"], tvbuf:range(pos+8, 1))
		elseif (cmd_name == "CMPC") then
			cmd_tree:add(pf_fields["pf_field_clipindex"], tvbuf:range(pos+8, 1))
		elseif (cmd_name == "CSTL") then
			cmd_tree:add(pf_fields["pf_field_stillindex"], tvbuf:range(pos+8, 1))
		elseif (cmd_name == "MPCS") then
			cmd_tree:add(pf_fields["pf_field_clipbank"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_isused"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_filename"], tvbuf:range(pos+10, 64))
			cmd_tree:add(pf_fields["pf_field_frames"], tvbuf:range(pos+74, 2))
		elseif (cmd_name == "SMPC") then
			cmd_tree:add(pf_fields["pf_field_clipbank"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_filename"], tvbuf:range(pos+10, 64))
			cmd_tree:add(pf_fields["pf_field_frames"], tvbuf:range(pos+74, 2))
		elseif (cmd_name == "MPAS") then
			cmd_tree:add(pf_fields["pf_field_clipbank"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_isused"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_cmd_mpas_hash"], tvbuf:range(pos+10, 16))
			cmd_tree:add(pf_fields["pf_field_filename"], tvbuf:range(pos+26, 64))
		elseif (cmd_name == "MPfe") then
			cmd_tree:add(pf_fields["pf_cmd_mpfe_type"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_cmd_mpfe_index"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_isused"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_cmd_mpfe_hash"], tvbuf:range(pos+13, 16))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+29, 1))
			cmd_tree:add(pf_fields["pf_cmd_mpfe_filenamestringlength"], tvbuf:range(pos+31, 1)) 
			if (tvbuf:range(pos+31, 1):uint() > 0) then
				cmd_tree:add(pf_fields["pf_field_filename"], tvbuf:range(pos+32, tvbuf:range(pos+31, 1):uint()))
			end
		elseif (cmd_name == "MRPr") then
			local cmd_mrpr_state_tree = cmd_tree:add(pf_fields["pf_cmd_mrpr_state"], tvbuf:range(pos+8, 1))
			cmd_mrpr_state_tree:add(pf_fields["pf_flag_cmd_mrpr_state_running"], tvbuf:range(pos+8, 1))
			cmd_mrpr_state_tree:add(pf_fields["pf_flag_cmd_mrpr_state_waiting"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd_mrpr_islooping"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_index0"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "MAct") then
			cmd_tree:add(pf_fields["pf_field_index0"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_mact_action"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "MRCP") then
			cmd_tree:add(pf_fields["pf_cmd_mrcp_setmask20"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd_mrcp_looping"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "MPrp") then
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd_mprp_macroindex"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_isused"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_namestringlength"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_descriptionstringlength"], tvbuf:range(pos+14, 2))
			
			if (tvbuf:range(pos+12, 2):uint() > 0) then
				cmd_tree:add(pf_fields["pf_cmd_mprp_name1"], tvbuf:range(pos+16, tvbuf:range(pos+12, 2):uint()))
			end
			
			if (tvbuf:range(pos+14, 2):uint() > 0) then
				cmd_tree:add(pf_fields["pf_field_description"], tvbuf:range(pos+16+tvbuf:range(pos+12, 2):uint(), tvbuf:range(pos+14, 2):uint()))
			end
		elseif (cmd_name == "CMPr") then
			local cmd_cmpr_setmask21_tree = cmd_tree:add(pf_fields["pf_cmd_cmpr_setmask21"], tvbuf:range(pos+8, 1))
			cmd_cmpr_setmask21_tree:add(pf_fields["pf_flag_cmd_cmpr_setmask21_name"], tvbuf:range(pos+8, 1))
			cmd_cmpr_setmask21_tree:add(pf_fields["pf_flag_cmd_cmpr_setmask21_description"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_index0"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_namestringlength"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_descriptionstringlength"], tvbuf:range(pos+14, 2))
			
			if (tvbuf:range(pos+12, 2):uint() > 0) then
				cmd_tree:add(pf_fields["pf_field_name2"], tvbuf:range(pos+16, tvbuf:range(pos+12, 2):uint()))
			end
			
			if (tvbuf:range(pos+14, 2):uint() > 0) then
				cmd_tree:add(pf_fields["pf_field_description"], tvbuf:range(pos+16+tvbuf:range(pos+12, 2):uint(), tvbuf:range(pos+14, 2):uint()))
			end
		elseif (cmd_name == "MSRc") then
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd_msrc_index1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_namestringlength"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_descriptionstringlength"], tvbuf:range(pos+12, 2))
			
			if (tvbuf:range(pos+10, 2):uint() > 0) then
				cmd_tree:add(pf_fields["pf_field_name2"], tvbuf:range(pos+14, tvbuf:range(pos+10, 2):uint()))
			end
			
			if (tvbuf:range(pos+12, 2):uint() > 0) then
				cmd_tree:add(pf_fields["pf_field_description"], tvbuf:range(pos+14+tvbuf:range(pos+10, 2):uint(), tvbuf:range(pos+12, 2):uint()))
			end
		elseif (cmd_name == "MSlp") then
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_frames"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "MRcS") then
			cmd_tree:add(pf_fields["pf_cmd_mrcs_isrecording"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_index0"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "SSrc") then
			cmd_tree:add(pf_fields["pf_field_ssrc_id"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_keysource"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_foreground"], tvbuf:range(pos+14, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+15, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_invertkey0"], tvbuf:range(pos+20, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+21, 3))
		elseif (cmd_name == "SSBd") then
			cmd_tree:add(pf_fields["pf_field_ssrc_id"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_borderenabled"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevel"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_borderouterwidth"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_borderinnerwidth"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_borderoutersoftness"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_borderinnersoftness"], tvbuf:range(pos+17, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelsoftness"], tvbuf:range(pos+18, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelposition"], tvbuf:range(pos+19, 1))
			cmd_tree:add(pf_fields["pf_field_borderhue"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_bordersaturation"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_borderluma"], tvbuf:range(pos+24, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcedirection"], tvbuf:range(pos+26, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcealtitude"], tvbuf:range(pos+28, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+29, 3))
		elseif (cmd_name == "CSSc") then
			local cmd_cssc_setmask22_tree = cmd_tree:add(pf_fields["pf_cmd_cssc_setmask22"], tvbuf:range(pos+8, 1))
			cmd_cssc_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_fillsource"], tvbuf:range(pos+8, 1))
			cmd_cssc_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_keysource"], tvbuf:range(pos+8, 1))
			cmd_cssc_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_foreground"], tvbuf:range(pos+8, 1))
			cmd_cssc_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_premultiplied"], tvbuf:range(pos+8, 1))
			cmd_cssc_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_clip"], tvbuf:range(pos+8, 1))
			cmd_cssc_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_gain"], tvbuf:range(pos+8, 1))
			cmd_cssc_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_invert"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_ssrc_id"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_fillsource"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_keysource"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_foreground"], tvbuf:range(pos+14, 1))
			cmd_tree:add(pf_fields["pf_field_premultiplied"], tvbuf:range(pos+15, 1))
			cmd_tree:add(pf_fields["pf_field_clip"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_gain0"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_invertkey0"], tvbuf:range(pos+20, 1))
			cmd_tree:add(pf_fields["pf_field_padding"], tvbuf:range(pos+21, 3))
		elseif (cmd_name == "CSBd") then
			local cmd_csbd_setmask22_tree = cmd_tree:add(pf_fields["pf_cmd_csbd_setmask22"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_enabled"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_bevel"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_outerwidth"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_innerwidth"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_outersoftness"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_innersoftness"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_bevelsoftness"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_bevelpos"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_hue"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_saturation"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_luma"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_direction"], tvbuf:range(pos+8, 2))
			cmd_csbd_setmask22_tree:add(pf_fields["pf_flag_cmd_cssc_setmask22_altitude"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_field_ssrc_id"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_borderenabled"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevel"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_padding"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_borderouterwidth"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_borderinnerwidth"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_borderoutersoftness"], tvbuf:range(pos+18, 1))
			cmd_tree:add(pf_fields["pf_field_borderinnersoftness"], tvbuf:range(pos+19, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelsoftness"], tvbuf:range(pos+20, 1))
			cmd_tree:add(pf_fields["pf_field_borderbevelposition"], tvbuf:range(pos+21, 1))
			cmd_tree:add(pf_fields["pf_field_borderhue"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_bordersaturation"], tvbuf:range(pos+24, 2))
			cmd_tree:add(pf_fields["pf_field_borderluma"], tvbuf:range(pos+26, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcedirection"], tvbuf:range(pos+28, 2))
			cmd_tree:add(pf_fields["pf_field_lightsourcealtitude"], tvbuf:range(pos+30, 1))
			cmd_tree:add(pf_fields["pf_field_padding"], tvbuf:range(pos+31, 1))
		elseif (cmd_name == "SSBP") then
			cmd_tree:add(pf_fields["pf_field_ssrc_id"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_box"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_enabled"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_padding"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_inputsource0"], tvbuf:range(pos+12, 2))
			cmd_tree:add(pf_fields["pf_field_positionx2"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_positiony2"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_size"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_cropped"], tvbuf:range(pos+20, 1))
			cmd_tree:add(pf_fields["pf_field_croptop"], tvbuf:range(pos+22, 2))
			cmd_tree:add(pf_fields["pf_field_cropbottom"], tvbuf:range(pos+24, 2))
			cmd_tree:add(pf_fields["pf_field_cropleft"], tvbuf:range(pos+26, 2))
			cmd_tree:add(pf_fields["pf_field_cropright"], tvbuf:range(pos+28, 2))
			cmd_tree:add(pf_fields["pf_field_padding"], tvbuf:range(pos+30, 2))
		elseif (cmd_name == "CSBP") then
			local cmd_csbp_setmask23_tree = cmd_tree:add(pf_fields["pf_cmd_csbp_setmask23"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_enabled"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_inputsource"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_positionx"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_positiony"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_size"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_cropped"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_croptop"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_cropbottom"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_cropleft"], tvbuf:range(pos+8, 2))
			cmd_csbp_setmask23_tree:add(pf_fields["pf_flag_cmd_csbp_setmask23_cropright"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_field_ssrc_id"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_box"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_enabled"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_padding"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_inputsource0"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_positionx2"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_positiony2"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_size"], tvbuf:range(pos+19, 3))
			cmd_tree:add(pf_fields["pf_field_cropped"], tvbuf:range(pos+22, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+23, 1))
			cmd_tree:add(pf_fields["pf_field_croptop"], tvbuf:range(pos+24, 2))
			cmd_tree:add(pf_fields["pf_field_cropbottom"], tvbuf:range(pos+26, 2))
			cmd_tree:add(pf_fields["pf_field_cropleft"], tvbuf:range(pos+28, 2))
			cmd_tree:add(pf_fields["pf_field_cropright"], tvbuf:range(pos+30, 2))
		elseif (cmd_name == "AMIP") then
			cmd_tree:add(pf_fields["pf_field_audiosource"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_amip_type2"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+11, 3))
			cmd_tree:add(pf_fields["pf_cmd_amip_frommediaplayer"], tvbuf:range(pos+14, 1))
			cmd_tree:add(pf_fields["pf_cmd_amip_plugtype"], tvbuf:range(pos+15, 1))
			cmd_tree:add(pf_fields["pf_field_mixoption"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+17, 1))
			cmd_tree:add(pf_fields["pf_field_volume"], tvbuf:range(pos+18, 2))
			cmd_tree:add(pf_fields["pf_field_balance"], tvbuf:range(pos+20, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+22, 1))
		elseif (cmd_name == "CAMI") then
			local cmd_cami_setmask24_tree = cmd_tree:add(pf_fields["pf_cmd_cami_setmask24"], tvbuf:range(pos+8, 1))
			cmd_cami_setmask24_tree:add(pf_fields["pf_flag_cmd_cami_setmask24_mixoption"], tvbuf:range(pos+8, 1))
			cmd_cami_setmask24_tree:add(pf_fields["pf_flag_cmd_cami_setmask24_volume"], tvbuf:range(pos+8, 1))
			cmd_cami_setmask24_tree:add(pf_fields["pf_flag_cmd_cami_setmask24_balance"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_audiosource"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_mixoption"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_volume"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_balance"], tvbuf:range(pos+16, 2))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+18, 1))
		elseif (cmd_name == "AMMO") then
			cmd_tree:add(pf_fields["pf_field_volume"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_ammo_unknown9"], tvbuf:range(pos+10, 6))
		elseif (cmd_name == "CAMM") then
			cmd_tree:add(pf_fields["pf_cmd_camm_setmask25"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_volume"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_unknown3"], tvbuf:range(pos+12, 4))
		elseif (cmd_name == "AMmO") then
			cmd_tree:add(pf_fields["pf_field_monitoraudio"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_volume"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_mute"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_solo"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_soloinput"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_dim"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+17, 3))
		elseif (cmd_name == "CAMm") then
			local cmd_camm_setmask26_tree = cmd_tree:add(pf_fields["pf_cmd_camm_setmask26"], tvbuf:range(pos+8, 1))
			cmd_camm_setmask26_tree:add(pf_fields["pf_flag_cmd_camm_setmask26_monitoraudio"], tvbuf:range(pos+8, 1))
			cmd_camm_setmask26_tree:add(pf_fields["pf_flag_cmd_camm_setmask26_volume"], tvbuf:range(pos+8, 1))
			cmd_camm_setmask26_tree:add(pf_fields["pf_flag_cmd_camm_setmask26_mute"], tvbuf:range(pos+8, 1))
			cmd_camm_setmask26_tree:add(pf_fields["pf_flag_cmd_camm_setmask26_solo"], tvbuf:range(pos+8, 1))
			cmd_camm_setmask26_tree:add(pf_fields["pf_flag_cmd_camm_setmask26_soloinput"], tvbuf:range(pos+8, 1))
			cmd_camm_setmask26_tree:add(pf_fields["pf_flag_cmd_camm_setmask26_dim"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_monitoraudio"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_field_volume"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_field_mute"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_solo"], tvbuf:range(pos+13, 1))
			cmd_tree:add(pf_fields["pf_field_soloinput"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_field_dim"], tvbuf:range(pos+16, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+17, 3))
		elseif (cmd_name == "SALN") then
			cmd_tree:add(pf_fields["pf_cmd_saln_enable"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+9, 3))
		elseif (cmd_name == "AMLv") then
			cmd_tree:add(pf_fields["pf_field_sources1"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_amlv_sourcesagain"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_cmd_amlv_masterleft"], tvbuf:range(pos+12, 4))
			cmd_tree:add(pf_fields["pf_cmd_amlv_masterright"], tvbuf:range(pos+16, 4))
			cmd_tree:add(pf_fields["pf_cmd_amlv_masterpeakleft"], tvbuf:range(pos+20, 4))
			cmd_tree:add(pf_fields["pf_cmd_amlv_masterpeakright"], tvbuf:range(pos+24, 4))
			cmd_tree:add(pf_fields["pf_cmd_amlv_monitor"], tvbuf:range(pos+28, 4))
			cmd_tree:add(pf_fields["pf_field_unknown5"], tvbuf:range(pos+32, 12))
		elseif (cmd_name == "RAMP") then
			local cmd_ramp_setmask27_tree = cmd_tree:add(pf_fields["pf_cmd_ramp_setmask27"], tvbuf:range(pos+8, 1))
			cmd_ramp_setmask27_tree:add(pf_fields["pf_flag_cmd_ramp_setmask27_"], tvbuf:range(pos+8, 1))
			cmd_ramp_setmask27_tree:add(pf_fields["pf_flag_cmd_ramp_setmask27_inputs"], tvbuf:range(pos+8, 1))
			cmd_ramp_setmask27_tree:add(pf_fields["pf_flag_cmd_ramp_setmask27_master"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_field_unknown1"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_cmd_ramp_inputsource1"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_cmd_ramp_master"], tvbuf:range(pos+12, 1))
			cmd_tree:add(pf_fields["pf_field_unknown2"], tvbuf:range(pos+13, 3))
		elseif (cmd_name == "AMTl") then
			cmd_tree:add(pf_fields["pf_field_sources1"], tvbuf:range(pos+8, 2))
		elseif (cmd_name == "TlIn") then
			cmd_tree:add(pf_fields["pf_field_sources1"], tvbuf:range(pos+8, 2))
		elseif (cmd_name == "TlSr") then
			cmd_tree:add(pf_fields["pf_field_sources1"], tvbuf:range(pos+8, 2))
		elseif (cmd_name == "Time") then
			cmd_tree:add(pf_fields["pf_cmd_time_hour"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd_time_minute"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_cmd_time_second"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_cmd_time_frame"], tvbuf:range(pos+11, 1))
			cmd_tree:add(pf_fields["pf_field_unknown3"], tvbuf:range(pos+12, 4))
		elseif (cmd_name == "SRsv") then
			cmd_tree:add(pf_fields["pf_field_unknown3"], tvbuf:range(pos+8, 4))
		elseif (cmd_name == "SRcl") then
			cmd_tree:add(pf_fields["pf_field_unknown3"], tvbuf:range(pos+8, 4))
		elseif (cmd_name == "LKOB") then
			cmd_tree:add(pf_fields["pf_cmd_lokb_storeId"], tvbuf:range(pos+9, 1))
		elseif (cmd_name == "LOCK") then
			cmd_tree:add(pf_fields["pf_cmd_lock_storeId"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_lock_state"], tvbuf:range(pos+10, 2))
		elseif (cmd_name == "LKST") then
			cmd_tree:add(pf_fields["pf_cmd_lkst_storeId"], tvbuf:range(pos+9, 1))
			cmd_tree:add(pf_fields["pf_cmd_lkst_state"], tvbuf:range(pos+10, 1))
		elseif (cmd_name == "InCm") then
			cmd_tree:add(pf_fields["pf_cmd_incm_state1"], tvbuf:range(pos+8, 1))
			cmd_tree:add(pf_fields["pf_cmd_incm_state2"], tvbuf:range(pos+9, 1))
		elseif (cmd_name == "FTSD") then
			cmd_tree:add(pf_fields["pf_cmd_ftsd_id"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_ftsd_storeId"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_cmd_ftsd_index"], tvbuf:range(pos+15, 1))
			cmd_tree:add(pf_fields["pf_cmd_ftsd_size"], tvbuf:range(pos+16, 4))
			cmd_tree:add(pf_fields["pf_cmd_ftsd_op"], tvbuf:range(pos+20, 2))
		elseif (cmd_name == "FTCD") then
			cmd_tree:add(pf_fields["pf_cmd_ftcd_id"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_ftcd_chunk_size"], tvbuf:range(pos+14, 2))
			cmd_tree:add(pf_fields["pf_cmd_ftcd_chunk_count"], tvbuf:range(pos+16, 2))
		elseif (cmd_name == "FTDa") then
			cmd_tree:add(pf_fields["pf_cmd_ftda_id"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_ftda_size"], tvbuf:range(pos+10, 2))
			cmd_tree:add(pf_fields["pf_cmd_ftda_data"], tvbuf:range(pos+12, tvbuf:range(pos+10, 2):uint()))
		elseif (cmd_name == "FTSU") then
			cmd_tree:add(pf_fields["pf_cmd_ftsu_id"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_ftsu_storeId"], tvbuf:range(pos+10, 1))
			cmd_tree:add(pf_fields["pf_cmd_ftsu_index"], tvbuf:range(pos+15, 1))
		elseif (cmd_name == "FTUA") then
			cmd_tree:add(pf_fields["pf_cmd_ftua_id"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_ftua_index"], tvbuf:range(pos+11, 1))
		elseif (cmd_name == "FTDC") then
			cmd_tree:add(pf_fields["pf_cmd_ftdc_id"], tvbuf:range(pos+8, 2))
		elseif (cmd_name == "FTFD") then
			cmd_tree:add(pf_fields["pf_cmd_ftfd_id"], tvbuf:range(pos+8, 2))
			cmd_tree:add(pf_fields["pf_cmd_ftfd_filename"], tvbuf:range(pos+10, 192))
			cmd_tree:add(pf_fields["pf_cmd_ftfd_hash"], tvbuf:range(pos+202, 16))
		else
		end
		
		pos = pos + cmd_length
		pktlen_remaining = pktlen_remaining - cmd_length        
		
		cmd_count = cmd_count + 1
	end
		if cmd_count == 1 then
			packet_type = "Command"
			pktinfo.cols.info:set("(".. packet_type .." ".. cmd_name ..", Len ".. packet_length ..")")
		else
			pktinfo.cols.info:set("(".. cmd_count .." ".. packet_type ..", Len ".. packet_length ..")")
		end
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
