----------------------------------------
-- script-name: mc-xml.lua
--
-- authors: Iñigo Ruiz <iruizr7@gmail.com>
-- Mikel Ramos (mikel.ramos@ehu.eus)

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
-- This script provides a single place to add all of the XML MIME types of MCX.

-- Add all new MIME types of MCPTT protocol to the XML dissector
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-info+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-mbms-usage-info+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-location-info+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-affiliation-command+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-floor-request+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-signed+xml", Dissector.get("xml"))

-- Configuration documents
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-ue-init-config+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-ue-config+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-user-profile+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcptt-service-config+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.oma.poc.groups+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcdata-ue-config+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcdata-user-profile+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcdata-service-config+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcvideo-ue-config+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcvideo-user-profile+xml", Dissector.get("xml"))
DissectorTable.get("media_type"):add("application/vnd.3gpp.mcvideo-service-config+xml", Dissector.get("xml"))


