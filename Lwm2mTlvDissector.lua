-- Dissector for the TLV format specified in LWM2M
-- Copyright (C) 2015 Christoph Burger-Scheidlin
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
-- 
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

p_tlv = Proto("tlv", "LWM2M TLV")

coap_payload_f = Field.new("coap.payload")
coap_payload_desc_f = Field.new("coap.opt.ctype")

local identifiers = {
        [0x00] = "Object Instance",
        [0x01] = "Resource Instance",
        [0x02] = "Multiple Resources",
        [0x03] = "Resource with value",
}

local length_identifier = {
        [0x00] = "1 byte identifier",
        [0x01] = "2 bytes identifier",
}

local length_type = {
        [0x00] = "No length field",
        [0x01] = "1 byte length field",
        [0x02] = "2 bytes length field",
        [0x03] = "3 bytes length field",
}

f_tlv_type_type                 = ProtoField.uint8("tlv.type.type",   "Type of Identifier", base.DEC, identifiers, 0xC0)
f_tlv_type_length_of_identifier = ProtoField.uint8("tlv.type.loi",    "Length of Identifier", base.DEC, length_identifier, 0x20)
f_tlv_type_length_of_length     = ProtoField.uint8("tlv.type.lol",    "Length of Length", base.DEC, length_type, 0x18)
f_tlv_type_length               = ProtoField.uint8("tlv.type.length", "Length", base.DEC, nil, 0x07)
f_tlv_type_ignored              = ProtoField.uint8("tlv.type.ignored", "Ignored", base.DEC, nil, 0x07)

f_tlv_identifier = ProtoField.uint16("tlv.identifier", "Identifier", base.DEC)
f_tlv_length     = ProtoField.uint32("tlv.length", "Length", base.DEC)
f_tlv_value      = ProtoField.bytes("tlv.value", "Value")

p_tlv.fields = { f_tlv_type_type, f_tlv_type_length_of_identifier, f_tlv_type_length_of_length, f_tlv_type_length, f_tlv_type_ignored, f_tlv_identifier, f_tlv_length, f_tlv_value }

function addTlvHeader(buffer, element, length_of_identifier, length_of_length, length_of_value)
    local header = element:add(buffer(0, 1+length_of_identifier+length_of_length), "TLV Header")
    header:add(f_tlv_type_type, buffer(0,1))
    header:add(f_tlv_type_length_of_identifier, buffer(0,1))
    header:add(f_tlv_type_length_of_length, buffer(0,1))

    if length_of_length == 0 then
        header:add(f_tlv_type_length, buffer(0,1))
    else
        header:add(f_tlv_type_ignored, buffer(0,1))
    end

    header:add(f_tlv_identifier, buffer(1, length_of_identifier))
    
    if length_of_length > 0 then
        header:add(f_tlv_length, buffer(1+length_of_identifier, length_of_length))
    else
        header:add("Inline length of " .. tostring(length_of_value))
    end    
end

function addTlvElement(buffer, tree, length_of_identifier, length_of_length, length_of_value)
    local elementId  = buffer(0,1):bitfield(0,2)
    local identifier = buffer(1,length_of_identifier):uint() 

    local value = buffer(1+length_of_identifier+length_of_length, length_of_value)
    if elementId == 0x03 or elementId == 0x01 then
        local text = identifiers[elementId]
                  .. ", ID: "
                  .. tostring(identifier)
                  .. " ("
                  .. tostring(length_of_value)
                  .. " Bytes): "
                  .. tostring(value)

        local element = tree:add(buffer, text)
        addTlvHeader(buffer, element, length_of_identifier, length_of_length, length_of_value)
        element:add(f_tlv_value, value)
    else
        local text = identifiers[elementId]
            .. ", ID: "
            .. tostring(identifier)
            .. " ("
            .. tostring(length_of_value)
            .. " Bytes)"

        local element = tree:add(buffer, text)
        addTlvHeader(buffer, element, length_of_identifier, length_of_length, length_of_value)

        parseArrayOfElements(value, element)
    end
end

function parseTLV(buffer, tree)
    local length_of_identifier = buffer(0,1):bitfield(2,1) + 1
    local length_of_length     = buffer(0,1):bitfield(3,2)
    local length_of_value      = buffer(0,1):bitfield(5,3)

    if length_of_length > 0 then
        length_of_value = buffer(1+length_of_identifier, length_of_length):uint()
    end

    local totalLength = 1 + length_of_identifier + length_of_length + length_of_value;
    addTlvElement(buffer(0,totalLength), tree, length_of_identifier, length_of_length, length_of_value)

    return totalLength
end

function parseArrayOfElements(buffer, tree)
    local length = buffer:len()
    local offset = 0

    while length > 0 do
        local parsed = parseTLV(buffer(offset, length), tree)
        length = length - parsed
        offset = offset + parsed
    end
end

-- function p_tlv.dissector(buffer, pinfo, tree)
--     local coap_payload = coap_payload_f()
--     local coap_payload_description = coap_payload_desc_f()
--     if coap_payload and coap_payload_description and coap_payload_description.range:uint() == 1542 then
--         local offset = coap_payload.range:offset()
--         local length = coap_payload.range:len()
--         local tlvtree = tree:add(p_tlv, buffer(offset))
--         
--         parseArrayOfElements(buffer(offset, length), tlvtree)
--     end
-- end

--register_postdissector(p_tlv)

function p_tlv.dissector(buffer, pinfo, tree)
    local tlvtree = tree:add(p_tlv, buffer)
    parseArrayOfElements(buffer, tlvtree)
end

do
    local media_type_table = DissectorTable.get("media_type")
    media_type_table:add("Unknown Type 1542", p_tlv)
end