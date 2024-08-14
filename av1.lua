------------------------------------------------------------------------------------------------
-- Lua Dissector for AV1 in RTP
------------------------------------------------------------------------------------------------
do
    local av1 = Proto("av1", "AV1")

    local prefs = av1.prefs
    prefs.dyn_pt = Pref.uint("AV1 dynamic payload type", 0, "XXX")

    local obu_types = {
        [0] = "Reserved",
        [1] = "OBU_SEQUENCE_HEADER",
        [2] = "OBU_TEMPORAL_DELIMITER",
        [3] = "OBU_FRAME_HEADER",
        [4] = "OBU_TILE_GROUP",
        [5] = "OBU_METADATA",
        [6] = "OBU_FRAME",
        [7] = "OBU_REDUNDANT_FRAME_HEADER",
        [8] = "OBU_TILE_LIST",
        [15] = "OBU_PADDING"
    }

    local f = {
        aggr = ProtoField.uint8("av1.AggregateHeader", "Aggregate Header", base.HEX),
        continuation = ProtoField.bool("av1.first_continuation", "1st OBU is continuation", 8, nil, 0x80,        "Does the first OBU continue from the previous packet"),
        continues = ProtoField.bool("av1.last_continues", "Last OBU continues", 8, nil, 0x40,        "Does the last OBU continue in the next packet"),
        num_obus = ProtoField.uint8("av1.num_obus", "Number of OBUs", base.DEC, nil, 0x30),
        cvs_start = ProtoField.bool("av1.cvs_start", "CVS start", 8, nil, 0x08),
        reserved = ProtoField.uint8("av1.reserved", "Reserved", base.HEX, nil, 0x07),
        data = ProtoField.bytes("av1.payload_data", "Payload Data"),
        obu_len = ProtoField.bytes("av1.obu_len", "OBU length"),
        obu_data = ProtoField.bytes("av1.obu_data", "OBU data"),
        obu_header = ProtoField.uint8("av1.obu_header", "OBU header", base.HEX),
        obu_header_forbidden = ProtoField.bool("av1.ObuHeader.ForbiddenBit", "Forbidden Bit", 8, nil, 0x80),
        obu_type = ProtoField.uint8("av1.obu_header.obu_type", "OBU type", base.HEX, obu_types, 0x78),
        obu_extension_flag = ProtoField.bool("av1.obu_header.extension_flag", "Extension Flag", 8, nil, 0x04),
        obu_has_size_field = ProtoField.bool("av1.obu_header.has_size_field", "Has Size Field", 8, nil, 0x02),
        obu_reserved_1bit = ProtoField.bool("av1.obu_header.reserved_bit", "Reserved 1 Bit", 8, nil, 0x01)
    }
    av1.fields = f

    local function leb128(range)
        local value = 0
        local leb128bytes = 0
        for i = 0, 8 do
            local leb128_byte = range(i, 1):uint()
            value = bit.bor(value, bit.lshift(bit.band(leb128_byte, 0x7f), (i * 7)))
            leb128bytes = leb128bytes + 1
            if bit.band(leb128_byte, 0x80) == 0 then
                break
            end
        end

        return value, leb128bytes
    end

    function av1.dissector(tvb, pinfo, tree)
        local subtree = tree:add(av1, tvb(), "AV1 Data")
        local aggr_range = tvb(0, 1)
        local aggr = subtree:add(f.aggr, aggr_range)
        aggr:add(f.continuation, aggr_range)
        aggr:add(f.continues, aggr_range)
        aggr:add(f.num_obus, aggr_range)
        local is_continuation = aggr_range:bitfield(0, 1)
        local num_obus = aggr_range:bitfield(2, 2)
        aggr:add(f.cvs_start, aggr_range)
        aggr:add(f.reserved, aggr_range)

        local function add_header(header, header_byte)
            header:add(f.obu_header_forbidden, header_byte)
            header:add(f.obu_type, header_byte)
            header:add(f.obu_extension_flag, header_byte)
            header:add(f.obu_has_size_field, header_byte)
            header:add(f.obu_reserved_1bit, header_byte)
        end


        local obu_range = tvb(1)
        local is_first = true
        while true do
            if num_obus == 1 then
                local header = subtree:add(f.obu_data, obu_range)
                if is_continuation ~= 1 then 
                    local header_byte = obu_range(0, 1)
                    add_header(header, header_byte)
                end
                break
            else
                if obu_range:len() == 0 then
                    break
                end
                local length, bytes = leb128(obu_range)
                local data = obu_range(bytes, length)
                subtree:add(f.obu_len, obu_range(0, bytes)):append_text(" (" .. length .. ")")
                local header = subtree:add(f.obu_data, data)
                if not (is_first and is_continuation == 1) then
                    local header_byte = data(0, 1)
                    add_header(header, header_byte)
                end

                obu_range = obu_range(bytes + length)

                if num_obus ~= 0 then
                    num_obus = num_obus - 1
                end
            end
            is_first = false
        end
    end

    -- register dissector to dynamic payload type dissectorTable
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")
    dyn_payload_type_table:add("av1", av1)

    -- register dissector to RTP payload type
    local payload_type_table = DissectorTable.get("rtp.pt")
    local old_dissector = nil
    local old_dyn_pt = 0
    function av1.init()
        if (prefs.dyn_pt ~= old_dyn_pt) then
            if (old_dyn_pt > 0) then
                if (old_dissector == nil) then
                    payload_type_table:remove(old_dyn_pt, av1)
                else
                    payload_type_table:add(old_dyn_pt, old_dissector)
                end
            end
            old_dyn_pt = prefs.dyn_pt
            old_dissector = payload_type_table:get_dissector(old_dyn_pt)
            if (prefs.dyn_pt > 0) then
                payload_type_table:add(prefs.dyn_pt, av1)
            end
        end
    end
end
