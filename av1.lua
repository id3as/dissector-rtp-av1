-- Lua Dissector for AV1 in RTP
--
--
------------------------------------------------------------------------------------------------
do
    local av1 = Proto("av1", "AV1")

    local prefs = av1.prefs
    prefs.dyn_pt = Pref.uint("AV1 dynamic payload type", 0, "XXX")

    local F = av1.fields

    F.AGGR = ProtoField.uint8("av1.AggregateHeader", "Aggregate Header", base.HEX)

    F.CONTINUATION = ProtoField.bool("av1.Continuation", "1st OBU is continuation", 8, nil, 0x80,
        "Does the first OBU continue from the previous packet")
    F.CONTINUES = ProtoField.bool("av1.Continues", "Last OBU continues", 8, nil, 0x40,
        "Does the last OBU continue in the next packet")
    F.NUM_OBUS = ProtoField.uint8("av1.NumObus", "Number of OBUs", base.DEC, nil, 0x30)
    F.CVS_START = ProtoField.bool("av1.CvsStart", "CVS start", 8, nil, 0x08)
    F.RESERVED = ProtoField.uint8("av1.Reserved", "Reserved", base.HEX, nil, 0x07)


    F.DATA = ProtoField.bytes("av1.PayloadData", "Payload Data")

    F.OBU_LEN = ProtoField.bytes("av1.ObuLen", "OBU length")
    F.OBU_DATA = ProtoField.bytes("av1.ObuData", "OBU data")

    F.OBU_HEADER = ProtoField.uint8("av1.ObuHeader", "OBU header", base.HEX)

    F.OBU_HEADER_FORBIDDEN = ProtoField.bool("av1.ObuHeader.ForbiddenBit", "Forbidden Bit", 8, nil, 0x80)

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

    F.OBU_TYPE = ProtoField.uint8("av1.ObuHeader.ObuType", "OBU type", base.HEX, obu_types, 0x78)
    F.OBU_EXTENSION_FLAG = ProtoField.bool("av1.ObuHeader.ExtensionFlag", "Extension Flag", 8, nil, 0x04)
    F.OBU_HAS_SIZE_FIELD = ProtoField.bool("av1.ObuHeader.HasSizeField", "Has Size Field", 8, nil, 0x02)
    F.OBU_RESERVED_1BIT = ProtoField.bool("av1.ObuHeader.ReservedBit", "Reserved 1 Bit", 8, nil, 0x01)


    local function leb128(range)
        local value = 0
        local leb128bytes = 0
        for i = 0, 8 do
            local leb128_byte = range(i, 1):uint()
            value = bit.bor(value, bit.lshift(bit.band(leb128_byte, 0x7f), (i * 7)))
            print("Loop i=" .. i .. ", value=" .. value)
            leb128bytes = leb128bytes + 1
            if bit.band(leb128_byte, 0x80) == 0 then
                break
            end
        end

        return value, leb128bytes
    end

    function av1.dissector(tvb, pinfo, tree)
        print("HELLO AV1 dissector");
        local subtree = tree:add(av1, tvb(), "AV1 Data")
        local aggr_range = tvb(0, 1)
        local aggr = subtree:add(F.AGGR, aggr_range)
        aggr:add(F.CONTINUATION, aggr_range)
        aggr:add(F.CONTINUES, aggr_range)
        aggr:add(F.NUM_OBUS, aggr_range)
        local is_continuation = aggr_range:bitfield(0, 1)
        local num_obus = aggr_range:bitfield(2, 2)
        print("num_obus=" .. num_obus)
        aggr:add(F.CVS_START, aggr_range)
        aggr:add(F.RESERVED, aggr_range)

        -- subtree:add(F.DATA, tvb(1))

        local function add_header(header, header_byte)
            print("adding header: "..header_byte)
            header:add(F.OBU_HEADER_FORBIDDEN, header_byte)
            header:add(F.OBU_TYPE, header_byte)
            header:add(F.OBU_EXTENSION_FLAG, header_byte)
            header:add(F.OBU_HAS_SIZE_FIELD, header_byte)
            header:add(F.OBU_RESERVED_1BIT, header_byte)
        end


        local obu_range = tvb(1)
        local is_first = true
        while true do
            if num_obus == 1 then
                local header = subtree:add(F.OBU_DATA, obu_range)
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
                print("length=" .. length)
                subtree:add(F.OBU_LEN, obu_range(0, bytes)):append_text(" (" .. length .. ")")
                local header = subtree:add(F.OBU_DATA, data)
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
