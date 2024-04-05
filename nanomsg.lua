-- protocol
nanomsg_proto = Proto("nanomsg","nanomsg protocol")

-- header messages
local f_header = ProtoField.bytes("nanomsg.header", "Header")
local f_protocol = ProtoField.string("nanomsg.protocol", "Protocol")
local f_reserved = ProtoField.uint16("nanomsg.reserved", "Reserved", base.HEX)

-- payload messages
local f_payload_size = ProtoField.uint64("nanomsg.payload_size", "Payload Size")
local f_payload = ProtoField.bytes("nanomsg.payload", "Payload")

nanomsg_proto.fields = { f_header, f_protocol, f_reserved, f_body, f_payload_size, f_payload }

-- scalability protocols looktup table
local protocols = {
    [1*16 + 0] = "PAIR",
    [2*16 + 0] = "PUB",
    [2*16 + 1] = "SUB",
    [3*16 + 0] = "REQ",
    [3*16 + 1] = "REP",
    [5*16 + 0] = "PUSH",
    [5*16 + 1] = "PULL",
    [6*16 + 2] = "SURVEYOR",
    [6*16 + 3] = "RESPONDENT",
    [7*16 + 0] = "BUS",
}

-- dissector
function nanomsg_proto.dissector(buffer,pinfo,tree)
    if buffer(0,4):bytes() == ByteArray.new("00535000") then
        -- header
        dissect_header(buffer,pinfo,tree)
    else
        -- payload
        dissect_payload(buffer,pinfo,tree)
    end
end

-- header dissector
function dissect_header(buffer,pinfo,tree)
    local protocol = protocols[buffer(4,2):uint()]

    local subtree = tree:add(nanomsg_proto,buffer(),"nanomsg")
    subtree:add(f_header,buffer(0,4))
    subtree:add(f_protocol, protocol)
    subtree:add(f_reserved,buffer(6,2))

    pinfo.cols.protocol = "nanomsg"
    pinfo.cols.info = string.format("[%s]", protocol)
end

-- payload dissector
function dissect_payload(buffer,pinfo,tree)
    local subtree = tree:add(nanomsg_proto, buffer(), "nanomsg")

    subtree:add(f_payload_size, buffer(0,8))
    subtree:add(f_payload,buffer(8))

    pinfo.cols.protocol = "nanomsg"

    -- -- call the msgpack dissector
    -- local msgpack = Dissector.get("msgpack")
    -- dissector:call(msgpack, buffer(8):tvb(), pinfo, tree)

end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 5555
tcp_table:add(4201,nanomsg_proto)
tcp_table:add(4202,nanomsg_proto)
