import dpkt
import queue
import threading
import socket
import struct
from datetime import datetime, timedelta
import uuid
import time
from collections import defaultdict

from moni_dict import *
from moni_writer import *
from __main__ import file_process, file_puml, append_seq_ack

# Shared queue for packet transfer
packet_queue = queue.Queue()

# TCP reassembly buffer: (src_ip, dst_ip, src_port, dst_port) → stream bytes
tcp_streams = {}

class OPCUAMappings:
    STATUS_CODE = {
    0x00000000: "Good", 0x00000400: "Uncertain", 0x80000000: "Bad",

    # Common Good codes
    0x00000001: "GoodSubscriptionTransferred", 0x00000002: "GoodCompletesAsynchronously", 0x00000003: "GoodOverload", 0x00000004: "GoodClamped",

    # Common Uncertain codes
    0x40000000: "UncertainReferenceOutOfServer", 0x40000001: "UncertainNoCommunicationLastUsableValue", 0x40000002: "UncertainLastUsableValue",
    0x40000003: "UncertainSubstituteValue", 0x40000004: "UncertainInitialValue", 0x40000005: "UncertainSensorNotAccurate",
    0x40000006: "UncertainEngineeringUnitsExceeded", 0x40000007: "UncertainSubNormal",

    # Common Bad codes
    0x80010000: "BadUnexpectedError", 0x80020000: "BadInternalError", 0x80030000: "BadOutOfMemory",
    0x80040000: "BadResourceUnavailable", 0x80050000: "BadCommunicationError", 0x80060000: "BadEncodingError",
    0x80070000: "BadDecodingError", 0x80080000: "BadEncodingLimitsExceeded", 0x80090000: "BadRequestTooLarge",
    0x800A0000: "BadResponseTooLarge", 0x800B0000: "BadUnknownResponse", 0x800C0000: "BadTimeout",
    0x800D0000: "BadServiceUnsupported", 0x800E0000: "BadShutdown", 0x800F0000: "BadServerNotConnected",
    0x80100000: "BadServerHalted", 0x80110000: "BadNothingToDo", 0x80120000: "BadTooManyOperations",
    0x80130000: "BadTooManyMonitoredItems", 0x80140000: "BadDataTypeIdUnknown",

    # Access and permissions
    0x803A0000: "BadUserAccessDenied", 0x803B0000: "BadIdentityTokenInvalid", 0x803C0000: "BadIdentityTokenRejected",
    0x803D0000: "BadSecureChannelIdInvalid", 0x803E0000: "BadSecurityPolicyRejected", 0x803F0000: "BadSequenceNumberInvalid",

    # Data-related
    0x80430000: "BadOutOfRange", 0x80460000: "BadNotReadable", 0x80470000: "BadNotWritable",
    0x80480000: "BadOutOfRange", 0x80490000: "BadTypeMismatch", 0x804B0000: "BadDataEncodingUnsupported",

    # Node-related
    0x80650000: "BadNodeIdUnknown", 0x80660000: "BadNodeIdExists", 0x80670000: "BadNodeClassInvalid",
    0x80680000: "BadBrowseNameInvalid", 0x80690000: "BadNodeAttributesInvalid", 0x806A0000: "BadReferenceNotAllowed",
    0x806B0000: "BadBrowseDirectionInvalid", 0x806C0000: "BadNodeNotInView",
    }
    VARIANT_ID = {
        0: "Null",
        1: "Boolean",
        2: "SByte",
        3: "Byte",
        4: "Int16",
        5: "UInt16",
        6: "Int32",
        7: "UInt32",
        8: "Int64",
        9: "UInt64",
        10: "Float",
        11: "Double",
        12: "String",
        13: "DateTime",
        14: "Guid",
        15: "ByteString",
        16: "XmlElement",
        17: "NodeId",
        18: "ExpandedNodeId",
        19: "StatusCode",
        20: "QualifiedName",
        21: "LocalizedText",
        22: "ExtensionObject",
        23: "DataValue",
        24: "Variant",
        25: "DiagnosticInfo"
    }
    ATTR_ID = {
        1: "NodeId",
        2: "NodeClass",
        3: "BrowseName",
        4: "DisplayName",
        5: "Description",
        6: "WriteMask",
        7: "UserWriteMask",
        8: "IsAbstract",
        9: "Symmetric",
        10: "InverseName",
        11: "ContainsNoLoops",
        12: "EventNotifier",
        13: "Value",
        14: "DataType",
        15: "ValueRank",
        16: "ArrayDimensions",
        17: "AccessLevel",
        18: "UserAccessLevel",
        19: "MinimumSamplingInterval",
        20: "Historizing",
        21: "Executable",
        22: "UserExecutable",
        23: "DataTypeDefinition",
        24: "RolePermissions",
        25: "UserRolePermissions",
        26: "AccessRestrictions",
        27: "AccessLevelEx",
    }
    HEADER = {
        "MSG": "UA Secure Conversation", "OPN": "OpenSecureChannel Message",
        "HEL": "Hello Message", "ACK": "Acknowledge Message", "ERR": "Error Message", "CLO": "CloseSecureChannel Message"
    }
    MSG_ID = {
        461: "CreateSessionRequest",
        464: "CreateSessionResponse",
        467: "ActivateSessionRequest",
        470: "ActivateSessionResponse",
        554: "TranslateBrowsePathsToNodeIdsRequest",
        557: "TranslateBrowsePathsToNodeIdsResponse",
        631: "ReadRequest",
        634: "ReadResponse",
        673: "WriteRequest",
        676: "WriteResponse"
    }
    APPLICATION_TYPE = {
        0:"Server",
        1:"Client",
        2:"Server and Client",
        3:"Discovery Server"
    }

class ByteUtils:
    @staticmethod
    def byte_length(data: bytes):
        if len(data) < 4:
            return 0, None
        length = int.from_bytes(data[:4], 'little', signed=True)
        if length == -1:
            return 4, None
        return 4 + length, data[4:4 + length]

    @staticmethod
    def array_byte_length(data: bytes):
        if len(data) < 4:
            return None, None
        arr_len = int.from_bytes(data[:4], 'little', signed=True)
        offset = 4
        items = []
        for _ in range(arr_len):
            size, content = ByteUtils.byte_length(data[offset:])
            items.append(content)
            offset += size
        return offset, items

    @staticmethod
    def array_length_and_items(data: bytes):
        count = int.from_bytes(data[:4], 'little', signed=True)
        offset = 4
        items = []
        for _ in range(count):
            size, content = ByteUtils.byte_length(data[offset:])
            items.append(content)
            offset += size
        return count, items, offset

    @staticmethod
    def length_prefixed_encoding(data: bytes):
        tag = data[0]
        if tag == 0x00:
            return 0, 1, None, data[1:2]
        elif tag == 0x01:
            ns_len = 1
            id_len = 2
            return ns_len, id_len, data[1:1+ns_len], data[1+ns_len:1+ns_len+id_len]
        elif tag in (0x02, 0x03, 0x04, 0x05):
            ns_len = 2
            if tag == 0x02:
                id_len = 4
                id = data[3:3+id_len]
            elif tag == 0x03:
                id_len, id = ByteUtils.byte_length(data[2:])
            elif tag == 0x04:
                id_len = 16
                id = data[3:3+id_len]
            elif tag == 0x05:
                id_len, id = ByteUtils.byte_length(data[2:])
            return ns_len, id_len, data[1:1+ns_len], id
        return 0, 0, None, None

    @staticmethod
    def extension_object(data: bytes):
        type_ns_len, type_id_len, _, _ = ByteUtils.length_prefixed_encoding(data)
        if data[0] == 0x00:
            return 1 + type_ns_len + type_id_len + 1
        size, _ = ByteUtils.byte_length(data[1:])
        return 1 + type_ns_len + type_id_len + 1 + size

    @staticmethod
    def diagnosis_info(data: bytes):
        length = 1
        flags = data[0]
        for bit in (1, 2, 4, 8, 16):
            if flags & bit:
                length += 4
        if flags & 0x20:
            size, _ = ByteUtils.byte_length(data[length:])
            length += size
        if flags & 0x40:
            length += ByteUtils.diagnosis_info(data[length:])
        return length

    @staticmethod
    def read_qualifiedname(data: bytes):
        id, id_len = ByteUtils.parse_variant(0x05,data)
        offset = id_len
        name, name_len = ByteUtils.parse_variant(0x0C,data[offset:])
        offset = id_len + name_len
        return id, name, offset

    @staticmethod
    def parse_variant(mask: int, data: bytes):
        type_id = mask & 0x3F
        # Scalar types
        if type_id == 0:
            return None, 0
        elif type_id == 1:
            return bool(data[0]), 1
        elif type_id in (2, 3):
            fmt = '<b' if type_id == 2 else '<B'
            return struct.unpack_from(fmt, data)[0], 1
        elif type_id in (4, 5):
            fmt = '<h' if type_id == 4 else '<H'
            return struct.unpack_from(fmt, data)[0], 2
        elif type_id in (6, 7):
            fmt = '<i' if type_id == 6 else '<I'
            return struct.unpack_from(fmt, data)[0], 4
        elif type_id in (8, 9):  # Int64, UInt64
            fmt = '<q' if type_id == 8 else '<Q'
            return struct.unpack_from(fmt, data)[0], 8
        elif type_id == 10:  # Float
            return struct.unpack_from('<f', data)[0], 4
        elif type_id == 11:  # Double
            return struct.unpack_from('<d', data)[0], 8
        elif type_id == 12:  # String
            length = int.from_bytes(data[:4], 'little', signed=True)
            if length == -1:
                return None, 4
            return data[4:4+length].decode('utf-8'), 4 + length
        elif type_id == 13:  # DateTime
            raw = int.from_bytes(data[:8], 'little', signed=True)
            dt = datetime(1601, 1, 1) + timedelta(microseconds=raw // 10)
            return dt, 8
        elif type_id == 14:  # GUID
            guid = uuid.UUID(bytes_le=data[:16])
            return guid, 16
        elif type_id == 15:  # ByteString
            length = int.from_bytes(data[:4], 'little', signed=True)
            if length == -1:
                return None, 4
            return data[4:4+length], 4 + length
        elif type_id == 16:  # XmlElement
            length = int.from_bytes(data[:4], 'little', signed=True)
            if length == -1:
                return None, 4
            return data[4:4+length].decode('utf-8'), 4 + length
        elif type_id == 17:  # NodeId
            header_len, id_len, ns, node_id = ByteUtils.length_prefixed_encoding(data)
            return {'namespace': ns, 'identifier': node_id}, header_len + id_len
        elif type_id == 18:  # ExpandedNodeId
            header_len, id_len, ns, node_id = ByteUtils.length_prefixed_encoding(data)
            return {'namespace': ns, 'identifier': node_id}, header_len + id_len
        elif type_id == 19:  # StatusCode
            code = int.from_bytes(data[:4], 'little')
            return OPCUAMappings.STATUS_CODE.get(code, code), 4
        elif type_id == 20:  # QualifiedName
            ns_index = int.from_bytes(data[:2], 'little')
            str_len = int.from_bytes(data[2:6], 'little', signed=True)
            if str_len == -1:
                name = None
                size = 6
            else:
                name = data[6:6+str_len].decode('utf-8')
                size = 6 + str_len
            return {'namespace_index': ns_index, 'name': name}, size
        elif type_id == 21:  # LocalizedText
            offset = 0
            type = data[offset]
            offset += 1
            locale = None
            text = None
            if type & 0x01:
                locale_length = struct.unpack_from('<I', data, offset)[0]
                offset += 4
                locale = data[offset:offset + locale_length].decode('utf-8')
                offset += locale_length

            if type & 0x02:
                text_length = struct.unpack_from('<I', data, offset)[0]
                offset += 4
                text = data[offset:offset + text_length].decode('utf-8')
                offset += text_length
            return {'locale': locale, 'text': text}, offset
        # Unknown or not implemented
        return None, 0

class InitParser:
    def __init__(self, buffer: bytes, conn_key):
        self.conn_key = conn_key
        self.buffer = buffer

class ReqRespHeaderSkipper:
    @staticmethod
    def skip_request_header(data: bytes) -> int:
        offset = 0
        # AuthenticationToken (NodeId)
        ns_len, id_len, ns, node_id = ByteUtils.length_prefixed_encoding(data[offset:])
        offset += 1 + ns_len + id_len
        # Timestamp (DateTime)
        offset += 8
        # RequestHandle (UInt32)
        offset += 4
        # ReturnDiagnostics (UInt32)
        offset += 4
        # AuditEntryId (String)
        _, adv = ByteUtils.parse_variant(0x0C,data[offset:])
        offset += adv
        # TimeoutHint (UInt32)
        offset += 4
        # AdditionalHeader (ExtensionObject)
        offset += ByteUtils.extension_object(data[offset:])
        return offset

    @staticmethod
    def skip_response_header(data: bytes) -> int:
        offset = 0
        # Timestamp (DateTime)
        offset += 8
        # RequestHandle (UInt32)
        offset += 4
        # ServiceResult (StatusCode)
        offset += 4
        # ServiceDiagnostics (DiagnosticInfo)
        offset += ByteUtils.diagnosis_info(data[offset:])
        # StringTable (Array of String)
        arr_size, _ = ByteUtils.array_byte_length(data[offset:])
        offset += arr_size
        # AdditionalHeader (ExtensionObject)
        offset += ByteUtils.extension_object(data[offset:])
        return offset

class ReadRequestParser(InitParser):
    def parse(self):
        nodes_offset = 28 + self._skip_security() + 12
        section = self.buffer[nodes_offset:]
        result = self._parse_nodes(section)
        print(f"OPC-UA | MSG | ReadRequest | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        for i in result:
            print(f"Namespace Index = {i['ns']}, Identifier Numeric = {i['ident']}, Attribute = {i['attr']}; ",end='')
        print()

    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_request_header(self.buffer[28:])

    def _parse_nodes(self, data: bytes):
        count = int.from_bytes(data[:4], 'little', signed=True)
        offset = 4
        results = []
        for _ in range(count):
            ns_len, id_len, ns, node_id = ByteUtils.length_prefixed_encoding(data[offset:])
            offset += 1 + ns_len + id_len
            attr = int.from_bytes(data[offset:offset+4], 'little')
            offset += 4
            try:
                ns_conv = int.from_bytes(ns, byteorder='little', signed=True)
                id_conv = int.from_bytes(node_id, byteorder='little', signed=True)
            except Exception as e:
                ns_conv = ns
                id_conv = node_id
            results.append({"ns": ns_conv, "ident": id_conv, "attr": OPCUAMappings.ATTR_ID.get(attr,attr)})
        return results

class ReadResponseParser(InitParser):
    def parse(self):
        res_offset = 28 + self._skip_security()
        section = self.buffer[res_offset:]
        result = self._parse_results(section)
        print(f"OPC-UA | MSG | ReadResponse | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        for i in result:
            print(f"Value = {i['value']}; ",end='')
        print()

    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_response_header(self.buffer[28:])

    def _parse_results(self, data: bytes):
        arr_len = int.from_bytes(data[:4], 'little', signed=True)
        offset = 4
        values = []
        for _ in range(arr_len):
            mask = data[offset]
            if mask & 1:
                offset += 1
                val, size = ByteUtils.parse_variant(data[offset], data[offset+1:])
                values.append({"value": val})
                offset += 1 + size
            else:
                offset += 1
        return values

class WriteRequestParser(InitParser):
    def parse(self):
        wr_offset = 28 + self._skip_security()
        section = self.buffer[wr_offset:]
        result = self._parse_write(section)
        print(f"OPC-UA | MSG | WriteRequest | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        for i in result:
            print(f"Node ID = {i['nodeID']}, Attribute = {i['attr']}, Value = {i['value']}; ",end='')
        print()

    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_request_header(self.buffer[28:])

    def _parse_write(self, data: bytes):
        count = int.from_bytes(data[:4], 'little', signed=True)
        offset = 4
        writes = []
        for _ in range(count):
            # NodeId
            ns_len, id_len, ns, node_id = ByteUtils.length_prefixed_encoding(data[offset:])
            offset += 1 + ns_len + id_len
            # AttributeId
            attr = int.from_bytes(data[offset:offset+4], 'little')
            offset += 4
            # IndexRange (String)
            str_len = int.from_bytes(data[offset:offset+4], 'little', signed=True)
            offset += 4
            if str_len != -1:
                offset += str_len
            # DataValue: Variant
            mask = data[offset]
            if mask & 1:
                offset += 1
                val, size = ByteUtils.parse_variant(data[offset], data[offset+1:])
                offset += 1 + size
            # skip StatusCode
            offset += 4
            # skip SourceTimestamp and ServerTimestamp (DateTime)
            offset += 8 + 8
            writes.append({"nodeID": int.from_bytes(node_id, byteorder='little', signed=True), "attr": OPCUAMappings.ATTR_ID.get(attr,attr), "value": val})
        return writes

class WriteResponseParser(InitParser):
    def parse(self):
        ws_offset = 28 + self._skip_security()
        section = self.buffer[ws_offset:]
        result = self._parse_status(section)
        print(f"OPC-UA | MSG | WriteResponse | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        for i in result:
            print(f"Status = {i['status']}; ",end='')
        print()

    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_response_header(self.buffer[28:])

    def _parse_status(self, data: bytes):
        arr_len = int.from_bytes(data[:4], 'little', signed=True)
        offset = 4
        statuses = []
        for _ in range(arr_len):
            code = int.from_bytes(data[offset:offset+4], 'little')
            statuses.append({"status": {OPCUAMappings.STATUS_CODE.get(code, code)}})
            offset += 4
        return statuses

class TranslateBrowsePathsToNodeIdsRequestParser(InitParser):
    def parse(self):
        nodes_offset = 28 + self._skip_security()
        section = self.buffer[nodes_offset:]
        result = self._parse_browsepath(section)
        print(f"OPC-UA | MSG | TranslateBrowsePathsToNodeIdsRequest | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        for rels in result:
            for i in rels['relativePath']:
                print(f"Target ID = {i['targetID']}, Name = {i['targetName']}; ",end='')
        print()
    
    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_request_header(self.buffer[28:])

    def _parse_browsepath(self, data: bytes):
        count = int.from_bytes(data[:4], 'little', signed=True)
        ofs = 4
        paths = []
        for _ in range(count):
            p1, p2, ns, ident = ByteUtils.length_prefixed_encoding(data[ofs:])
            start_node = {'ns': ns, 'id': ident}
            ofs += 1 + p1 + p2
            elem_count = int.from_bytes(data[ofs:ofs+4], 'little', signed=True)
            ofs += 4
            rels = []
            for _ in range(elem_count):
                p1, p2, nsr, idr = ByteUtils.length_prefixed_encoding(data[ofs:])
                ofs += 1 + p1 + p2
                inv = bool(data[ofs]); ofs += 1
                sub = bool(data[ofs]); ofs += 1
                id, name, nl = ByteUtils.read_qualifiedname(data[ofs:])
                ofs += nl
                rels.append({'refType': {'ns': nsr, 'id': idr}, 'isInverse': inv, 'includeSubtypes': sub, 'targetID': id, 'targetName': name})
            paths.append({'startNode': start_node, 'relativePath': rels})
        return paths

class TranslateBrowsePathsToNodeIdsResponseParser(InitParser):
    def parse(self):
        nodes_offset = 28 + self._skip_security()
        section = self.buffer[nodes_offset:]
        result = self._parse_browsepath(section)
        print(f"OPC-UA | MSG | TranslateBrowsePathsToNodeIdsResponse | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        for items in result:
            print(f"Status = {items['status']}; ",end='')
            for i in items['targets']:
                print(f"Namespace Index = {i['nodeId']['ns']}, Identifier Numeric = {i['nodeId']['id']}", end='')
        print()
    
    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_response_header(self.buffer[28:])

    def _parse_browsepath(self, data:bytes):
        count = int.from_bytes(data[:4], 'little', signed=True); ofs = 4
        results = []
        for _ in range(count):
            status = int.from_bytes(data[ofs:ofs+4], 'little'); ofs += 4
            tgt_cnt = int.from_bytes(data[ofs:ofs+4], 'little', signed=True); ofs += 4
            targets = []
            for _ in range(tgt_cnt):
                h1, h2, ns, ident = ByteUtils.length_prefixed_encoding(data[ofs:])
                ofs += 1 +  h1 + h2
                sv_idx = int.from_bytes(data[ofs:ofs+4], 'little'); ofs += 4
                rem = int.from_bytes(data[ofs:ofs+4], 'little'); ofs += 4
                try:
                    ns_conv = int.from_bytes(ns, byteorder='little', signed=True)
                    ident_conv = int.from_bytes(ident, byteorder='little', signed=True)
                except Exception as e:
                    ns_conv = ns
                    ident_conv = ident
                targets.append({'nodeId': {'ns': ns_conv, 'id': ident_conv}, 'serverIndex': sv_idx, 'remainingPathIndex': rem})
            results.append({'status': OPCUAMappings.STATUS_CODE.get(status, status), 'targets': targets})
        return results

class CreateSessionRequestParser(InitParser):
    def parse(self):
        nodes_offset = 28 + self._skip_security()
        section = self.buffer[nodes_offset:]
        result = self._parse_session(section)
        print(f"OPC-UA | MSG | CreateSessionRequest | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        for i in result:
            clientDesc = i['clientDescription']
            print(f"Session Name = {i['sessionName']}, Application Name = {clientDesc['applicationName']}, Application type = {OPCUAMappings.APPLICATION_TYPE.get(clientDesc['applicationType'],clientDesc['applicationType'])}; ",end='')
        print()
    
    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_request_header(self.buffer[28:])

    def _parse_session(self, data: bytes):
        cds = {}
        cds['applicationUri'], adv = ByteUtils.parse_variant(0x0C,data); ofs = adv
        cds['productUri'], adv = ByteUtils.parse_variant(0x0C,data[ofs:]); ofs += adv
        cds['applicationName'], adv = ByteUtils.parse_variant(0x15,data[ofs:]); ofs += adv
        cds['applicationType'], adv = ByteUtils.parse_variant(0x07,data[ofs:]); ofs += adv
        cds['gatewayServerUri'], adv = ByteUtils.parse_variant(0x0C,data[ofs:]); ofs += adv
        cds['discoveryProfileUri'], adv = ByteUtils.parse_variant(0x0C,data[ofs:]); ofs += adv
        cnt, urls, adv = ByteUtils.array_length_and_items(data[ofs:]); ofs += adv
        cds['discoveryUrls'] = [u.decode('utf-8') for u in urls]
        srv, adv = ByteUtils.parse_variant(0x0C,data[ofs:]); ofs += adv
        ep, adv = ByteUtils.parse_variant(0x0C,data[ofs:]); ofs += adv
        sn, adv = ByteUtils.parse_variant(0x0C,data[ofs:]); ofs += adv
        nonce, adv = ByteUtils.parse_variant(0x0F,data[ofs:]); ofs += adv
        cert, adv = ByteUtils.parse_variant(0x0F,data[ofs:]); ofs += adv
        return [{'clientDescription': cds, 'serverUri': srv, 'endpointUrl': ep, 'sessionName': sn, 'clientNonce': nonce, 'clientCertificate': cert}]

class CreateSessionResponseParser(InitParser):
    def parse(self):
        nodes_offset = 28 + self._skip_security()
        section = self.buffer[nodes_offset:]
        result = self._parse_nodes(section)
        print(f"OPC-UA | MSG | CreateSessionResponse | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        for i in result:
            print(f"Session Namespace = {i['sessionId']['ns']}, Session ID = {i['sessionId']['id']}; ",end='')
        print()
    
    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_response_header(self.buffer[28:])

    def _parse_nodes(self, data: bytes):
        res = {}
        # sessionId (NodeId)
        hdr_len, id_len, ns, ident = ByteUtils.length_prefixed_encoding(data)
        try:
            ns_conv = int.from_bytes(ns, byteorder='little', signed=True)
            ident_conv = int.from_bytes(ident, byteorder='little', signed=True)
        except Exception as e:
            ns_conv = ns
            ident_conv = ident
        res['sessionId'] = {'ns': ns_conv, 'id': ident_conv}
        ofs = 1 + hdr_len + id_len
        # authenticationToken (NodeId)
        hdr2, id2, ns2, ident2 = ByteUtils.length_prefixed_encoding(data[ofs:])
        res['authenticationToken'] = {'ns': ns2, 'id': ident2}
        ofs += 1 + hdr2 + id2
        # revisedSessionTimeout (Duration - Double)
        res['revisedSessionTimeout'] = struct.unpack_from('<d', data, ofs)[0]
        ofs += 8
        # serverNonce
        res['serverNonce'], adv = ByteUtils.parse_variant(0x0F,data[ofs:])
        ofs += adv
        # serverCertificate
        res['serverCertificate'], adv = ByteUtils.parse_variant(0x0F,data[ofs:])
        ofs += adv
        return [res]

class ActivateSessionRequestParser(InitParser):
    def parse(self):
        nodes_offset = 28 + self._skip_security()
        section = self.buffer[nodes_offset:]
        result =  self._parse_session(section)
        print(f"OPC-UA | MSG | ActivateSessionRequest | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        for i in result:
            print(f"Client Signature = {i['clientSignature']}; ",end='')
        print()
    
    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_request_header(self.buffer[28:])
    
    def _parse_session(self, data: bytes):
        alg, adv = ByteUtils.parse_variant(0x0C,data); ofs = adv
        sig, adv = ByteUtils.parse_variant(0x0F,data[ofs:]); ofs += adv
        clientSig = {'algorithm': alg, 'signature': sig}
        cnt, certs, adv = ByteUtils.array_length_and_items(data[ofs:]); ofs += adv
        softwareCerts = []
        for c in certs:
            cd, l1 = ByteUtils.parse_variant(0x0F,c)
            sd, l2 = ByteUtils.parse_variant(0x0F,c[l1:])
            softwareCerts.append({'certificateData': cd, 'signature': sd})
        cnt, locales, adv = ByteUtils.array_length_and_items(data[ofs:]); ofs += adv
        localeIds = [l.decode('utf-8') for l in locales]
        xo_sz = ByteUtils.extension_object(data[ofs:]); token = data[ofs:ofs+xo_sz]; ofs += xo_sz
        alg2, adv = ByteUtils.parse_variant(0x0C,data[ofs:]); ofs += adv
        sig2, adv = ByteUtils.parse_variant(0x0F,data[ofs:]); ofs += adv
        userSig = {'algorithm': alg2, 'signature': sig2}
        return [{'clientSignature': clientSig, 'softwareCertificates': softwareCerts, 'localeIds': localeIds, 'userIdentityToken': token, 'userTokenSignature': userSig}]

class ActivateSessionResponseParser(InitParser):
    def parse(self):
        nodes_offset = 28 + self._skip_security()
        section = self.buffer[nodes_offset:]
        result = self._parse_session(section)
        print(f"OPC-UA | MSG | ActivateSessionResponse | {DEVICE_LIST.get(self.conn_key[0],self.conn_key[0])} -> {DEVICE_LIST.get(self.conn_key[2],self.conn_key[2])}: ",end='')
        #for i in result:
        #    print(f"Server Signature = {i['serverSignature']}; ",end='')
        print()
    
    def _skip_security(self):
        return ReqRespHeaderSkipper.skip_response_header(self.buffer[28:])

    def _parse_session(self, data : bytes):
        res = {}
        res['serverNonce'], adv = ByteUtils.parse_variant(0x0F,data); ofs = adv
        #alg, adv = ByteUtils.parse_variant(0x0C,data[ofs:]); ofs += adv
        #sig, adv = ByteUtils.parse_variant(0x0F,data[ofs:]); ofs += adv
        #res['serverSignature'] = {'algorithm': alg, 'signature': sig}
        return [res]

class OPCUAParser:
    def __init__(self):
        self.buffer = defaultdict(bytearray)
        self.start_ts = {}
    
    def parse(self, buffer: bytes):
        msg = buffer[:3].decode('utf-8')
        chunk = buffer[3:4].decode('utf-8')
        return msg, chunk

    def parse_msg_id(self, buffer: bytes):
        enc_mask = buffer[24]
        ident = int.from_bytes(buffer[26:28], 'little')
        return enc_mask, ident

    def process_opcua(self, conn_key, data, ts, seq):
        if data == b'' and ts is None:
            self.buffer.pop(conn_key, None)
            self.start_ts.pop(conn_key, None)
            return
        buffer = self.buffer[conn_key]
        buffer.extend(data)
        # set start_ts for new frame
        if conn_key not in self.start_ts:
            self.start_ts[conn_key] = ts
        try:
            msg, chunk = self.parse(buffer)
            if not msg in ['HEL','MSG','OPN','ACK','ERR','CLO']:
                raise ValueError
        except Exception as e:
            buffer.pop(0)
            self.start_ts.pop(conn_key, None)
        offset = 0
        while True:
            try:
                msg_len = struct.unpack('<I',buffer[offset+4:offset+8])[0]
            except Exception as e:
                break
            
            start = self.start_ts.get(conn_key)
            if msg == 'MSG':
                mask, mid = self.parse_msg_id(buffer[offset:offset+msg_len])
                msg_type = {
                    461: CreateSessionRequestParser,
                    464: CreateSessionResponseParser,
                    467: ActivateSessionRequestParser,
                    470: ActivateSessionResponseParser,
                    554: TranslateBrowsePathsToNodeIdsRequestParser,
                    557: TranslateBrowsePathsToNodeIdsResponseParser,
                    631: ReadRequestParser,
                    634: ReadResponseParser,
                    673: WriteRequestParser,
                    676: WriteResponseParser
                }.get(mid)
                if msg_type:
                    msg_type(buffer[offset:offset+msg_len]).parse(conn_key)
                    if msg_type in [464,470,557,634,676]:
                        append_seq_ack(seq)
                else:
                    print(f"OPC-UA | Unknown MSG Type detected: MSG ID = {mid} | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}")
            else:
                print(f"OPC-UA | {OPCUAMappings.MSG_ID.get(msg,msg)} | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}")
            
            c = 0 if conn_key[0] == "192.168.10.200" or conn_key[2] == "192.168.10.200" else 1
            WriteMeasurement().add_to_process_time(file_process,time.time()-start,c,'opcua')
            WriteMeasurement().add_to_puml(file_puml,conn_key[0],conn_key[2],f"OPCUA Message","->")
            
            self.start_ts.pop(conn_key, None)
            offset += msg_len

        self.buffer[conn_key] = buffer[offset:]
