import socket
import threading
import time
import struct
import queue
import os
import psutil
from collections import defaultdict

from __main__ import file_process, file_puml, append_seq_ack
from moni_dict import *
from moni_writer import *

# MQTT MESSAGE TYPE
MQTT_MSG_TYPE = {
    1:"CONNECT", 2:"CONNACK", 3:"PUBLISH",
    4:"PUBACK", 5:"PUBREC", 6:"PUBREL",
    7:"PUBCOMP", 8:"SUBSCRIBE", 9:"SUBACK",
    10:"UNSUBSCRIBE", 11:"UNSUBACK", 12:"PINGREQ",
    13:"PINGRESP", 14:"DISCONNECT", 15:"AUTH"
}

# CONNACK STATUS CODE
CONNACK_REASON_CODE = {
    0:"Good", 128:"Unspecified Error", 129:"Malformed Packet",
    130:"Protocol Error", 131:"Implementation specific error", 132:"Unsupported Protocol Version",
    133:"Client Identifier not valid", 134:"Bad User Name or Password", 135:"Not authorized",
    136:"Server Unavailable", 137:"Server Busy", 138:"Banned", 140:"Bad authentification method",
    141:"Topic Name invalid", 149:"Packet too large", 151:"Quota exceeded", 153:"Payload format invalid",
    154:"Retain not supported", 155:"QoS not supported", 156:"Use another server", 157:"Server moved",
    159:"Connection rate exceeded"
}

# SUBACK STATUS CODE
SUBACK_REASON_CODE = {
    0:"Granted QoS 0", 1:"Granted QoS 1", 2:"Granted QoS 2",
    128:"Unspecified error", 131:"Implementation specific error", 135:"Not authorized",
    143:"Topic Filter invalid", 145:"Packet Identifier in use", 151:"Quota exceeded",
    158:"Shared Subscription not supported", 161:"Subscription Identifier not supported", 162:"Wildcard Subscriptions not supported"
}

# -- MQTTParser --
class MQTTParser:
    def __init__(self):
        self.buffer = defaultdict(bytearray)
        self.length = 0
        self.error = False
        self.detected = 0
        self.start_ts = {}
        self.handlers = {
            1: self._handle_connect, 2: self._handle_connack,
            3: self._handle_publish, 4: self._handle_puback,
            5: self._handle_pubrec, 6: self._handle_pubrel,
            7: self._handle_pubcomp, 8: self._handle_subscribe,
            9: self._handle_suback, 10: self._handle_unsubscribe,
            11: self._handle_unsuback, 12: self._handle_pingreq,
            13: self._handle_pingresp, 14: self._handle_disconnect,
            15: self._handle_auth
        }
    
    def control_checker(self, mqtt_type, reserved, remaining):
        if mqtt_type in [2,4,5,6,7,11] and remaining == 2:
            if (mqtt_type == 6 and reserved == 2) or (mqtt_type in [2,4,5,7,11] and reserved == 0):
                return True
        elif mqtt_type in [12,13,14] and remaining == 0 and reserved == 0:
            return True
        elif mqtt_type in [1,8,9,10,15]:
            if (mqtt_type in [8,10] and reserved == 2) or (mqtt_type in [1,9,15] and reserved == 0):
                return True
        elif mqtt_type == 3:
            return True
        return False

    def parse_mqtt_frame(self, buffer):
        if len(buffer) < 2:
            raise ValueError
        header = buffer[0]
        mqtt_type = (header >> 4) & 0x0F
        dup = bool(header & 0x08)
        qos = (header & 0x06) >> 1
        retain = bool(header & 0x01)
        remaining_length = 0
        multiplier = 1
        index = 1
        count = 0
        while True:
            if index >= len(buffer) or count >= 4:
                raise ValueError
            byte = buffer[index]
            remaining_length += (byte & 0x7F) * multiplier
            multiplier *= 128
            index += 1
            count += 1
            if not (byte & 0x80):
                break
        total = index + remaining_length
        if len(buffer) < total:
            raise ValueError
        return mqtt_type, dup, qos, retain, index, remaining_length, total


    def process_mqtt(self, conn_key, data, ts, seq):
        if data == b'' and ts is None:
            self.buffer.pop(conn_key, None)
            self.start_ts.pop(conn_key, None)
            self.detected += 1
            return
        buffer = self.buffer[conn_key]
        buffer.extend(data)
        
        # set start_ts for new frame
        if conn_key not in self.start_ts:
            self.start_ts[conn_key] = ts
        
        # delete buffer if header incorrect
        mqtt_type = (buffer[0] >> 4) & 0x0F
        reserve = buffer[0] & 0x0F
        if not mqtt_type == 3 and self.error:
            self.buffer.pop(conn_key, None)
            return
        if 1 <= mqtt_type <= 15:
            try:
                remaining = 0; multiplier = 1; index = 1; count = 0
                while True:
                    if count >= 4:
                        raise ValueError
                    byte = buffer[index]
                    remaining += (byte & 0x7F) * multiplier
                    multiplier *= 128
                    index += 1; count += 1
                    if not (byte & 0x80): break
                if not self.control_checker(mqtt_type, reserve, remaining):
                    raise ValueError
            except (ValueError, IndexError):
                print(f"MQTT | [!] Possible packet error detected ({self.detected},{seq}). Deleting buffer and waiting for PUBLISH...")
                WriteMeasurement().add_to_error_log("error.txt",time.time(),self.length)
                self.error = True
                self.buffer.pop(conn_key, None)
                return
        else:
            print(f"MQTT | [!] Possible packet error detected ({self.detected},{seq}). Deleting buffer and waiting for PUBLISH...")
            WriteMeasurement().add_to_error_log("error.txt",time.time(),self.length)
            self.error = True
            self.buffer.pop(conn_key, None)
            return
        offset = 0
        while True:
            try:
                mqtt_type, dup, qos, retain, index, remaining_length, total = self.parse_mqtt_frame(buffer[offset:])
            except ValueError:
                break
            if self.error:
                self.error = False

            # Define length
            self.length = remaining_length

            # Define a single MQTT message
            frame = buffer[offset:offset+total]

            # Define body (variable header + payload)
            body = frame[index:index+remaining_length]

            # Define handler
            handler = self.handlers.get(mqtt_type, self._handle_unknown)

            # Define start
            start = self.start_ts.get(conn_key)

            # Run MQTT control handler
            handler(conn_key, dup, qos, retain, body, start, ts)

            # Append to seq ack from main
            append_seq_ack(seq+len(data),start)

            # Add to Sequence Diagram if not MQTT PUBLISH, as MQTT PUBLISH is implemented inside the control handler
            if not mqtt_type == 3:
                WriteMeasurement().add_to_puml(file_puml,conn_key[0],conn_key[2],f"MQTT | {MQTT_MSG_TYPE.get(mqtt_type,mqtt_type)}","->")

            # Offset for next mmessage
            offset += total

            # Set error number to 0
            self.detected = 0
        
        # Delete start ts and set new buffer from offset
        self.start_ts.pop(conn_key, None)
        self.buffer[conn_key] = buffer[offset:]

    def _handle_connect(self, conn_key, dup, qos, retain, body, start=None, end=None):
        # parse CONNECT body fields
        proto_len = int.from_bytes(body[0:2], 'big')
        proto = body[2:2+proto_len].decode('utf-8', 'ignore')
        version = body[2+proto_len]
        flags = body[3+proto_len]
        keepalive = int.from_bytes(body[4+proto_len:6+proto_len], 'big')
        client_len = int.from_bytes(body[6+proto_len:8+proto_len], 'big')
        client_id = body[8+proto_len:8+proto_len+client_len].decode('utf-8','ignore')
        print(f"MQTT | CONNECT | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: proto={proto}, ver={version}, flags={flags}, keepalive={keepalive}, client_id={client_id}")

    def _handle_connack(self, conn_key, dup, qos, retain, body, start=None, end=None):
        session = bool(body[0] & 0x01)
        code = body[1]
        print(f"MQTT | CONNACK | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: session_present={session}, status={CONNACK_REASON_CODE.get(code,code)}")

    def _handle_publish(self, conn_key, dup, qos, retain, body, start=None, end=None):
        # parse topic and packet_id
        global file_pcap
        tlen = int.from_bytes(body[0:2],'big')
        topic = body[2:2+tlen].decode('utf-8','ignore')
        idx = 2 + tlen
        pid = None
        if qos>0:
            pid = int.from_bytes(body[idx:idx+2],'big'); idx+=2
        payload = body[idx:].decode('utf-8')
        if start is not None and end is not None:
            print(f"MQTT | PUBLISH | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: topic={topic}, pid={pid}, time={time.time()-start:.9f}s, payload={len(payload)}")
            if conn_key[0] == "192.168.10.200" or conn_key[2] == "192.168.10.200":
                c = 0
            else:
                c = 1
            WriteMeasurement().add_to_process_time(file_process,time.time()-start,c,'mqtt')
        else:
            print(f"MQTT | PUBLISH | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: topic={topic}, pid={pid}, payload={len(payload)}")
        WriteMeasurement().add_to_puml(file_puml,conn_key[0],conn_key[2],f"MQTT | Topic: {topic}, Message: {payload}","->")

    def _handle_puback(self, conn_key, dup, qos, retain, body, start=None, end=None):
        pid = int.from_bytes(body[0:2],'big')
        print(f"MQTT | PUBACK | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: packet_id={pid}")

    def _handle_pubrec(self, conn_key, dup, qos, retain, body, start=None, end=None):
        pid = int.from_bytes(body[0:2],'big')
        print(f"MQTT | PUBREC | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: packet_id={pid}")

    def _handle_pubrel(self, conn_key, dup, qos, retain, body, start=None, end=None):
        pid = int.from_bytes(body[0:2],'big')
        print(f"MQTT | PUBREL | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: packet_id={pid}")

    def _handle_pubcomp(self, conn_key, dup, qos, retain, body, start=None, end=None):
        pid = int.from_bytes(body[0:2],'big')
        print(f"MQTT | PUBCOMP | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: packet_id={pid}")

    def _handle_subscribe(self, conn_key, dup, qos, retain, body, start=None, end=None):
        pid = int.from_bytes(body[0:2],'big'); idx=2; filters=[]
        while idx<len(body):
            l=int.from_bytes(body[idx:idx+2],'big'); idx+=2
            topic=body[idx:idx+l].decode('utf-8','ignore'); idx+=l
            so=body[idx]; idx+=1
            filters.append((topic,so))
        print(f"MQTT | SUBSCRIBE | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: packet_id={pid}, topic, sub_opt={filters}")

    def _handle_suback(self, conn_key, dup, qos, retain, body, start=None, end=None):
        pid=int.from_bytes(body[0:2],'big'); codes=list(body[2:]); status = []
        for code in codes:
            status.append(SUBACK_REASON_CODE.get(code,code))
        print(f"MQTT | SUBACK | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: packet_id={pid}, return_reason={status}")

    def _handle_unsubscribe(self, conn_key, dup, qos, retain, body, start=None, end=None):
        pid=int.from_bytes(body[0:2],'big'); idx=2; topics=[]
        while idx<len(body):
            l=int.from_bytes(body[idx:idx+2],'big'); idx+=2
            t=body[idx:idx+l].decode('utf-8','ignore'); idx+=l
            topics.append(t)
        print(f"MQTT | UNSUBSCRIBE | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: packet_id={pid}, topics={topics}")

    def _handle_unsuback(self, conn_key, dup, qos, retain, body, start=None, end=None):
        pid=int.from_bytes(body[0:2],'big')
        print(f"MQTT | UNSUBACK | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: packet_id={pid}")

    def _handle_pingreq(self, conn_key, dup, qos, retain, body, start=None, end=None):
        print(f"MQTT | PINGREQ | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}")

    def _handle_pingresp(self, conn_key, dup, qos, retain, body, start=None, end=None):
        print(f"MQTT | PINGRESP | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}")

    def _handle_disconnect(self, conn_key, dup, qos, retain, body, start=None, end=None):
        print(f"MQTT | DISCONNECT | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}")

    def _handle_auth(self, conn_key, dup, qos, retain, body, start=None, end=None):
        reason=body[0] if body else None
        print(f"MQTT | AUTH | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: reason_code={reason}")

    def _handle_unknown(self, conn_key, dup, qos, retain, body, start=None, end=None):
        print(f"MQTT | UNKNOWN MSG ID | {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}: body={body}")
