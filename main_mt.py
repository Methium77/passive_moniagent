import socket
import threading
import time
import struct
import queue
import os
import psutil
from collections import defaultdict
from multiprocessing import Process, Queue, cpu_count, Manager
from multiprocessing.queues import Empty

import dpkt

from moni_writer import *

# Promisc mode
os.system("sudo ip link set eth0 promisc on")

# Timestamp NS Setup
if not hasattr(socket,'SO_TIMESTAMPNS'):
    socket.SO_TIMESTAMPNS = 35

seq_ack = {}

# TCP Sequence Ordering Algorithm
class TCPSequenceOrdering:
    def __init__(self, timeout=2):
        self.mqtt_callback = MQTTParser().process_mqtt
        self.opcua_callback = OPCUAParser().process_opcua
        self.timeout = timeout
        self.streams = {}
        self._MASK = 0xFFFFFFFF
        self._HALF = 0x80000000
        
    def _seq_diff(self,a, b):
        return (a - b) & self._MASK
    
    def feed(self, opt, conn_key, seq, data, ts):
        # Callback definitions (Protocol Select)
        if opt == 'mqtt':
            callback = self.mqtt_callback
        elif opt == 'opcua':
            callback = self.opcua_callback
        else:
            raise ValueError
        
        # Find stream if available
        state = self.streams.get(conn_key)

        # On timeout call to delete buffer
        if state and time.time() - state['last_time'] > self.timeout:
            callback(conn_key, b'', None, seq)
            del self.streams[conn_key]
            state = None

        # New stream initialization
        if state is None:
            state = {
                'next_seq': (seq + len(data)) & self._MASK,
                'segments': {},
                'last_time': time.time()
            }
            self.streams[conn_key] = state
            callback(conn_key, data, ts, seq)
        # Stream available
        else:
            # Get the sequence difference
            diff = self._seq_diff(seq, state['next_seq'])
            # Handle overlap
            if diff > self._HALF:
                overlap = self._seq_diff(state['next_seq'], seq)
                if overlap >= len(data):
                    state['last_time'] = time.time()
                    return
                data = data[overlap:]
                seq = (seq + overlap) & self._MASK
                diff = self._seq_diff(seq, state['next_seq'])
            # out-of-order
            if diff != 0:
                if diff < self._HALF:
                    state['segments'][seq] = (data, ts)
            else:
                # in-order
                callback(conn_key, data, ts, seq)
                state['next_seq'] = seq + len(data)
                self._flush(state, conn_key, callback)
            state['last_time'] = time.time()

    def _flush(self, state, conn_key, callback):
        # Deliver buffered segments in order
        while True:
            seq = state['next_seq']
            if seq not in state['segments']:
                break
            data, ts = state['segments'].pop(seq)
            callback(conn_key, data, ts, seq)
            state['next_seq'] = (seq + len(data)) & self._MASK

# TCP Control Handler
class TCPControlHandler:
    def __init__(self, event_callback):
        self.event_callback = event_callback

    def feed(self, conn_key, flags, seq, ack, ts):
        event = ""
        if flags & 0x02:
            event = 'SYN'
        if flags & 0x01:
            event = 'FIN'
        if flags & 0x10:
            if event == "":
                event = 'ACK'
            else:
                event = event + ', ACK'
        if flags & 0x04:
            event = 'RST'
        self.event_callback(conn_key, event, seq, ack, ts)

# PCAP Saver OLD
def save_pcap_old(packets, filename):
    i = 1
    with open(filename,'wb') as f:
        writer = dpkt.pcap.Writer(f, linktype=1)
        for ts_sec, ts_nsec, data in packets:
            writer.writepkt(data,ts=ts_sec + ts_nsec/1e9)
            print(f'\r{i}/{len(packets)}',end='')
            i += 1
    print("\nProcessing done")

# PCAP Saver
def save_pcap(filetemp, filename):
    i = 1
    with open(filetemp,"rb") as temp, open(filename,"wb") as pcap:
        writer = dpkt.pcap.Writer(pcap, linktype=1)
        while True:
            header = temp.read(12)
            if not header:
                break
                
            ts_sec = int.from_bytes(header[0:4],'little')
            ts_nsec = int.from_bytes(header[4:8],'little')
            length = int.from_bytes(header[8:12],'little')
            data = temp.read(length)
            
            writer.writepkt(data, ts=ts_sec + ts_nsec/1e9)
            print(f'\r{i} Packets written',end='')
            i += 1
    print("\nWriting to .pcap done") 
    os.remove(filetemp)

# Socket Capture Thread
def socket_capture(iface, pkt_queue, stop_event):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,16 * 1024 * 1024)
    sock.bind((iface, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_TIMESTAMPNS, 1)
    sock.settimeout(1.0)
    cmsg_size = socket.CMSG_LEN(struct.calcsize('ll'))
    print("Sniffing...")
    try:
        while not stop_event.is_set():
            try:
                data, metadata, _, _ = sock.recvmsg(65535, cmsg_size)
            except socket.timeout:
                continue
            ts_sec = ts_nsec = 0
            for level, ctype, cdata in metadata:
                if level == socket.SOL_SOCKET and ctype == socket.SO_TIMESTAMPNS:
                    ts_sec, ts_nsec = struct.unpack('qq', cdata[:16])
                    break
            pkt_queue.put((ts_sec, ts_nsec, data),timeout=1)
    finally:
        sock.close()

# Write packet to a file temporarily
def write_to_temp(filename,ts_sec,ts_nsec,raw):
    with open("temp.bin","ab") as f:
        length = len(raw)
        f.write(ts_sec.to_bytes(4,'little'))
        f.write(ts_nsec.to_bytes(4,'little'))
        f.write(length.to_bytes(4,'little'))
        f.write(raw)

# DPKT Processing Thread
def dpkt_processor(pkt_queue, tcp_seqordering, control_handler, stop_event, processed):
    while not stop_event.is_set() or not pkt_queue.empty():
        try:
            ts_sec, ts_nsec, raw = pkt_queue.get(timeout=1)
        except Exception:
            continue
            
        # Write to temp.bin
        write_to_temp("temp.bin",ts_sec,ts_nsec,raw)

        # Parse Ethernet, IP, and TCP layer
        try:
            eth = dpkt.ethernet.Ethernet(raw)
            ip = eth.data
            tcp = ip.data
        except Exception:
            continue
            
        # Filter out non TCP packets
        if not isinstance(ip, dpkt.ip.IP) or not isinstance(tcp, dpkt.tcp.TCP):
            continue
        if not(tcp.dport in [1883,4840] or tcp.sport in [1883,4840]):
            continue
        
        # Set connection key
        conn_key = (socket.inet_ntoa(ip.src), tcp.sport, socket.inet_ntoa(ip.dst), tcp.dport)

        # If no raw data detected (no other protocols detected)
        if not tcp.data:
            ts = ts_sec + ts_nsec / 1e9
            control_handler.feed(conn_key, tcp.flags, tcp.seq, tcp.ack,ts)
        else:
            # If MQTT unencrypted (port 1883)
            if tcp.dport == 1883 or tcp.sport == 1883:
                ts = ts_sec + ts_nsec / 1e9
                parser_index = hash(conn_key) % cpu_count()
                tcp_seqordering.feed('mqtt',conn_key,tcp.seq,tcp.data,ts)
            # If OPC-UA (port 4840)
            elif tcp.dport == 4840 or tcp.sport == 4840:
                ts = ts_sec + ts_nsec / 1e9
                parser_index = hash(conn_key) % cpu_count()
                tcp_seqordering.feed('opcua',conn_key,tcp.seq,tcp.data,ts)

# Sequence Ordering Worker (ONLY FOR MP)
def seqreordering_worker(queue, parser_id,stop_event):
    seqworker = TCPSequenceOrdering(parser_id)
    try:
        while not stop_event.is_set():
            try:
                a,b,c,d,e = queue.get(timeout=1)
            except Empty:
                continue
            except KeyboardInterrupt:
                break
            #print(f"{parser_id} | ",end='')
            seqworker.feed(a,b,c,d,e)
    except KeyboardInterrupt:
        return
    except Exception as e:
        print(f"Error: {e}")

# Handle TCP Control packet visualization
def handle_event(conn_key, event, seq, ack, ts):
    global seq_ack
    # If ACK
    if event == "ACK":
        if ack in list(seq_ack.keys()):
            msg = f"TCP  | {event} on {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])} with wait time={ts - seq_ack[ack]:.9f}s"
            print(msg)
            # Remove ACK from seq_ack dictionary
            seq_ack.pop(ack, None)
            # Write to Sequence Diagram
            WriteMeasurement().add_to_puml(file_puml,conn_key[0],conn_key[2],"TCP ACK","-->")
    # If not ACK
    else:
        msg = f"TCP  | {event} on {DEVICE_LIST.get(conn_key[0],conn_key[0])} -> {DEVICE_LIST.get(conn_key[2],conn_key[2])}"
        print(msg)

# Packet Capture
class PacketCapture:
    def __init__(self, iface='eth0'):
        self.queue = queue.Queue(maxsize=1000)
        
        # Used for old pcap saver (deprecated)
        #self.processed = []

        # Handlers and Event
        self.tcp_ctrl_handler = TCPControlHandler(handle_event)
        self.tcp_seqordering_handler = TCPSequenceOrdering()
        self.stop_event = threading.Event()
        
        # Start socket thread
        self.sock_thread = threading.Thread(target=socket_capture, args=(iface,self.queue,self.stop_event,),daemon=True)
        self.sock_thread.start()
        
        # Start dpkt thread
        self.worker_thread = threading.Thread(target=dpkt_processor, args=(self.queue, self.tcp_seqordering_handler, self.tcp_ctrl_handler, self.stop_event,self.processed,),daemon=True)
        self.worker_thread.start()

    def shutdown(self, pcap_file='capture.pcap'):
        print("Shutting Down...")
        self.stop_event.set()
        self.sock_thread.join()
        self.worker_thread.join()

        # Save pcap
        save_pcap("temp.bin", pcap_file)
        #save_pcap_old(self.processed, pcap_file)

# Call from MQTT parser to append to seq_ack
def append_seq_ack(seq, start = None):
    global seq_ack
    if start:
        seq_ack[seq] = start
        # Delete to prevent overflow for no TCP ACK
        if len(seq_ack) == 40:
            seq_ack.pop(next(iter(seq_ack)))

if __name__=='__main__':
    #Setup
    if os.path.exists("temp.bin"):
        os.remove("temp.bin")
    freq = input("Freq: ")
    leng = input("Len : ")
    
    file_pcap = f"f{freq}ln{leng}.pcap"
    file_log = f"f{freq}ln{leng}cpu.txt"
    file_process =f"f{freq}ln{leng}pt.txt"
    file_puml = "SequenceDiagram.puml"
    
    from moni_mqtt import *
    from moni_opcua import *
    
    write_measurement=WriteMeasurement()
    write_measurement.create_puml(file_puml)
    parser=PacketCapture('eth0')
    
    go_time=time.time()
    
    while time.time() - go_time < 30000:
        try:
            write_measurement.add_to_log(file_log)
            time.sleep(0.1)
        except KeyboardInterrupt:
            break

    parser.shutdown(file_pcap)
