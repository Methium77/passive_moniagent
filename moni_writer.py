import psutil
from moni_dict import DEVICE_LIST
import time
import os
import subprocess

def get_cpu_temp():
    result = subprocess.run(['vcgencmd','measure_temp'], capture_output=True, text=True)
    output = result.stdout.strip()
    return float(output.replace("temp=","").replace("'C",""))

# Measurements
class WriteMeasurement:
    # PUML New Template
    def create_puml(self, filename):
        with open(filename, "w") as f:
            f.write("""
    @startuml MQTT Packet Capture Sequenzdiagramm
    title MQTT Packet Capture Sequenzdiagramm

    """)
        with open(filename, "a") as f:
            for x in DEVICE_LIST:
                f.write(f"actor {DEVICE_LIST[x]} as {x}\n")
            f.write("\n@enduml")

     # Append to PUML file
    def add_to_puml(self, filename, src, dst, message, ack):
        size_before = os.path.getsize(filename)
        with open(filename, "r+") as f:
            f.seek(size_before - 7)
            f.write(src + " " + ack + " " + dst + " : " + message + "\n@enduml")

    # Capture and Write CPU Load
    def add_to_log(self, filename):
        with open(filename, "a") as f:
            f.write(f"{time.time()} - {psutil.cpu_percent(interval=0.1)} - {get_cpu_temp()}\n")

    # Capture and write time delay        
    def add_to_process_time(self, filename, delay, dev, proto):
        with open(filename, "a") as f:
            f.write(f"{time.time()} - {delay} - {dev} - {proto}\n")
    
    def add_to_error_log(self, filename, time,length):
        with open(filename,"a") as f:
            f.write(f"{time} - {length}\n")
