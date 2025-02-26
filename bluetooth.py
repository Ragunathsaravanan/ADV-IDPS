import tkinter as tk
from tkinter import scrolledtext
import threading
import asyncio
from bleak import BleakScanner
import time


# Attack detection class for device scanning anomalies
class AttackDetector:
    def __init__(self, threshold=10, time_frame=5):
        self.threshold = threshold  # Number of devices discovered within the time frame
        self.time_frame = time_frame  # Time frame in seconds
        self.device_count = 0
        self.start_time = time.time()

    def analyze_device(self):
        self.device_count += 1
        current_time = time.time()

        if current_time - self.start_time > self.time_frame:
            # Reset the counter after time_frame seconds
            if self.device_count > self.threshold:
                self.detect_attack()
            self.device_count = 0
            self.start_time = current_time

    def detect_attack(self):
        print("Potential DoS attack detected! Too many devices in a short time.")


# BLE Sniffer App class with Tkinter GUI
class BluetoothSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bluetooth Low Energy Network Analyzer")

        # Create a ScrolledText widget to display discovered devices
        self.device_display = scrolledtext.ScrolledText(root, width=80, height=20)
        self.device_display.pack(pady=10)

        # Start BLE scanning in a separate thread
        self.attack_detector = AttackDetector()
        self.loop = asyncio.get_event_loop()  # Get the event loop
        threading.Thread(target=self.run_async_scan, daemon=True).start()

    def run_async_scan(self):
        """Run the async BLE scanning loop in a separate thread."""
        self.loop.run_until_complete(self.scan_ble_devices())

    async def scan_ble_devices(self):
        print("Scanning for Bluetooth Low Energy devices...")

        known_devices = set()

        try:
            while True:
                # Use bleak to scan for nearby BLE devices
                devices = await BleakScanner.discover()
                for device in devices:
                    device_address = device.address
                    device_name = device.name if device.name else "Unknown"  # Get the device name

                    # Only display devices that are newly discovered
                    if device_address not in known_devices:
                        self.display_device(device_address, device_name)
                        known_devices.add(device_address)
                        self.attack_detector.analyze_device()

                await asyncio.sleep(5)  # Sleep for 5 seconds before scanning again
        except Exception as e:
            print(f"Error during scanning: {e}")

    def display_device(self, device_address, device_name):
        # Display the device name and address in the GUI
        self.device_display.insert(tk.END, f"New device detected: {device_name} ({device_address})\n")
        self.device_display.yview(tk.END)


def bluetooth_tracker():
    # Initialize Tkinter GUI
    root = tk.Tk()
    # root.iconbitmap('app.ico')
    app = BluetoothSnifferApp(root)
    root.mainloop()
