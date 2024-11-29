import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.layers.tls.all import TLS
import threading


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("800x600")

        # UI Components
        self.create_widgets()

        # Packet capture variables
        self.sniffing_thread = None
        self.stop_sniffing = False
        self.packet_data = []

    def create_widgets(self):
        # Start/Stop buttons
        control_frame = tk.Frame(self.root)
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)

        self.start_button = tk.Button(control_frame, text="Start Capture", command=self.start_capture, bg="green",
                                      fg="white")
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(control_frame, text="Stop Capture", command=self.stop_capture, bg="red",
                                     fg="white", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.save_button = tk.Button(control_frame, text="Save Packets", command=self.save_packets, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Packet Display Table
        self.packet_tree = ttk.Treeview(self.root, columns=("No", "Source IP", "Destination IP", "Protocol", "Details"),
                                        show="headings")
        self.packet_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Define table columns
        self.packet_tree.heading("No", text="No")
        self.packet_tree.heading("Source IP", text="Source IP")
        self.packet_tree.heading("Destination IP", text="Destination IP")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Details", text="Details")

        # Set column widths
        self.packet_tree.column("No", width=50, anchor=tk.CENTER)
        self.packet_tree.column("Source IP", width=150, anchor=tk.W)
        self.packet_tree.column("Destination IP", width=150, anchor=tk.W)
        self.packet_tree.column("Protocol", width=100, anchor=tk.CENTER)
        self.packet_tree.column("Details", width=300, anchor=tk.W)

    def start_capture(self):
        self.stop_sniffing = False
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Run packet sniffing in a separate thread to avoid freezing the GUI
        self.sniffing_thread = threading.Thread(target=self.capture_packets)
        self.sniffing_thread.daemon = True
        self.sniffing_thread.start()

    def stop_capture(self):
        self.stop_sniffing = True
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)

    def capture_packets(self):
        sniff(filter="ip", prn=self.packet_callback, stop_filter=lambda x: self.stop_sniffing)

    def packet_callback(self, packet):
        if self.stop_sniffing:
            return

        # Extract packet details
        packet_no = len(self.packet_data) + 1
        src_ip = packet[IP].src if IP in packet else "Unknown"
        dst_ip = packet[IP].dst if IP in packet else "Unknown"
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        details = ""

        if TLS in packet:
            details = "TLS/SSL traffic"
        elif Raw in packet:
            details = packet[Raw].load.decode(errors='ignore')[:50]  # Show first 50 chars of payload

        # Save packet to memory
        self.packet_data.append((packet_no, src_ip, dst_ip, protocol, details))

        # Update the table
        self.packet_tree.insert("", tk.END, values=(packet_no, src_ip, dst_ip, protocol, details))

    def save_packets(self):
        # Save captured packets to a file
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
        if not file_path:
            return

        # Convert captured packets to scapy format for saving
        pkts = sniff(filter="ip", count=0, prn=lambda x: None)  # Dummy sniff for format
        for packet in self.packet_data:
            # Add only raw captured data as a placeholder
            pkt = IP(src=packet[1], dst=packet[2]) / TCP() / Raw(load=packet[4])
            pkts.append(pkt)

        try:
            from scapy.utils import wrpcap
            wrpcap(file_path, pkts)
            messagebox.showinfo("Success", "Packets saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save packets: {e}")


# Run the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
