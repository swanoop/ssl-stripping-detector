import tkinter as tk
from tkinter import filedialog, messagebox
import pyshark
import csv


def detect_ssl_stripping(packet):
    if 'http' in packet and hasattr(packet.http, 'response'):
        http_response = packet.http.response

        if hasattr(http_response, 'code') and http_response.code.lower() == '200':
            if hasattr(http_response,
                       'content_security_policy') and 'upgrade-insecure-requests' in http_response.content_security_policy:
                return True
            if hasattr(http_response, 'content_type') and 'text/html' in http_response.content_type:
                if hasattr(http_response, 'get_field_value') and 'response_full_uri' in http_response.get_field_value(
                        'response_full_uri'):
                    full_uri = http_response.get_field_value('response_full_uri')
                    if full_uri.startswith('http://') and not full_uri.startswith('https://'):
                        return True
                if hasattr(http_response, 'get_field_value') and 'html' in http_response.get_field_value('html'):
                    html_content = http_response.get_field_value('html')
                    if '<a href="http://' in html_content:
                        return True
    return False


def analyze_pcap(file_path):
    http_detected = False
    ssl_stripping_detected = False
    connections = []

    capture = pyshark.FileCapture(file_path)

    for packet in capture:
        if 'ip' in packet:
            if hasattr(packet.ip, 'src') and hasattr(packet.ip, 'dst'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst

                if 'tcp' in packet:
                    if hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
                        src_port = packet.tcp.srcport
                        dst_port = packet.tcp.dstport
                        connections.append((src_ip, src_port, dst_ip, dst_port))

        if 'http' in packet:
            http_detected = True

            if detect_ssl_stripping(packet):
                ssl_stripping_detected = True

    capture.close()

    return http_detected, ssl_stripping_detected, connections


def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("Wireshark pcap files", "*.pcap")])
    file_path_entry.delete(0, tk.END)
    file_path_entry.insert(0, file_path)


def run_analysis():
    input_file = file_path_entry.get()

    if not input_file:
        messagebox.showerror("Error", "Please select a pcap file.")
        return

    try:
        http_detected, ssl_stripping_detected, connections = analyze_pcap(input_file)
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return

    http_result_text = "HTTP Traffic Detected" if http_detected else "No HTTP Traffic Detected"

    if http_detected:
        ssl_stripping_result_text = "Possible SSL Stripping Detected"
    else:
        ssl_stripping_result_text = "No SSL Stripping Detected"

    http_result_label.config(text=http_result_text)
    ssl_stripping_result_label.config(text=ssl_stripping_result_text)

    if connections:
        export_button.config(state=tk.NORMAL)


def export_results():
    input_file = file_path_entry.get()

    if not input_file:
        messagebox.showerror("Error", "Please select a pcap file.")
        return

    output_file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])

    try:
        http_detected, _, connections = analyze_pcap(input_file)
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return

    data = [['Inbound IP', 'Inbound Port', 'Outbound IP', 'Outbound Port', 'HTTP Detected',
             'Possible SSL Stripping Detected']]

    for connection in connections:
        data.append([connection[0], connection[1], connection[2], connection[3], http_detected,
                     'Possible' if http_detected else 'No'])

    try:
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(data)
    except Exception as e:
        messagebox.showerror("Error", str(e))


root = tk.Tk()
root.title("SSL Stripping Detector")

file_path_entry = tk.Entry(root, width=50)
file_path_entry.grid(row=0, column=0, padx=10, pady=10)

select_button = tk.Button(root, text="Select File", command=select_file)
select_button.grid(row=0, column=1, padx=10, pady=10)

run_button = tk.Button(root, text="Run Analysis", command=run_analysis)
run_button.grid(row=1, column=0, padx=10, pady=10)

export_button = tk.Button(root, text="Export Results", command=export_results, state="disabled")
export_button.grid(row=1, column=1, padx=10, pady=10)

http_result_label = tk.Label(root, text="")
http_result_label.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

ssl_stripping_result_label = tk.Label(root, text="")
ssl_stripping_result_label.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

root.mainloop()
