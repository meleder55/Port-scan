
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import re
import socket
import whois  # You may need to install this module using 'pip install python-whois'
import threading

# Dictionary for port descriptions
port_descriptions = {
    20: "FTP - Data Transfer",
    21: "FTP - Command Control",
    22: "SSH - Secure Shell",
    23: "Telnet - Unencrypted Text Communications",
    25: "SMTP - Simple Mail Transfer Protocol",
    53: "DNS - Domain Name System",
    80: "HTTP - HyperText Transfer Protocol",
    110: "POP3 - Post Office Protocol",
    143: "IMAP - Internet Message Access Protocol",
    443: "HTTPS - Secure HTTP",
    3389: "RDP - Remote Desktop Protocol",
    # Add more ports and descriptions as needed
}

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        parts = ip.split(".")
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def is_valid_port(port):
    try:
        port = int(port)
        return 0 <= port <= 65535
    except ValueError:
        return False

def ip_range(start_ip, end_ip):
    # Generate a list of IPs in the range between start_ip and end_ip
    def ip_to_int(ip):
        parts = list(map(int, ip.split(".")))
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

    def int_to_ip(ip_int):
        return f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"

    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    return [int_to_ip(i) for i in range(start, end + 1)]

def scan_ports_with_progress(ip, start_port, end_port, progress_bar):
    open_ports = []
    closed_ports = []
    total_ports = end_port - start_port + 1
    scanned_ports = 0

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        else:
            closed_ports.append(port)
        sock.close()
        scanned_ports += 1
        progress_bar['value'] = (scanned_ports / total_ports) * 100
        app.update_idletasks()  # Update the progress bar in real-time

    return open_ports, closed_ports

def save_log(ip, open_ports, closed_ports, whois_data=None):
    with open("scan.txt", "a") as log_file:
        log_file.write(f"IP Address: {ip}\n")
        if whois_data:
            log_file.write("Whois Data:\n")
            log_file.write(whois_data + "\n")
        log_file.write("Open Ports:\n")
        for port in open_ports:
            description = port_descriptions.get(port, "Unknown Service")
            log_file.write(f"{port} ({description})\n")
        log_file.write("Closed Ports:\n")
        for port in closed_ports:
            log_file.write(f"{port}\n")

def perform_whois_lookup(ip):
    try:
        whois_info = whois.whois(ip)  # Perform the Whois lookup
        return str(whois_info)
    except Exception as e:
        return f"Whois lookup failed: {str(e)}"

def run_scan():
    ip_mode = mode_var.get()
    start_port = start_port_entry.get()
    end_port = end_port_entry.get()

    try:
        start_port = int(start_port)
        if not is_valid_port(start_port):
            raise ValueError
    except ValueError:
        messagebox.showerror("Error", "Invalid start port!")
        return
    
    try:
        end_port = int(end_port)
        if not is_valid_port(end_port):
            raise ValueError
    except ValueError:
        messagebox.showerror("Error", "Invalid end port!")
        return

    if start_port > end_port:
        messagebox.showerror("Error", "Start port must be less than or equal to end port!")
        return

    progress_bar['value'] = 0  # Reset progress bar

    result_text.delete(1.0, tk.END)

    if ip_mode == "Single IP":
        ip = ip_entry.get()
        if not is_valid_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format!")
            return
        threading.Thread(target=scan_and_display_results, args=(ip, start_port, end_port)).start()
    elif ip_mode == "IP Range":
        start_ip = start_ip_entry.get()
        end_ip = end_ip_entry.get()
        if not is_valid_ip(start_ip) or not is_valid_ip(end_ip):
            messagebox.showerror("Error", "Invalid IP range format!")
            return
        ip_list = ip_range(start_ip, end_ip)
        for ip in ip_list:
            threading.Thread(target=scan_and_display_results, args=(ip, start_port, end_port)).start()

def scan_and_display_results(ip, start_port, end_port):
    open_ports, closed_ports = scan_ports_with_progress(ip, start_port, end_port, progress_bar)
    whois_data = perform_whois_lookup(ip)
    save_log(ip, open_ports, closed_ports, whois_data)
    result_text.insert(tk.END, f"IP Address: {ip}\n")
    result_text.insert(tk.END, "Whois Data:\n")
    result_text.insert(tk.END, whois_data + "\n")
    result_text.insert(tk.END, "Open Ports:\n")
    for port in open_ports:
        description = port_descriptions.get(port, "Unknown Service")
        result_text.insert(tk.END, f"{port} ({description})\n")
    result_text.insert(tk.END, "Closed Ports:\n")
    for port in closed_ports:
        result_text.insert(tk.END, f"{port}\n")

app = tk.Tk()
app.title("Port Scanner with Whois Lookup")

mode_var = tk.StringVar(value="Single IP")

tk.Label(app, text="Mode:").grid(row=0, column=0, padx=10, pady=10)
tk.OptionMenu(app, mode_var, "Single IP", "IP Range").grid(row=0, column=1, padx=10, pady=10)

tk.Label(app, text="IP Address / Start IP:").grid(row=1, column=0, padx=10, pady=10)
ip_entry = tk.Entry(app)
ip_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Label(app, text="End IP (for Range):").grid(row=2, column=0, padx=10, pady=10)
start_ip_entry = tk.Entry(app)
end_ip_entry = tk.Entry(app)
start_ip_entry.grid(row=2, column=1, padx=10, pady=10)
end_ip_entry.grid(row=2, column=2, padx=10, pady=10)

tk.Label(app, text="Start Port:").grid(row=3, column=0, padx=10, pady=10)
start_port_entry = tk.Entry(app)
start_port_entry.grid(row=3, column=1, padx=10, pady=10)

tk.Label(app, text="End Port:").grid(row=4, column=0, padx=10, pady=10)
end_port_entry = tk.Entry(app)
end_port_entry.grid(row=4, column=1, padx=10, pady=10)

tk.Button(app, text="Scan Ports", command=run_scan).grid(row=5, column=0, columnspan=2, pady=10)

progress_bar = ttk.Progressbar(app, orient="horizontal", length=300, mode="determinate")
progress_bar.grid(row=6, column=0, columnspan=2, pady=10)

result_text = scrolledtext.ScrolledText(app, width=40, height=10)
result_text.grid(row=7, column=0, columnspan=3, padx=10, pady=10)

app.mainloop()