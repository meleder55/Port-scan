
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import threading

# Function to validate an IP address
def is_valid_ip(ip):
    import re
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(pattern, ip):
        octets = ip.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    return False

# Function to validate a port number
def is_valid_port(port):
    return port.isdigit() and 0 < int(port) <= 65535

# Function to scan a single port
def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return f"Port {port} is open"
            else:
                return f"Port {port} is closed"
    except Exception as e:
        return f"Error scanning port {port}: {e}"

# Function to scan ports with progress bar
def scan_ports_with_progress(ip, start_port, end_port):
    open_ports = []
    closed_ports = []
    total_ports = end_port - start_port + 1
    scanned_ports = 0

    for port in range(start_port, end_port + 1):
        result = scan_port(ip, port)
        if "open" in result:
            open_ports.append(port)
        else:
            closed_ports.append(port)

        # Update progress bar
        scanned_ports += 1
        progress = (scanned_ports / total_ports) * 100
        progress_bar['value'] = progress
        app.update_idletasks()  # Force the GUI to update

    return open_ports, closed_ports

# Function to save results to a TXT file
def save_results_to_txt(ip, open_ports, closed_ports):
    try:
        with open("scan_results.txt", "w") as txt_file:
            txt_file.write(f"Scan Results for IP: {ip}\n")
            txt_file.write("Open Ports:\n")
            for port in open_ports:
                txt_file.write(f"Port {port} is open\n")
            txt_file.write("Closed Ports:\n")
            for port in closed_ports:
                txt_file.write(f"Port {port} is closed\n")
        messagebox.showinfo("Success", "Results saved to scan_results.txt")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save results to TXT: {e}")

# Function to save results to a JSON file
def save_results_to_json(ip, open_ports, closed_ports):
    try:
        results = {
            "ip": ip,
            "open_ports": open_ports,
            "closed_ports": closed_ports
        }
        with open("scan_results.json", "w") as json_file:
            json.dump(results, json_file, indent=4)
        messagebox.showinfo("Success", "Results saved to scan_results.json")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save results to JSON: {e}")

# Function to run the scan in a separate thread
def run_scan():
    start_ip = ip_entry.get().strip()
    start_port = start_port_entry.get().strip()
    end_port = end_port_entry.get().strip()
    save_option = save_option_var.get()

    # Validate inputs
    if not is_valid_ip(start_ip):
        messagebox.showerror("Error", "Invalid IP address.")
        return
    if not is_valid_port(start_port) or not is_valid_port(end_port):
        messagebox.showerror("Error", "Ports must be valid numbers between 1 and 65535.")
        return

    start_port = int(start_port)
    end_port = int(end_port)

    if start_port > end_port:
        messagebox.showerror("Error", "Start Port must be less than or equal to End Port.")
        return

    # Clear previous results and reset progress bar
    result_text.delete(1.0, tk.END)
    progress_bar['value'] = 0

    # Run the scan in a separate thread
    threading.Thread(target=scan_and_display_results, args=(start_ip, start_port, end_port, save_option)).start()

# Function to scan and display results
def scan_and_display_results(ip, start_port, end_port, save_option):
    open_ports, closed_ports = scan_ports_with_progress(ip, start_port, end_port)

    # Display results in the text box
    result_text.insert(tk.END, f"Scan Results for IP: {ip}\n")
    result_text.insert(tk.END, "Open Ports:\n")
    for port in open_ports:
        result_text.insert(tk.END, f"Port {port} is open\n")
    result_text.insert(tk.END, "Closed Ports:\n")
    for port in closed_ports:
        result_text.insert(tk.END, f"Port {port} is closed\n")

    # Save results based on the selected option
    if save_option == "TXT":
        save_results_to_txt(ip, open_ports, closed_ports)
    elif save_option == "JSON":
        save_results_to_json(ip, open_ports, closed_ports)

# Create the GUI
app = tk.Tk()
app.title("Port Scanner with Save Options")

save_option_var = tk.StringVar(value="TXT")  # Default save option is TXT

tk.Label(app, text="IP Address:").grid(row=0, column=0, padx=10, pady=10)
ip_entry = tk.Entry(app)
ip_entry.grid(row=0, column=1, padx=10, pady=10)

tk.Label(app, text="Start Port:").grid(row=1, column=0, padx=10, pady=10)
start_port_entry = tk.Entry(app)
start_port_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Label(app, text="End Port:").grid(row=2, column=0, padx=10, pady=10)
end_port_entry = tk.Entry(app)
end_port_entry.grid(row=2, column=1, padx=10, pady=10)

tk.Label(app, text="Save As:").grid(row=3, column=0, padx=10, pady=10)
tk.OptionMenu(app, save_option_var, "TXT", "JSON").grid(row=3, column=1, padx=10, pady=10)

tk.Button(app, text="Scan Ports", command=run_scan).grid(row=4, column=0, columnspan=2, pady=10)

progress_bar = ttk.Progressbar(app, orient="horizontal", length=300, mode="determinate")
progress_bar.grid(row=5, column=0, columnspan=2, pady=10)

result_text = scrolledtext.ScrolledText(app, width=60, height=15)
result_text.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

app.mainloop()
