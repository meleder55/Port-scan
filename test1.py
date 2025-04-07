
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import csv
import threading
import ipaddress
import whois
from PIL import Image, ImageTk
import pygame

# Function to validate an IP address
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
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

# Function to save results to a CSV file
def save_results_to_csv(ip, open_ports, closed_ports):
    try:
        with open("scan_results.csv", "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["IP Address", "Port", "Status"])
            for port in open_ports:
                writer.writerow([ip, port, "Open"])
            for port in closed_ports:
                writer.writerow([ip, port, "Closed"])
        messagebox.showinfo("Success", "Results saved to scan_results.csv")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save results to CSV: {e}")

# Unified function to save results based on the selected option
def save_results(ip, open_ports, closed_ports, save_option):
    if save_option == "TXT":
        save_results_to_txt(ip, open_ports, closed_ports)
    elif save_option == "JSON":
        save_results_to_json(ip, open_ports, closed_ports)
    elif save_option == "CSV":
        save_results_to_csv(ip, open_ports, closed_ports)

# Function to run the scan in a separate thread
def run_scan():
    mode = mode_var.get()
    start_ip = ip_entry.get().strip()
    end_ip = end_ip_entry.get().strip()
    start_port = start_port_entry.get().strip()
    end_port = end_port_entry.get().strip()
    save_option = save_option_var.get()

    # Validate inputs
    if not is_valid_ip(start_ip):
        messagebox.showerror("Error", "Invalid Start IP address.")
        return
    if mode == "IP Range" and not is_valid_ip(end_ip):
        messagebox.showerror("Error", "Invalid End IP address.")
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
    threading.Thread(target=scan_and_display_results, args=(mode, start_ip, end_ip, start_port, end_port, save_option)).start()

# Function to scan and display results
def scan_and_display_results(mode, start_ip, end_ip, start_port, end_port, save_option):
    all_results = []
    if mode == "Single IP":
        open_ports, closed_ports = scan_ports_with_progress(start_ip, start_port, end_port)
        result_text.insert(tk.END, f"Scan Results for IP: {start_ip}\n")
        result_text.insert(tk.END, "Open Ports:\n")
        for port in open_ports:
            result_text.insert(tk.END, f"Port {port} is open\n")
        result_text.insert(tk.END, "Closed Ports:\n")
        for port in closed_ports:
            result_text.insert(tk.END, f"Port {port} is closed\n")
        all_results.append({"ip": start_ip, "open_ports": open_ports, "closed_ports": closed_ports})
    elif mode == "IP Range":
        current_ip = ipaddress.ip_address(start_ip)
        end_ip = ipaddress.ip_address(end_ip)
        while current_ip <= end_ip:
            result_text.insert(tk.END, f"Scanning IP: {current_ip}\n")
            open_ports, closed_ports = scan_ports_with_progress(str(current_ip), start_port, end_port)
            result_text.insert(tk.END, f"Scan Results for IP: {current_ip}\n")
            result_text.insert(tk.END, "Open Ports:\n")
            for port in open_ports:
                result_text.insert(tk.END, f"Port {port} is open\n")
            result_text.insert(tk.END, "Closed Ports:\n")
            for port in closed_ports:
                result_text.insert(tk.END, f"Port {port} is closed\n")
            all_results.append({"ip": str(current_ip), "open_ports": open_ports, "closed_ports": closed_ports})
            current_ip += 1

    # Save results based on the selected option
    for result in all_results:
        save_results(result["ip"], result["open_ports"], result["closed_ports"], save_option)

# Function to perform a WHOIS lookup
def perform_whois(ip):
    try:
        w = whois.whois(ip)
        return str(w)
    except Exception as e:
        return f"Error performing WHOIS lookup: {e}"

# Function to run WHOIS lookup and display results
def run_whois():
    ip = ip_entry.get().strip()
    if not is_valid_ip(ip):
        messagebox.showerror("Error", "Invalid IP address.")
        return

    # Perform WHOIS lookup in a separate thread
    threading.Thread(target=whois_and_display_results, args=(ip,)).start()

def whois_and_display_results(ip):
    result = perform_whois(ip)
    result_text.delete(1.0, tk.END)  # Clear previous results
    result_text.insert(tk.END, f"WHOIS Results for IP: {ip}\n")
    result_text.insert(tk.END, result)

# Load and display the image at the top of the GUI
def add_image_to_gui():
    try:
        # Load the image using Pillow
        image = Image.open("hacker_cat.jpg")
        image = image.resize((300, 200))  # Resize the image to fit the GUI
        photo = ImageTk.PhotoImage(image)

        # Create a label to display the image
        image_label = tk.Label(app, image=photo)
        image_label.image = photo  # Keep a reference to avoid garbage collection
        image_label.grid(row=0, column=0, columnspan=2, pady=10)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load image: {e}")

# Create the GUI
app = tk.Tk()
app.title("Port Scanner with Save Options")

# Add the image to the GUI
add_image_to_gui()

mode_var = tk.StringVar(value="Single IP")
save_option_var = tk.StringVar(value="TXT")  # Default save option is TXT

tk.Label(app, text="Mode:").grid(row=1, column=0, padx=10, pady=10)
tk.OptionMenu(app, mode_var, "Single IP", "IP Range").grid(row=1, column=1, padx=10, pady=10)

tk.Label(app, text="IP Address / Start IP:").grid(row=2, column=0, padx=10, pady=10)
ip_entry = tk.Entry(app)
ip_entry.grid(row=2, column=1, padx=10, pady=10)

tk.Label(app, text="End IP (for Range):").grid(row=3, column=0, padx=10, pady=10)
end_ip_entry = tk.Entry(app)
end_ip_entry.grid(row=3, column=1, padx=10, pady=10)

tk.Label(app, text="Start Port:").grid(row=4, column=0, padx=10, pady=10)
start_port_entry = tk.Entry(app)
start_port_entry.grid(row=4, column=1, padx=10, pady=10)

tk.Label(app, text="End Port:").grid(row=5, column=0, padx=10, pady=10)
end_port_entry = tk.Entry(app)
end_port_entry.grid(row=5, column=1, padx=10, pady=10)

tk.Label(app, text="Save As:").grid(row=6, column=0, padx=10, pady=10)
tk.OptionMenu(app, save_option_var, "TXT", "JSON", "CSV").grid(row=6, column=1, padx=10, pady=10)

tk.Button(app, text="Scan Ports", command=run_scan).grid(row=7, column=0, columnspan=2, pady=10)
tk.Button(app, text="WHOIS Lookup", command=run_whois).grid(row=8, column=0, columnspan=2, pady=10)

progress_bar = ttk.Progressbar(app, orient="horizontal", length=300, mode="determinate")
progress_bar.grid(row=9, column=0, columnspan=2, pady=10)

result_text = scrolledtext.ScrolledText(app, width=60, height=15)
result_text.grid(row=10, column=0, columnspan=2, padx=10, pady=10)

app.mainloop()