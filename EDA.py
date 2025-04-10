import pandas as pd
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

CSV_FILE = "captured_packets.csv"
df = pd.read_csv(CSV_FILE)
df.columns = df.columns.str.strip()

def analyze_data():
    global df
    try:
        df = pd.read_csv(CSV_FILE)
        df.columns = df.columns.str.strip()
    except Exception as e:
        stats_text.set(f"Error reading CSV: {e}")
        return
    required_columns = {"Protocol", "Source IP", "Destination IP", "Packet Size"}
    if not required_columns.issubset(df.columns):
        stats_text.set("Required columns missing in CSV.\nCheck if you captured packets.")
        return

    if df.empty or df["Protocol"].dropna().empty:
        stats_text.set("No data found in CSV. Start packet sniffing first.")
        return
    total_packets = len(df)
    protocol_counts = df["Protocol"].value_counts()
    top_src_ips = df["Source IP"].value_counts().head(5)
    top_dest_ips = df["Destination IP"].value_counts().head(5)
    min_size = df["Packet Size"].min()
    max_size = df["Packet Size"].max()
    avg_size = df["Packet Size"].mean()
    stats_text.set(
        f"Total Packets: {total_packets}\n"
        f"Min Packet Size: {min_size} bytes\n"
        f"Max Packet Size: {max_size} bytes\n"
        f"Avg Packet Size: {avg_size:.2f} bytes"
    )
    for widget in [protocol_chart, src_ip_chart, dest_ip_chart]:
        for child in widget.winfo_children():
            child.destroy()
    if not protocol_counts.empty:
        fig1, ax1 = plt.subplots(figsize=(3.5, 3))
        protocol_counts.plot(kind="bar", ax=ax1, color="skyblue")
        ax1.set_title("Protocol Distribution")
        ax1.set_ylabel("Count")
        fig1.tight_layout()
        canvas1 = FigureCanvasTkAgg(fig1, master=protocol_chart)
        canvas1.draw()
        canvas1.get_tk_widget().pack()
    if not top_src_ips.empty:
        fig2, ax2 = plt.subplots(figsize=(4, 3))
        top_src_ips.plot(kind="bar", ax=ax2, color="lightcoral")
        ax2.set_title("Top 5 Source IPs")
        ax2.set_ylabel("Count")
        fig2.tight_layout()
        canvas2 = FigureCanvasTkAgg(fig2, master=src_ip_chart)
        canvas2.draw()
        canvas2.get_tk_widget().pack()
    if not top_dest_ips.empty:
        fig3, ax3 = plt.subplots(figsize=(4, 3))
        top_dest_ips.plot(kind="bar", ax=ax3, color="lightgreen")
        ax3.set_title("Top 5 Destination IPs")
        ax3.set_ylabel("Count")
        fig3.tight_layout()
        canvas3 = FigureCanvasTkAgg(fig3, master=dest_ip_chart)
        canvas3.draw()
        canvas3.get_tk_widget().pack()

def launch_packet_eda_gui():
    root = tk.Tk()
    root.title("Packet Sniffing Data Analysis")
    root.geometry("1200x600")  
    header_label = tk.Label(root, text="Network Traffic Analysis", font=("Arial", 16, "bold"))
    header_label.pack(pady=10)
    global stats_text, protocol_chart, src_ip_chart, dest_ip_chart
    stats_text = tk.StringVar()
    stats_text.set("🔎 Press 'Analyze Data' after capturing packets.")
    stats_label = tk.Label(root, textvariable=stats_text, font=("Arial", 12), justify="left")
    stats_label.pack()
    analyze_button = tk.Button(root, text="Analyze Data", command=analyze_data, font=("Arial", 12, "bold"), bg="blue", fg="white")
    analyze_button.pack(pady=10)
    chart_row = tk.Frame(root)
    chart_row.pack(pady=10)
    protocol_chart = tk.Frame(chart_row)
    protocol_chart.pack(side=tk.LEFT, padx=10)
    src_ip_chart = tk.Frame(chart_row)
    src_ip_chart.pack(side=tk.LEFT, padx=10)
    dest_ip_chart = tk.Frame(chart_row)
    dest_ip_chart.pack(side=tk.LEFT, padx=10)
    root.mainloop()
