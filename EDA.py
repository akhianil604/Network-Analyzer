import pandas as pd
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Path to the CSV file containing the captured packet data
CSV_FILE = "captured_packets.csv"

# Load CSV data into a pandas DataFrame
df = pd.read_csv(CSV_FILE)
df.columns = df.columns.str.strip()  # Strip any extra spaces from column names

def analyze_data():
    """
    Analyzes the packet capture data from the CSV file and updates the GUI with statistics and charts.
    """
    global df
    try:
        # Reload the CSV data
        df = pd.read_csv(CSV_FILE)
        df.columns = df.columns.str.strip()  # Strip any extra spaces from column names
    except Exception as e:
        stats_text.set(f"Error reading CSV: {e}")  # Show error message in case of any exception
        return
  
    # Define required columns that should be present in the CSV
    required_columns = {"Protocol", "Source IP", "Destination IP", "Packet Size"}
    
    # Check if the required columns exist in the DataFrame
    if not required_columns.issubset(df.columns):
        stats_text.set("Required columns missing in CSV.\nCheck if you captured packets.")
        return

    # Check if the DataFrame is empty or contains no valid protocol data
    if df.empty or df["Protocol"].dropna().empty:
        stats_text.set("No data found in CSV. Start packet sniffing first.")
        return

    # Calculate various statistics from the DataFrame
    total_packets = len(df)
    protocol_counts = df["Protocol"].value_counts()  # Count occurrences of each protocol
    top_src_ips = df["Source IP"].value_counts().head(5)  # Get top 5 source IPs
    top_dest_ips = df["Destination IP"].value_counts().head(5)  # Get top 5 destination IPs
    min_size = df["Packet Size"].min()  # Find the smallest packet size
    max_size = df["Packet Size"].max()  # Find the largest packet size
    avg_size = df["Packet Size"].mean()  # Calculate the average packet size

    # Update the text display with the computed statistics
    stats_text.set(
        f"Total Packets: {total_packets}\n"
        f"Min Packet Size: {min_size} bytes\n"
        f"Max Packet Size: {max_size} bytes\n"
        f"Avg Packet Size: {avg_size:.2f} bytes"
    )

    # Clear any existing charts in the GUI
    for widget in [protocol_chart, src_ip_chart, dest_ip_chart]:
        for child in widget.winfo_children():
            child.destroy()

    # Generate charts and display them in the GUI if data is available
    if not protocol_counts.empty:
        # Create a bar chart for protocol distribution
        fig1, ax1 = plt.subplots(figsize=(3.5, 3))
        protocol_counts.plot(kind="bar", ax=ax1, color="skyblue")
        ax1.set_title("Protocol Distribution")
        ax1.set_ylabel("Count")
        fig1.tight_layout()
        canvas1 = FigureCanvasTkAgg(fig1, master=protocol_chart)
        canvas1.draw()
        canvas1.get_tk_widget().pack()

    if not top_src_ips.empty:
        # Create a bar chart for top 5 source IPs
        fig2, ax2 = plt.subplots(figsize=(4, 3))
        top_src_ips.plot(kind="bar", ax=ax2, color="lightcoral")
        ax2.set_title("Top 5 Source IPs")
        ax2.set_ylabel("Count")
        fig2.tight_layout()
        canvas2 = FigureCanvasTkAgg(fig2, master=src_ip_chart)
        canvas2.draw()
        canvas2.get_tk_widget().pack()

    if not top_dest_ips.empty:
        # Create a bar chart for top 5 destination IPs
        fig3, ax3 = plt.subplots(figsize=(4, 3))
        top_dest_ips.plot(kind="bar", ax=ax3, color="lightgreen")
        ax3.set_title("Top 5 Destination IPs")
        ax3.set_ylabel("Count")
        fig3.tight_layout()
        canvas3 = FigureCanvasTkAgg(fig3, master=dest_ip_chart)
        canvas3.draw()
        canvas3.get_tk_widget().pack()

def launch_packet_eda_gui():
    """
    Launches the Tkinter GUI to display packet capture data and analysis results.
    """
    root = tk.Tk()
    root.title("Packet Sniffing Data Analysis")  # Set the title of the GUI window
    root.geometry("1200x600")  # Set the window size

    # Create and pack a label for the header
    header_label = tk.Label(root, text="Network Traffic Analysis", font=("Arial", 16, "bold"))
    header_label.pack(pady=10)

    # Define a StringVar for displaying stats in the GUI and initialize it with a prompt
    global stats_text, protocol_chart, src_ip_chart, dest_ip_chart
    stats_text = tk.StringVar()
    stats_text.set("🔎 Press 'Analyze Data' after capturing packets.")

    # Create and pack a label to display the statistics text
    stats_label = tk.Label(root, textvariable=stats_text, font=("Arial", 12), justify="left")
    stats_label.pack()

    # Create a button to trigger data analysis when pressed
    analyze_button = tk.Button(root, text="Analyze Data", command=analyze_data, font=("Arial", 12, "bold"), bg="blue", fg="white")
    analyze_button.pack(pady=10)

    # Create a row of frames to hold the charts
    chart_row = tk.Frame(root)
    chart_row.pack(pady=10)

    # Create separate frames for each chart and pack them into the row
    protocol_chart = tk.Frame(chart_row)
    protocol_chart.pack(side=tk.LEFT, padx=10)
    src_ip_chart = tk.Frame(chart_row)
    src_ip_chart.pack(side=tk.LEFT, padx=10)
    dest_ip_chart = tk.Frame(chart_row)
    dest_ip_chart.pack(side=tk.LEFT, padx=10)

    # Start the Tkinter event loop to display the GUI
    root.mainloop()
