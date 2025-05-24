import psutil
import platform
from rich.console import Console
from rich.table import Table
import json

console = Console()

DIAGNOSTICS_FILE = "reports/system_diagnostics.json"


def get_cpu_info():
    """
    Gather detailed CPU information, including CPU count and core count.
    """
    cpu_stats = {
        "Physical CPU Count": psutil.cpu_count(logical=False),  # Physical processors
        "Core Count": psutil.cpu_count(logical=True),          # Total logical cores
        "Max Frequency (MHz)": psutil.cpu_freq().max,
        "Current Frequency (MHz)": psutil.cpu_freq().current,
        "CPU Usage (%)": psutil.cpu_percent(interval=1)
    }

    return cpu_stats

def get_system_info():
    """
    Gather detailed system information.
    """
    system_stats = {
        "System": platform.system(),
        "Node Name": platform.node(),
        "Release": platform.release(),
        "Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor()
    }

    return system_stats


def get_memory_info():
    """
    Gather detailed memory (RAM) usage information.
    """
    memory = psutil.virtual_memory()
    memory_stats = {
        "Total Memory (GB)": round(memory.total / (1024 ** 3), 2),
        "Available Memory (GB)": round(memory.available / (1024 ** 3), 2),
        "Used Memory (GB)": round(memory.used / (1024 ** 3), 2),
        "Memory Usage (%)": memory.percent
    }

    return memory_stats


def get_disk_info():
    """
    Gather detailed disk usage information.
    """
    disk = psutil.disk_usage("/")
    disk_stats = {
        "Total Disk Space (GB)": round(disk.total / (1024 ** 3), 2),
        "Used Disk Space (GB)": round(disk.used / (1024 ** 3), 2),
        "Free Disk Space (GB)": round(disk.free / (1024 ** 3), 2),
        "Disk Usage (%)": disk.percent
    }

    return disk_stats


def render_table(title, data):
    """
    Create a Rich table to display system stats.
    """
    table = Table(title=title)

    table.add_column("Key", justify="left", style="cyan")
    table.add_column("Value", justify="right", style="green")

    for key, value in data.items():
        table.add_row(key, str(value))

    console.print(table)


def save_as_json(data, filename):
    """
    Save diagnostics data as a JSON file.
    """
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        console.print(f"[green]Diagnostics saved to {filename}[/green]")
    except Exception as e:
        console.print(f"[red]Error saving diagnostics: {e}[/red]")


def run_diagnostics():
    """
    Run system diagnostics and save results.
    """
    console.print("[bold blue]Running System Diagnostics...[/bold blue]")

    # Gather diagnostics
    cpu_info = get_cpu_info()
    system_info = get_system_info()
    memory_info = get_memory_info()
    disk_info = get_disk_info()

    # Render tables
    render_table("CPU Information", cpu_info)
    render_table("System Information", system_info)
    render_table("Memory Information", memory_info)
    render_table("Disk Information", disk_info)

    # Save diagnostics as JSON
    diagnostics = {
        "CPU Information": cpu_info,
        "System Information": system_info,
        "Memory Information": memory_info,
        "Disk Information": disk_info
    }

    save_as_json(diagnostics, DIAGNOSTICS_FILE)
    console.print("[bold green]Diagnostics complete![/bold green]")


if __name__ == "__main__":
    run_diagnostics()
