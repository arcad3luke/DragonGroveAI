from rich.table import Table
from rich.console import Console

def render_table(title, data):
    """
    Render a rich table for a dictionary or a list of dictionaries.
    :param title: Title of the table.
    :param data: Dictionary or list of dictionaries to render.
    """
    table = Table(title=title)
    console = Console()

    if isinstance(data, dict):
        # Handle single dictionary
        table.add_column("Key", justify="left")
        table.add_column("Value", justify="left")
        for key, value in data.items():
            table.add_row(str(key), str(value))
    elif isinstance(data, list) and all(isinstance(item, dict) for item in data):
        # Handle list of dictionaries
        if data:
            # Dynamically add columns based on keys in the first dictionary
            for key in data[0].keys():
                table.add_column(str(key), justify="left")

            # Add rows for each dictionary
            for item in data:
                table.add_row(*[str(value) for value in item.values()])
    else:
        console.print("[red]Error: Data must be a dictionary or a list of dictionaries.[/red]")
        return

    console.print(table)

def save_as_json(data, filename):
    """Save data to JSON file."""
    import json  # Ensure `json` is imported
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"Error saving to JSON: {e}")
