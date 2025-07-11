
import sys
from log_parser import main as log_parser_main

def main_with_output_file(log_file_path, output_file_path="output.txt"):
    """Runs the log parser and redirects all output to a file."""
    original_stdout = sys.stdout
    try:
        with open(output_file_path, 'w') as outfile:
            sys.stdout = outfile
            print("Successfully opened log file: {log_file_path}")
            log_parser_main(log_file_path)
            print("Analysis complete.")
    finally:
        sys.stdout = original_stdout  # Restore the original stdout

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <log_file_path>")
    else:
        log_file_path = sys.argv[1]
        # Redirect stdout immediately when main.py starts
        original_stdout = sys.stdout
        try:
            with open("output.txt", 'w') as outfile:
                sys.stdout = outfile
                main_with_output_file(log_file_path)
        finally:
            sys.stdout = original_stdout
        print(f"Output has been written to: output.txt")
        print("Starting the Cyber Threat Detection System...")
        print(f"Analyzing log file: {log_file_path}")

