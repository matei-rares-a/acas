from pathlib import Path
import shutil

# Folder where the script is located
BASE_DIR = Path(__file__).parent.resolve()

# Output folder
OUTPUT_DIR = BASE_DIR / "converted_txt"
OUTPUT_DIR.mkdir(exist_ok=True)

# Ignore anything containing this text
IGNORE_CONTAINS = "__pycache__"

# Maximum recursion depth
MAX_DEPTH = 4


def should_ignore(path_obj):
    """
    Ignore hidden files/folders and anything containing __pycache__
    """
    return (
        path_obj.name.startswith(".")
        or IGNORE_CONTAINS in str(path_obj)
    )


def convert_file_to_txt(input_file, output_file):
    """
    Reads a file and saves it as UTF-8 .txt
    """
    encodings = ["utf-8", "latin-1", "cp1252"]

    for encoding in encodings:
        try:
            with open(input_file, "r", encoding=encoding, errors="ignore") as f:
                content = f.read()

            with open(output_file, "w", encoding="utf-8") as out:
                out.write(content)

            print(f"Converted: {input_file} -> {output_file}")
            return

        except Exception:
            continue

    print(f"Failed: {input_file}")


def process_file(file_path):
    """
    Process a single file
    """

    if should_ignore(file_path):
        return

    relative_path = file_path.relative_to(BASE_DIR)

    parts = list(relative_path.parts)

    # Remove original extension from filename
    file_stem = Path(parts[-1]).stem

    # Replace last part with stem
    parts[-1] = file_stem

    output_base_name = "_".join(parts)

    # Keep DOCX files unchanged
    if file_path.suffix.lower() == ".docx":

        output_path = OUTPUT_DIR / f"{output_base_name}.docx"

        shutil.copy2(file_path, output_path)

        print(f"Copied DOCX: {file_path} -> {output_path}")

    else:
        output_path = OUTPUT_DIR / f"{output_base_name}.txt"

        convert_file_to_txt(file_path, output_path)


def process_folder(folder_path, depth=1):
    """
    Recursively process folders up to MAX_DEPTH
    """

    if depth > MAX_DEPTH:
        return

    for item in folder_path.iterdir():

        if should_ignore(item):
            continue

        if item.is_dir():
            process_folder(item, depth + 1)

        elif item.is_file():
            process_file(item)


# Process everything in the same folder as the script
for item in BASE_DIR.iterdir():

    # Skip output folder
    if item == OUTPUT_DIR:
        continue

    if should_ignore(item):
        continue

    if item.is_file():
        process_file(item)

    elif item.is_dir():
        process_folder(item)

print("\nDone.")