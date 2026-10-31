import hashlib
import mimetypes
import os
from datetime import datetime


def calculate_sha256(file_path):
    """Calculate SHA-256 using 1 MB chunks."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def get_file_analysis(file_path):
    """
    Collect forensic-friendly metadata from the preserved evidence copy.

    This function only reads the file and does not modify it.
    """

    if not file_path:
        raise ValueError("No file path was supplied.")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            "The preserved evidence file could not be found."
        )

    stat = os.stat(file_path)

    file_name = os.path.basename(file_path)
    extension = os.path.splitext(file_name)[1]

    if extension:
        extension = extension.lower()
    else:
        extension = "No extension"

    mime_type, _ = mimetypes.guess_type(file_path)

    if not mime_type:
        mime_type = "Unknown"

    size_bytes = stat.st_size
    size_kb = size_bytes / 1024
    size_mb = size_bytes / (1024 * 1024)

    created_time = datetime.fromtimestamp(
        stat.st_ctime
    ).strftime("%Y-%m-%d %H:%M:%S")

    modified_time = datetime.fromtimestamp(
        stat.st_mtime
    ).strftime("%Y-%m-%d %H:%M:%S")

    accessed_time = datetime.fromtimestamp(
        stat.st_atime
    ).strftime("%Y-%m-%d %H:%M:%S")

    sha256 = calculate_sha256(file_path)

    return {
        "file_name": file_name,
        "full_path": os.path.abspath(file_path),
        "extension": extension,
        "mime_type": mime_type,
        "size_bytes": size_bytes,
        "size_kb": size_kb,
        "size_mb": size_mb,
        "created_time": created_time,
        "modified_time": modified_time,
        "accessed_time": accessed_time,
        "sha256": sha256,
    }
