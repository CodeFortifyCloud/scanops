from pathlib import Path
import shutil


def sanitize_filename(name: str) -> str:
    """
    Folder name থেকে safe filename তৈরি করে।
    চাইলে এখানে আরও rule যোগ করতে পারবেন।
    """
    return name.strip()


def ensure_unique_path(destination: Path) -> Path:
    """
    যদি destination file আগে থেকেই থাকে, তাহলে _1, _2 ইত্যাদি suffix যোগ করে
    unique filename তৈরি করবে।
    """
    if not destination.exists():
        return destination

    stem = destination.stem
    suffix = destination.suffix
    parent = destination.parent
    counter = 1

    while True:
        new_path = parent / f"{stem}_{counter}{suffix}"
        if not new_path.exists():
            return new_path
        counter += 1


def process_main_folder(main_folder: str) -> None:
    main_path = Path(main_folder).resolve()

    if not main_path.exists() or not main_path.is_dir():
        raise ValueError(f"Invalid folder path: {main_path}")

    html_output = main_path / "html"
    images_output = main_path / "images"

    html_output.mkdir(exist_ok=True)
    images_output.mkdir(exist_ok=True)

    print(f"Main folder: {main_path}")
    print(f"HTML output: {html_output}")
    print(f"Images output: {images_output}")
    print("-" * 60)

    # main folder এর direct subfolder গুলো process করবে
    for subfolder in main_path.iterdir():
        if not subfolder.is_dir():
            continue

        # output folder দুইটা skip করবে
        if subfolder.name in {"html", "images"}:
            continue

        folder_name = sanitize_filename(subfolder.name)

        source_html = subfolder / "code.html"
        source_png = subfolder / "screen.png"

        renamed_html = subfolder / f"{folder_name}.html"
        renamed_png = subfolder / f"{folder_name}.png"

        print(f"Processing folder: {subfolder.name}")

        # HTML rename
        if source_html.exists():
            if renamed_html.exists() and renamed_html != source_html:
                print(f"  [WARN] Target HTML already exists: {renamed_html.name}")
            else:
                source_html.rename(renamed_html)
                print(f"  Renamed: code.html -> {renamed_html.name}")
        elif renamed_html.exists():
            print(f"  HTML already renamed: {renamed_html.name}")
        else:
            print("  [WARN] code.html not found")

        # PNG rename
        if source_png.exists():
            if renamed_png.exists() and renamed_png != source_png:
                print(f"  [WARN] Target PNG already exists: {renamed_png.name}")
            else:
                source_png.rename(renamed_png)
                print(f"  Renamed: screen.png -> {renamed_png.name}")
        elif renamed_png.exists():
            print(f"  PNG already renamed: {renamed_png.name}")
        else:
            print("  [WARN] screen.png not found")

        # HTML move
        if renamed_html.exists():
            target_html_path = ensure_unique_path(html_output / renamed_html.name)
            shutil.move(str(renamed_html), str(target_html_path))
            print(f"  Moved HTML -> {target_html_path}")

        # PNG move
        if renamed_png.exists():
            target_png_path = ensure_unique_path(images_output / renamed_png.name)
            shutil.move(str(renamed_png), str(target_png_path))
            print(f"  Moved PNG  -> {target_png_path}")

        print("-" * 60)

    print("All tasks completed successfully.")


if __name__ == "__main__":
    # এখানে main folder path দিন
    main_folder_path = "/home/jaki/Downloads/nationwire_news_portal"

    process_main_folder(main_folder_path)
