"""Gera assets do instalador (icones, banners)."""
import os
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("A instalar Pillow...")
    os.system("pip install Pillow")
    from PIL import Image, ImageDraw, ImageFont

def create_icon():
    sizes = [256, 128, 64, 48, 32, 16]
    images = []
    for size in sizes:
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        cx, cy = size // 2, size // 2
        r = size // 2 - 2
        draw.ellipse([2, 2, size-2, size-2], fill=(0, 100, 50))
        draw.ellipse([2, 2, size-2, size-2], outline=(0, 200, 83), width=max(1, size//32))
        font_size = size // 3
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except (OSError, IOError):
            font = ImageFont.load_default()
        text = "BS"
        bbox = draw.textbbox((0, 0), text, font=font)
        tw = bbox[2] - bbox[0]
        draw.text(((size - tw) // 2, (size - font_size) // 2), text, fill=(255, 255, 255), font=font)
        images.append(img)
    output = Path(__file__).parent / "assets" / "icon.ico"
    output.parent.mkdir(parents=True, exist_ok=True)
    images[0].save(str(output), format='ICO', sizes=[(s, s) for s in sizes], append_images=images[1:])
    print(f"  Icone: {output}")

def create_banner():
    width, height = 493, 58
    img = Image.new('RGB', (width, height), (26, 26, 26))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, width, 3], fill=(0, 200, 83))
    try:
        font = ImageFont.truetype("arial.ttf", 18)
        font_sub = ImageFont.truetype("arial.ttf", 10)
    except (OSError, IOError):
        font = ImageFont.load_default()
        font_sub = ImageFont.load_default()
    draw.text((15, 12), "BenguelaShield", fill=(255, 255, 255), font=font)
    draw.text((15, 35), "Proteccao Municipal Inteligente", fill=(0, 200, 83), font=font_sub)
    output = Path(__file__).parent / "assets" / "banner.bmp"
    img.save(str(output), format='BMP')
    print(f"  Banner: {output}")

def create_dialog():
    width, height = 164, 314
    img = Image.new('RGB', (width, height), (26, 26, 26))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, 3, height], fill=(0, 200, 83))
    cx, cy = width // 2, 100
    r = 50
    draw.ellipse([cx-r, cy-r, cx+r, cy+r], fill=(0, 100, 50))
    draw.ellipse([cx-r, cy-r, cx+r, cy+r], outline=(0, 200, 83), width=3)
    try:
        font = ImageFont.truetype("arial.ttf", 36)
        font2 = ImageFont.truetype("arial.ttf", 14)
        font3 = ImageFont.truetype("arial.ttf", 10)
    except (OSError, IOError):
        font = font2 = font3 = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), "BS", font=font)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy - 20), "BS", fill=(255, 255, 255), font=font)
    draw.text((20, 170), "Benguela", fill=(255, 255, 255), font=font2)
    draw.text((20, 190), "Shield", fill=(0, 200, 83), font=font2)
    draw.text((20, 220), "v1.0.0", fill=(120, 120, 120), font=font3)
    draw.text((20, 250), "Open Source", fill=(120, 120, 120), font=font3)
    draw.text((20, 270), "GPLv2", fill=(120, 120, 120), font=font3)
    output = Path(__file__).parent / "assets" / "dialog.bmp"
    img.save(str(output), format='BMP')
    print(f"  Dialog: {output}")

if __name__ == "__main__":
    print("A gerar assets...")
    create_icon()
    create_banner()
    create_dialog()
    print("Assets criados!")