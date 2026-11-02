"""
Generate shield icons for the Threat Investigator Chrome extension.
Sizes: 16x16, 48x48, 128x128
Colors: Dark blue background (#0B1120), Blue accent (#60A5FA)
"""

from PIL import Image, ImageDraw
import math
import os

BACKGROUND = (11, 17, 32, 255)     # #0B1120
ACCENT = (96, 165, 250, 255)       # #60A5FA
ACCENT_DARK = (59, 130, 246, 255)  # slightly darker blue for depth
WHITE = (255, 255, 255, 255)

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))


def draw_shield(draw, size):
    """Draw a shield shape with a magnifying glass / checkmark accent."""
    w = h = size
    # Margins as fraction of size
    mx = w * 0.15  # horizontal margin
    mt = h * 0.08  # top margin
    mb = h * 0.08  # bottom margin

    # Shield outline points (normalized then scaled)
    # Shield: flat top with slight arch, curves inward at sides, meets at bottom point
    cx = w / 2.0
    top_y = mt
    bottom_y = h - mb
    left_x = mx
    right_x = w - mx
    shoulder_y = top_y + (bottom_y - top_y) * 0.35  # where the shield starts narrowing

    # Build shield polygon with smooth curves
    points = []
    num_curve = max(8, size // 4)

    # Top edge: slight upward arch from left to right
    for i in range(num_curve + 1):
        t = i / float(num_curve)
        x = left_x + t * (right_x - left_x)
        # slight arch: parabola peaking at center
        arch = -h * 0.03 * (4 * t * (1 - t))
        y = top_y + arch
        points.append((x, y))

    # Right side: from top-right down to shoulder, then curving in to bottom point
    for i in range(1, num_curve + 1):
        t = i / float(num_curve)
        # Bezier-like curve: right_x -> cx at bottom
        # Shoulder control
        if t < 0.4:
            # Nearly straight down
            tt = t / 0.4
            x = right_x
            y = top_y + tt * (shoulder_y - top_y)
        else:
            # Curve inward to bottom point
            tt = (t - 0.4) / 0.6
            # Quadratic bezier from (right_x, shoulder_y) through (right_x*0.7, bottom_y*0.8) to (cx, bottom_y)
            bx0, by0 = right_x, shoulder_y
            bx1, by1 = right_x * 0.85, bottom_y * 0.85
            bx2, by2 = cx, bottom_y
            x = (1-tt)**2 * bx0 + 2*(1-tt)*tt * bx1 + tt**2 * bx2
            y = (1-tt)**2 * by0 + 2*(1-tt)*tt * by1 + tt**2 * by2
        points.append((x, y))

    # Left side: from bottom point back up to top-left (mirror of right)
    for i in range(1, num_curve + 1):
        t = i / float(num_curve)
        if t < 0.6:
            tt = t / 0.6
            bx0, by0 = cx, bottom_y
            bx1, by1 = left_x * 1.15 + (w - left_x * 1.15 - w) * 0, bottom_y * 0.85
            bx2, by2 = left_x, shoulder_y
            # Mirror the control point
            bx1 = w - (right_x * 0.85)  # mirror of right side control
            x = (1-tt)**2 * bx0 + 2*(1-tt)*tt * bx1 + tt**2 * bx2
            y = (1-tt)**2 * by0 + 2*(1-tt)*tt * by1 + tt**2 * by2
        else:
            tt = (t - 0.6) / 0.4
            x = left_x
            y = shoulder_y + (1-tt) * 0 + tt * (-(shoulder_y - top_y))
            y = shoulder_y - tt * (shoulder_y - top_y)
        points.append((x, y))

    # Draw filled shield outline (accent color)
    draw.polygon(points, fill=ACCENT)

    # Draw inner shield (dark background, smaller) to create a border effect
    inner_margin = max(1, size * 0.08)
    inner_points = []
    imx = mx + inner_margin
    imt = mt + inner_margin * 0.8
    imb = mb + inner_margin * 0.5
    i_top_y = imt
    i_bottom_y = h - imb
    i_left_x = imx
    i_right_x = w - imx
    i_shoulder_y = i_top_y + (i_bottom_y - i_top_y) * 0.35

    for i in range(num_curve + 1):
        t = i / float(num_curve)
        x = i_left_x + t * (i_right_x - i_left_x)
        arch = -h * 0.02 * (4 * t * (1 - t))
        y = i_top_y + arch
        inner_points.append((x, y))

    for i in range(1, num_curve + 1):
        t = i / float(num_curve)
        if t < 0.4:
            tt = t / 0.4
            x = i_right_x
            y = i_top_y + tt * (i_shoulder_y - i_top_y)
        else:
            tt = (t - 0.4) / 0.6
            bx0, by0 = i_right_x, i_shoulder_y
            bx1, by1 = i_right_x * 0.85, i_bottom_y * 0.85
            bx2, by2 = cx, i_bottom_y
            x = (1-tt)**2 * bx0 + 2*(1-tt)*tt * bx1 + tt**2 * bx2
            y = (1-tt)**2 * by0 + 2*(1-tt)*tt * by1 + tt**2 * by2
        inner_points.append((x, y))

    for i in range(1, num_curve + 1):
        t = i / float(num_curve)
        if t < 0.6:
            tt = t / 0.6
            bx0, by0 = cx, i_bottom_y
            bx1 = w - (i_right_x * 0.85)
            by1 = i_bottom_y * 0.85
            bx2, by2 = i_left_x, i_shoulder_y
            x = (1-tt)**2 * bx0 + 2*(1-tt)*tt * bx1 + tt**2 * bx2
            y = (1-tt)**2 * by0 + 2*(1-tt)*tt * by1 + tt**2 * by2
        else:
            tt = (t - 0.6) / 0.4
            x = i_left_x
            y = i_shoulder_y - tt * (i_shoulder_y - i_top_y)
        inner_points.append((x, y))

    draw.polygon(inner_points, fill=BACKGROUND)

    # Draw a checkmark inside the shield as the "investigator" symbol
    # Or a simple "eye" / magnifying glass - let's do a clean checkmark
    check_line_width = max(1, int(size * 0.07))

    # Checkmark points relative to center
    # Start from left-middle, go down to center-bottom, then up to right-top
    ck_x1 = cx - w * 0.15
    ck_y1 = h * 0.45
    ck_x2 = cx - w * 0.02
    ck_y2 = h * 0.60
    ck_x3 = cx + w * 0.18
    ck_y3 = h * 0.32

    # Draw checkmark with thick lines
    draw.line([(ck_x1, ck_y1), (ck_x2, ck_y2)], fill=ACCENT, width=check_line_width)
    draw.line([(ck_x2, ck_y2), (ck_x3, ck_y3)], fill=ACCENT, width=check_line_width)

    # Round the joints/ends for cleaner look
    r = check_line_width / 2.0
    for px, py in [(ck_x1, ck_y1), (ck_x2, ck_y2), (ck_x3, ck_y3)]:
        draw.ellipse([px - r, py - r, px + r, py + r], fill=ACCENT)


def generate_icon(size, filepath):
    """Generate a single icon at the given size."""
    img = Image.new("RGBA", (size, size), BACKGROUND)
    draw = ImageDraw.Draw(img)
    draw_shield(draw, size)
    img.save(filepath, "PNG")
    print(f"  Created {filepath} ({size}x{size})")


def main():
    sizes = [16, 48, 128]
    print("Generating Threat Investigator extension icons...")
    for size in sizes:
        filename = f"icon{size}.png"
        filepath = os.path.join(OUTPUT_DIR, filename)
        generate_icon(size, filepath)
    print("Done! All icons generated successfully.")


if __name__ == "__main__":
    main()
