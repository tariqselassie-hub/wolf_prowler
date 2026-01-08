# Wolf UI Kit Documentation

The Wolf UI Kit is a specialized component library built for the Wolf Prowler dashboard. It prioritizes performance, visual consistency, and a strict "Cyber-Admin" aesthetic.

## Components

### `Card`
A generic container with a semi-transparent background, border styling, and optional hover effects.

**Usage:**
```rust
Card {
    h3 { "Title" }
    p { "Content" }
}
```

### `Button`
An interactive element for triggering actions. Supports `disabled` state and `onclick` handlers.

**Usage:**
```rust
Button {
    onclick: move |_| do_something(),
    disabled: is_loading(),
    "Execute"
}
```

### `Badge`
A compact status indicator.

**Props:**
- `label`: Text content.
- `color`: Semantic color string ("green", "red", "blue", "yellow").

**Usage:**
```rust
Badge { label: "ONLINE", color: "green" }
```

### `Sparkline`
A lightweight SVG chart for visualizing trends without the overhead of a full charting library.

**Props:**
- `data`: `Vec<f32>` of values.
- `width` / `height`: Dimensions.
- `color`: Stroke color.

**Usage:**
```rust
Sparkline {
    data: vec![1.0, 5.0, 3.0, 8.0],
    width: 100.0,
    height: 30.0,
    color: "blue"
}
```

## Styling
All components utilize Tailwind CSS utility classes. The design system enforces:
- **Font**: Monospace (`font-mono`).
- **Colors**: High-contrast neons (Green-500, Red-500) against dark backgrounds (Black/Gray-900).
- **Effects**: Subtle glows, scanlines, and glassmorphism (backdrop-blur).
