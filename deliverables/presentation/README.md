# Presentation

The thirty-minute deck for the assignment. `deck.mjs` is the deck itself: a plain ES module exporting `meta` and `slides`. `app.mjs` renders it, `styles.css` carries the design, and `index.html` is the entry point. There is no build step and no dependency.

## Run it

ES modules do not load from `file://`, so serve the folder:

```
python3 -m http.server 8000
```

Then open <http://localhost:8000>. Keys: arrows or space to move, `n` for speaker notes, `f` for fullscreen. Add `#7` to the URL to open a slide directly.

## Printing

`deck.pdf` is the 18-slide export. To regenerate it, print the page to PDF from the browser. The print stylesheet hides the controls, puts one slide on each 1280×720 page, and leaves the notes out.

## Files

| File | Contents |
| --- | --- |
| `deck.mjs` | Slide content and speaker notes |
| `app.mjs` | Renderer, keyboard navigation, notes panel |
| `styles.css` | Layout and typography |
| `index.html` | Entry point |
| `deck.pdf` | Exported slides |

Facts and figures match `deliverables/report/main.tex` as of 26 November 2026. If one changes, change the other.
