# dsh-file-opener

Turns file and directory paths that appear in a DSH conversation into clickable buttons: click one to preview it in the right sidebar, or to open it with your system's default application.

- Package: `dsh-file-opener`
- Repository: <https://github.com/sailoumili/dsh-file-opener>
- Supports the web and desktop builds of DSH 0.1.7-alpha.1 and later
- No third-party runtime dependencies, writes no state files, makes no network requests

## Features

| Action | Result |
|---|---|
| Click a file path | Opens in the right sidebar if the sidebar can display it, otherwise with the system default application |
| Shift + click a file path | Always opens with the system default application |
| Click a directory path | Opens the directory in File Explorer |
| Click the folder icon after a path | File: opens the directory containing it. Directory: opens the directory itself |
| Click a path that does not exist | Opens the nearest real directory above it, without an error |

- Recognized path forms: absolute paths, `~/...` (expanded to the current user's home directory), and `./` or `../` (resolved against the session working directory).
- Inline code in user messages that carries no official button becomes clickable with the same folder icon, as long as its content is a path.
- A failed open always shows a visible message; nothing fails silently.

## Installation

### Web build

```
dsh plugin --profile web add dsh-file-opener
```

### Desktop build

1. Open the DSH desktop app and click **Plugins** in the left sidebar.
2. Click **Add plugin**.
3. Enter the package name `dsh-file-opener` and click **Install**, then wait for it to finish.
4. When installation completes, click **Enable now** and confirm its switch is on under **Installed**.

## Making the AI emit clickable paths

The plugin recognizes path text inside inline code (wrapped in backticks). To make files mentioned in AI replies clickable, ask the AI to write complete paths in your agent instruction file (for example `AGENTS.md`):

```
Every file or directory you mention in a reply must be wrapped in backticks as a complete
absolute path, for example `C:\work\report.md`. Never write only a file name, and never give
a directory and then a bare file name.
```

## What happens when you click

Clicking a file path resolves in this order:

1. The path does not exist → open the directory containing it.
2. The path is a directory → open it in File Explorer.
3. The path is a file:
   1. Its content is plain text → right sidebar;
   2. Otherwise, query the official previewer registry; a match → right sidebar;
   3. No match → system default application.

Plain text is decided by content alone: the first 4 KB are read, and the file counts as plain text when it contains no NUL byte and decodes as UTF-8. The extension is irrelevant.

### Formats that open in the right sidebar

Markdown (`md`, `markdown`), HTML (`html`, `htm`), images (`png`, `jpg`, `jpeg`, `gif`, `webp`, `bmp`, `ico`, `svg`), PDF (`pdf`), Office (`doc`, `docx`, `ppt`, `pptx`), Excel (`xlsx`, `xls`, `csv`, `tsv`), syntax-highlighted code (every suffix in the official code-language table, such as `ts`, `js`, `py`, `go`, `rs`, `java`, `c`, `cpp`, `cs`, `php`, `sh`, `bat`, `ps1`, `yaml`, `toml`, `sql`, `xml`, `css`), and any file whose content is plain text (such as `txt`, `log`, `dxf`).

### Formats that open with the system default application

`dwg`, `psd`, `ai`, `skp`, `max`, `zip`, `7z`, `rar`, `mp3`, `mp4`, `exe`, `msi`, `lnk`, `iso`, `tif`, `tiff`, `avif`, and similar: archives, audio and video, installers, disk images, and binary formats the official previewers do not handle.

### Two cases that look like faults but are not

- **`.dxf`**: DXF is a text format, so it is treated as plain text and shown as source in the sidebar rather than launching CAD. Hold Shift while clicking to open it in CAD.
- **`.docx`, `.xlsx`, `.pptx`**: DSH 0.2.0-rc.2 ships Office and Excel previewers, so these open in the sidebar rather than launching Office. This is intended behavior.

Office and Excel previews in the sidebar depend on the host's conversion component. When conversion fails, the sidebar only reports that it cannot preview the file and does not fall back automatically; hold Shift while clicking to open it with the system application.

## Known limitations

- Opening directories is implemented for Windows only; other platforms fall back to the right sidebar.
- UNC network paths (`\\server\share`) and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`) are not opened.
- Relative paths have no absolute path available and can only open in the sidebar; Shift does not force the system application for them.
- A path outside the workspace handed to the sidebar preview can return 403 under the host's access policy, and a very large file can return 413; hold Shift while clicking to open it with the system application.
- A path the process cannot read is treated as missing, which shows up as opening its parent directory.
- When a file name ends with a single quote or a backtick, that character is stripped as punctuation.

## License

MIT, see `LICENSE`.
