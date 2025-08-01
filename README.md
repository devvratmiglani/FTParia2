# FTPAria2

**FTParia2** (CLI: `aftp`) is a high-performance FTP file crawler and downloader. It provides powerful filtering, traversal control, and parallel downloading using `aria2`. The tool is ideal for scripting, automation, or selectively downloading large FTP trees quickly and flexibly.

## Motive

Tools like wget and lftp exist, but none are perfect for this task. Most lack recursive downloading, and those that support it don't offer multithreaded or multi-connection modes—making them slower, especially for many small files. lftp comes close but fails to set proper file permissions, which is tedious to fix on Windows. I also find its commands hard to remember. I prefer using [aria2](https://github.com/aria2/aria2), which handles these things better and faster, [aria2](https://github.com/aria2/aria2) is not intended to recursively crawl and here I fill that gap.
<!-- I built this mostly for myself because I wanted something fast, simple, and cross-platform friendly using aria2 -->
## Features

- Traverse FTP directories recursively
- Filter files and directories
- Multithreaded and Multi-connection [aria2](https://github.com/aria2/aria2)
- Clone directory structure with [aria2](https://github.com/aria2/aria2)
- Directly download matched files to flat structure
- Filter by extension, path, or file name
- Customize recursion and exclusion
- Control parallelism and directory layout

## Installation

### Windows

```bash
pip install git+https://github.com/devvratmiglani/FTParia2.git
```
A copy of `Aria2` is supplied for windows, system installed overrides it.

### Linux
`Aria2` needs to be installed for your operating system.
#### Debian Based (Ubuntu, Linux Mint, ...)
```bash
sudo apt install aria2
```
Then:
```bash
pip install git+https://github.com/devvratmiglani/FTParia2.git
```
If you get `break-system-packages` error, use [pipx](https://github.com/pypa/pipx?tab=readme-ov-file#pipx--install-and-run-python-applications-in-isolated-environments)
```bash
pipx install git+https://github.com/devvratmiglani/FTParia2.git
```

<!-- Or install directly with pip once published:
```bash
pip install FTParia2
``` -->
Then use it as a CLI:

```bash
aftp ftp://host/path
```
Only shows directory listing in ftp_links.txt

## Basic Usage

```
aftp [HOST_AND_PATH] [OPTIONS]
```

`HOST_AND_PATH` is the FTP server URI:

```
ftp://user:pass@host:port/path
ftp://user:pass@ftp.example.com/path
```

All filters and commands work only when a valid FTP URI is given.

## Commands
```bash
  -h, --help            show this help message and exit
  -u USER, --user USER  Username (overrides URL credentials)
  -p PASSWORD, --password PASSWORD
                        Password (overrides URL credentials)
  --port PORT           Port (overrides URL port; default 21)
  --ftps                Use explicit TLS (overrides URL scheme)
  --start START         Start path on server (overrides URL path; default '/')
  --out OUT             Base output name (used for listing and link files)
  --active              Use active mode (default: passive)
  --timeout TIMEOUT     Socket timeout in seconds (default: 30)
  --no-mlsd             Disable MLSD preference and use portable listing
  -e EXTENSION, --extension EXTENSION
                        Include only these file extensions (case-insensitive). Repeat or comma-separate.
  -ie IGNORE_EXTENSION, --ignore-extension IGNORE_EXTENSION
                        Exclude these file extensions (case-insensitive). Repeat or comma-separate.
  -r REGEX, --regex REGEX
                        Filter regex (applies to BOTH files & dirs; basename).
  -rf REGEX_FILE, --regex-file REGEX_FILE
                        Filter regex for FILES only (basename).
  -rd REGEX_DIR, --regex-dir REGEX_DIR
                        Filter regex for DIRECTORIES only (basename).
  -xrd EXCLUDE_REGEX_DIR, --exclude-regex-dir EXCLUDE_REGEX_DIR
                        Exclude regex for DIRECTORIES only.
  --link-file {aria2,wget,curl,powershell}
                        Generate a link file for the given tool. Can be specified multiple times.
  --keep-structure      Keep relative directory structure in generated link files (per-file dir).
  --embed-user-pass     Embed user:pass@host:port in generated links. (Clone mode implies this by default.)
  --clone               Clone the server subtree into a local folder using aria2c.
  --clone-dir CLONE_DIR
                        Destination directory name for --clone (default: host name).
  -d, --download        Download the server files into a local folder using aria2c. Ignored if --clone is used
  -ddir DOWNLOAD_DIR, --download-dir DOWNLOAD_DIR
                        Destination directory name for --download (default: host name).
  --examples            Show usage examples for all features and exit.
```
<!-- - `--server`: (Reserved for future - run interactive server) -->
## Filters

- `-e EXT`: Include files with extension [`.EXT` |`EXT`]
- `-ie EXT`: Exclude files with extension [`.EXT` |`EXT`]
- `-rf REGEX`: Include only files matching REGEX
- `-rd REGEX`: Include only directories matching REGEX
- `-xrd REGEX`: Exclude directories (omit scanning) matching REGEX
<!-- - `--max-depth N`: Limit recursion depth
- `--max-files N`: Stop after N files
- `--max-size N`: Skip files larger than N bytes -->

## FTP(S) Options
- `--active`: Use active mode (default: passive)
- `--ftps`: Use FTPS
- `--port`: Override port number
- `--user`, `--password`: Override or supply credentials

## Examples

### Clone FTP Server Using Aria2
```
aftp ftp://user:pass@host:port/ --clone
```

### Clone to Specific Directory
```
aftp ftp://user:pass@host:port/ --clone --clone-dir my_ftp_backup
```

### Combine Clone with Filters
```
aftp ftp://user:pass@host:port/ --clone -e pdf -xrd "Android" -rf "report"
```

### Flat Download with File Filters
```
aftp ftp://host/ --download -e zip -rf "dataset"
```

### Download to Custom Directory
```
aftp ftp://host/ -d -ddir /tmp/data
```

### Use FTPS with Credentials
```
aftp ftp://host/ --ftps --user admin --password secret --clone
```
### Create Link File
```
aftp ftp://user:pass@ftp.example.com/ --link-file aria2 --link-file wget --embed-user-pass
```

## Development & Contributions

The tool is designed with modularity and future extensibility in mind. Planned features include:

- Interactive server browsing with fuzzy-finder (`fzf`)
- Persistent config/profiles

To contribute:

1. Fork and clone the repo
2. Make changes in a feature branch
3. Test
4. Submit a pull request

## License

GPL-2.0 license