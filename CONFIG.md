# WebScope Configuration

WebScope supports configuration files to customize behavior, including the ability to use custom wordlists for path discovery.

## Configuration File Locations

WebScope will automatically search for configuration files in the following locations (in order):

1. `~/.webscope/config.json`
2. `~/.config/webscope/config.json`
3. `./webscope.json` (current directory)
4. `./config.json` (current directory)

You can also specify a custom configuration file using the `-c` flag:

```bash
webscope -c /path/to/your/config.json
```

## Configuration Format

The configuration file uses JSON format. Here's an example:

```json
{
  "wordlists": {
    "common_paths": "wordlists/custom-paths.txt"
  }
}
```

## Configuration Options

### Wordlists

#### `wordlists.common_paths`

Specifies a custom wordlist file for path discovery. The paths can be:

- **Absolute paths**: `/home/user/wordlists/custom.txt`
- **Relative to ~/.webscope/**: `custom-paths.txt` → `~/.webscope/custom-paths.txt`
- **Relative to config file**: `./wordlists/paths.txt`

## Custom Wordlist Format

Custom wordlist files should contain one path per line:

```
# Comments start with #
admin
api/v1
api/v2
.env
robots.txt
sitemap.xml
```

## Priority Order

WebScope uses wordlists in this priority order:

1. **Custom wordlist** (from config file)
2. **Embedded wordlist** (built into the binary)
3. **Default fallback wordlist** (hardcoded list)

## Example Usage

1. Create a configuration file:
```bash
mkdir -p ~/.webscope
cat > ~/.webscope/config.json << EOF
{
  "wordlists": {
    "common_paths": "custom-paths.txt"
  }
}
EOF
```

2. Create a custom wordlist:
```bash
cat > ~/.webscope/custom-paths.txt << EOF
admin
api
graphql
.env
config.json
EOF
```

3. Run WebScope (will automatically use the config):
```bash
echo 'https://example.com' | webscope -v
```

4. Or specify a custom config file:
```bash
echo 'https://example.com' | webscope -c /path/to/config.json -v
```

## Example Files

See the included example files:

- `example-config.json` - Example configuration file
- `wordlists/custom-paths-example.txt` - Example custom wordlist file