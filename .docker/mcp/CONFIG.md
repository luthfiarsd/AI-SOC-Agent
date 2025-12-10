# MCP Configuration Files

Folder ini berisi konfigurasi untuk integrasi AI-SOC-Agent dengan Claude Desktop.


- `catalogs.json` - Daftar katalog tools yang tersedia dengan use case masing-masing
- `claude_desktop_config.json` - Konfigurasi MCP server untuk Claude Desktop
- `server-info.json` - Informasi detail tentang MCP server, capabilities, dan environment requirements
- `tools-catalog.json` - Daftar lengkap semua tools dengan parameter dan return value

## Cara Menggunakan

### Setup Claude Desktop

1. Buka file konfigurasi Claude Desktop di:

   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. Copy isi dari `config/claude_desktop_config.json` ke file konfigurasi Claude Desktop

3. Sesuaikan path `args` dengan lokasi `server.py` di sistem Anda

4. Restart Claude Desktop

Setelah restart Claude Desktop, MCP server akan otomatis terhubung. Anda dapat memverifikasi dengan:

1. Cek logs Claude Desktop untuk memastikan server berhasil connect
2. Coba gunakan salah satu tools, misalnya: "Get bad hosts in last 24 hours"
