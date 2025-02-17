echo "Your Message" | nc -u 127.0.0.1 2053
dig @127.0.0.1 -p 2053 codecrafters.io
dig @127.0.0.1 -p 2053 +noedns codecrafters.io
dig @127.0.0.1 -p 2053 +noedns +nocookie codecrafters.io google.com
dig @127.0.0.1 -p 2053 -t MX google.com example.com