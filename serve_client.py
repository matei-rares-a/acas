#!/usr/bin/env python3
"""
Simple HTTP server to serve the client application.
Run this from the client_app directory.
"""

import http.server
import socketserver
import os
import ssl

class CORSHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

if __name__ == '__main__':
    PORT = 8000

    # Change to client_app directory
    os.chdir('client_app')

    with socketserver.TCPServer(("", PORT), CORSHTTPRequestHandler) as httpd:
        print(f"Serving client application at http://localhost:{PORT}")
        print("Open your browser and go to:")
        print(f"  Register: http://localhost:{PORT}/register.html")
        print(f"  Login:    http://localhost:{PORT}/login.html")
        print(f"  Home:     http://localhost:{PORT}/index.html")
        print("\nPress Ctrl+C to stop the server")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped")
            httpd.shutdown()