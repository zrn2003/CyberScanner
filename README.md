# CyberScanner Backend API

A comprehensive FastAPI-based backend for network scanning and vulnerability assessment.

## Features

- **Port Scanning**: TCP/UDP port scanning with customizable port ranges
- **Vulnerability Detection**: Automated vulnerability assessment for common services
- **Real-time Monitoring**: WebSocket-based real-time scan progress updates
- **MongoDB Integration**: Persistent storage for scan results and history
- **RESTful API**: Clean, documented API endpoints
- **CORS Support**: Cross-origin resource sharing enabled

## Tech Stack

- **FastAPI**: Modern, fast web framework for building APIs
- **Python 3.8+**: Core programming language
- **MongoDB**: NoSQL database for data persistence
- **Nmap**: Network discovery and security auditing
- **WebSockets**: Real-time communication
- **Uvicorn**: ASGI server for running the application

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/zrn2003/CyberScanner.git
   cd CyberScanner/backend
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up MongoDB**
   - Install MongoDB or use MongoDB Atlas
   - Update the `MONGODB_URL` in `main.py` with your connection string

4. **Run the application**
   ```bash
   python start.py
   ```

## API Endpoints

### Port Scanning
- `POST /scan/ports` - Start a new port scan
- `GET /scan/status/{scan_id}` - Get scan status
- `GET /scan/results/{scan_id}` - Get scan results

### Vulnerability Assessment
- `POST /vulnerability/scan` - Start vulnerability scan
- `GET /vulnerability/results/{scan_id}` - Get vulnerability results

### Scan Management
- `GET /scans/history` - Get scan history
- `DELETE /scans/{scan_id}` - Delete scan results
- `GET /scans/search` - Search scans by criteria

### Real-time Updates
- WebSocket endpoint for real-time scan progress

## Configuration

The application can be configured through environment variables or by modifying the constants in `main.py`:

- `MONGODB_URL`: MongoDB connection string
- `DATABASE_NAME`: Database name
- `COLLECTION_NAME`: Collection name for scan results

## Usage Examples

### Start a Port Scan
```bash
curl -X POST "http://localhost:8000/scan/ports" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "192.168.1.1",
       "ports": "common_services",
       "scan_type": "tcp",
       "timeout": 5
     }'
```

### Get Scan Results
```bash
curl "http://localhost:8000/scan/results/{scan_id}"
```

## Security Considerations

- Input validation and sanitization
- Rate limiting for scan requests
- Secure MongoDB connection
- CORS configuration for frontend integration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For support and questions, please open an issue on GitHub.
