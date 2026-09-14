import struct
import json

def generate_viewer():
    with open('industrial_meltdown.pcap', 'rb') as f: data = f.read()
    magic = struct.unpack('<I', data[0:4])[0]
    endian = '<' if magic == 0xA1B2C3D4 else '>'
    offset = 24
    
    SCADA = "192.168.100.20"
    
    # Extract all registers ordered by time
    bits_time = []
    
    # Also group by unit
    bits_unit = {i: [] for i in range(1, 11)}
    
    while offset < len(data) - 16:
        incl_len = struct.unpack(endian + 'I', data[offset+8:offset+12])[0]
        pkt = data[offset+16:offset+16+incl_len]
        offset += 16 + incl_len
        
        if len(pkt) > 54 and struct.unpack('>H', pkt[12:14])[0] == 0x0800:
            ip = pkt[14:]
            if len(ip) > 20 and ip[9] == 6:
                src_ip = '.'.join(str(b) for b in ip[12:16])
                dst_ip = '.'.join(str(b) for b in ip[16:20])
                ihl = (ip[0] & 0xF) * 4
                tcp = ip[ihl:]
                if len(tcp) >= 20:
                    src_port = struct.unpack('>H', tcp[0:2])[0]
                    doff = ((tcp[12] >> 4) & 0xF) * 4
                    payload = tcp[doff:]
                    
                    if dst_ip == SCADA and src_port == 502 and len(payload) >= 8:
                        fc = payload[7]
                        if fc == 3 and len(payload) >= 9:
                            bc = payload[8]
                            if len(payload) >= 9 + bc:
                                reg_bytes = payload[9:9+bc]
                                unit_id = int(src_ip.split('.')[-1]) - 100
                                for i in range(0, bc, 2):
                                    if i + 1 < bc:
                                        val = struct.unpack('>H', reg_bytes[i:i+2])[0]
                                        # Convert to 16 bits
                                        bits = [(val >> b) & 1 for b in range(15, -1, -1)]
                                        bits_time.extend(bits)
                                        if 1 <= unit_id <= 10:
                                            bits_unit[unit_id].extend(bits)

    # Concatenate by unit 1 to 10
    bits_by_unit = []
    for i in range(1, 11):
        bits_by_unit.extend(bits_unit[i])
        
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Meltdown Viewer</title>
        <style>
            body { font-family: monospace; background: #222; color: #0f0; margin: 20px; }
            canvas { background: #000; border: 1px solid #555; image-rendering: pixelated; margin-top: 20px; }
            .controls { margin-bottom: 20px; }
            input[type=range] { width: 500px; }
        </style>
    </head>
    <body>
        <h2>Interactive Bitstream Viewer</h2>
        <div class="controls">
            <label>Mode: 
                <select id="mode">
                    <option value="time">Ordered by Time</option>
                    <option value="unit">Ordered by Unit (1 to 10)</option>
                </select>
            </label><br><br>
            <label>Width: <span id="width-val">100</span></label><br>
            <input type="range" id="width" min="10" max="1000" value="100"><br><br>
            <label>Offset: <span id="offset-val">0</span></label><br>
            <input type="range" id="offset" min="0" max="100" value="0"><br><br>
            <label>Invert Colors: <input type="checkbox" id="invert"></label>
        </div>
        <canvas id="canvas"></canvas>
        <script>
            const bitsTime = %s;
            const bitsUnit = %s;
            
            const canvas = document.getElementById('canvas');
            const ctx = canvas.getContext('2d');
            const widthSlider = document.getElementById('width');
            const offsetSlider = document.getElementById('offset');
            const widthVal = document.getElementById('width-val');
            const offsetVal = document.getElementById('offset-val');
            const modeSelect = document.getElementById('mode');
            const invertCheck = document.getElementById('invert');
            
            function draw() {
                const width = parseInt(widthSlider.value);
                const offset = parseInt(offsetSlider.value);
                const invert = invertCheck.checked;
                const mode = modeSelect.value;
                const bits = mode === 'time' ? bitsTime : bitsUnit;
                
                widthVal.textContent = width;
                offsetVal.textContent = offset;
                
                const height = Math.ceil((bits.length - offset) / width);
                canvas.width = width;
                canvas.height = height;
                
                const imgData = ctx.createImageData(width, height);
                for (let i = offset; i < bits.length; i++) {
                    const idx = i - offset;
                    const val = bits[i] === 1 ? (invert ? 0 : 255) : (invert ? 255 : 0);
                    const pIdx = idx * 4;
                    imgData.data[pIdx] = val;     // R
                    imgData.data[pIdx+1] = val;   // G
                    imgData.data[pIdx+2] = val;   // B
                    imgData.data[pIdx+3] = 255;   // A
                }
                ctx.putImageData(imgData, 0, 0);
                
                // Scale up canvas for visibility
                canvas.style.width = (width * 2) + "px";
                canvas.style.height = (height * 2) + "px";
            }
            
            widthSlider.addEventListener('input', draw);
            offsetSlider.addEventListener('input', draw);
            modeSelect.addEventListener('change', draw);
            invertCheck.addEventListener('change', draw);
            
            draw();
        </script>
    </body>
    </html>
    """ % (json.dumps(bits_time), json.dumps(bits_by_unit))
    
    with open('viewer.html', 'w', encoding='utf-8') as f:
        f.write(html)
    print("Created viewer.html. Open it in your web browser!")

if __name__ == "__main__":
    generate_viewer()
