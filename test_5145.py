import subprocess
import xml.etree.ElementTree as ET

cmd = ['wevtutil', 'qe', 'Security', '/q:*[System[(EventID=5145)]]', '/e:Events', '/c:5', '/rd:true']
res = subprocess.run(cmd, capture_output=True, text=True)

root = ET.fromstring(res.stdout)
ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

for event in root.findall('ns:Event', ns):
    edata = event.find('ns:EventData', ns)
    if edata is not None:
        target = ""
        accesses = ""
        for data in edata.findall('ns:Data', ns):
            if data.get('Name') == 'RelativeTargetName':
                target = data.text
            elif data.get('Name') == 'AccessList':
                accesses = data.text
        print(f"Target: {target}")
        print(f"Accesses: {accesses}")
        print("---")
