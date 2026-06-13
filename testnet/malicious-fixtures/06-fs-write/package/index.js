const fs = require('fs');
const os = require('os');
const target = require('path').join(os.homedir(), '.creg-exfil-marker');
fs.writeFileSync(target, 'marker');
