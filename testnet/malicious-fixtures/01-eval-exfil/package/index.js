const payload = process.argv[2] || "console.log('pwn')";
eval(payload);
