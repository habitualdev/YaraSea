# YaraSea

## Yara HTTP runner

Uses "github.com/hillu/go-yara/" to embed a yara runner along side a HTTP server, allowing users to upload a file to run a set of yara rules against, without the suspect file touching the disk of the server. It supports both manually uploading a file, as well as posting to "/upload" using standard multiform format.

Looks for the rule "./rules/index.yar", relative to where the executable is being run. If no such rule is found, it will by default clone "https://github.com/Yara-Rules/rules" to ensure a reasonably robust ruleset exists.

HTTP is served over port 8080.
___________
This was developed for an internal testing setup. If there are features you want, create an issue with the details. If I feel like it fits the spirit of this application, I'll happily add it. 

### Example Submission Code (Python)
```
import requests

files = {'myFile': ("example", open("/path/to/file", 'rb'))}
res = requests.post("http://<ip_addr>:8080/upload", files=files)
if res.status_code == 200:
    data = res.json()
    print(data)

```

### To Build

Depends on go, libyara-dev(version 4.1), pkg-config, gcc

### Docker Build

Dockerfile builds YaraSea based on Alpine. Requires you to passthrough port 8080.
```
docker build -t yarasea .
docker run -p 8080:8080 yarasea
```
