# WebSnoopy

Script for fast recon through multiple web servers. You must specify file with URLs in 
first param. 

```
./websnoopy.py list-of-urls.txt
```

list-of-urls.txt example:
```
http://1.1.1.1:8080/
http://1.1.1.2/
https://1.1.1.3/
https://1.1.1.4:8443/
```

WebSnoopy will show you interest headers, meta tags and other info. You may find it in 
websnoopy.log in the end of work.