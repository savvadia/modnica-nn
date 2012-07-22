README
------
This is a folder with APP written with Google App Engine (GAE).

It's available in the web:
http://modnica-nn.appspot.com

To run it locally:
cd /home/diana/Documents/google_appengine
 ./dev_appserver.py  ../google_app/modnica-nn/
 - or - 
./dev_appserver.py  ../google_app/modnica-nn/ -d
where -d stands for debug

Then go to:
http://localhost:8080

To upload a new version:
 - edit app.yaml with new version
 - cd /home/diana/Documents/google_appengine
 - ./appcfg.py update ../google_app/modnica-nn/
 
