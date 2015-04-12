# Flask WebRTC Demo

This project demononstrates how to implement WebRTC with Flask.

Motivations behind project:
 - Create simple example to experiment
 - Use [SSE](https://developer.mozilla.org/en-US/docs/Server-sent_events/Using_server-sent_events) and not WebSockets

# Installation

    git clone https://github.com/spectralsun/flask-webrtc-demo.git
    cd flaks-webrtc-demo
    virtualenv webrtc
    source webrtc/bin/activate
    pip install -r requirements.txt

Then run the development server with:

    python app.py

Now you should be able to visit [http://localhost:5000](http://localhost:5000) in your browser.

# Restarting the development server

Since this app runs multithreaded and has open streaming connections, you may find it difficult to reload python changes dynamically while the server is running. You will have to kill all the related python processes if you want to restart the development server.

I recommend using the following one-liner command to kill all running instances after you use Ctrl+C to stop `python app.py`:

    for pid in `ps aux |grep app\.py|grep -v grep|awk '{print $2}'`; do; kill -9 $pid; done; python app.py;

