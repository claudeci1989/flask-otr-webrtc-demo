;(function() {
 
    ;(function(strings, regex) {
        /* 
         * Uses single percentage sign for formatting and double percentage sign for escaping.  
         * > "you don't have to plus %0 together, you can format %0 %1%% of the time now!".format('strings', 100) 
         * "you don't have to plus strings together, you can format strings 100% of the time now!" 
         */
        strings.f = function () {
            var args = arguments;
            return this.replace(regex, function(token) {
                var index = parseInt(token.substring(1, token.length ));
                if (index >= 0 && args[index]) {
                    return args[index];
                } else if (token === '%%') {
                    return '%';
                }
                return "";  
            });
        };
        strings.bold = function() {
            return "<strong>%0</strong>".f(this);
        }
        strings.toID = function() {
            var id = 0;
            for (var x = 0; x < this.length; x++) 
                id += this.charCodeAt(x);
            return id;
        }
        /*
         * Use this to avoid xss
         * recommended escaped char's found here 
         * https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#RULE_.231_-_HTML_Escape_Before_Inserting_Untrusted_Data_into_HTML_Element_Content
         */
        strings.sanitize = function() {
            return this.replace(/[\<\>''\/]/g, function(c) {  
                var sanitize_replace = {
                    '<' : '&lt;',
                    '>' : '&gt;',
                    "'" : '&quot;',
                    "'" : '&#x27;',
                    '/' : '&#x2F;'
                }
                return sanitize_replace[c]; 
            });
        }
    })(String.prototype, /%(\d+)|%%/g);

    var browser = 'unsupported';

    /*
     * Determine the correct RTC functions and classes
     */
    if (window.mozRTCPeerConnection) {
        browser = 'firefox';
        var PeerConnection = mozRTCPeerConnection;
        var iceCandidate = mozRTCIceCandidate;
        var SessionDescription = mozRTCSessionDescription;
    } else if (window.PeerConnection || 
               window.webkitPeerConnection00 || 
               window.webkitRTCPeerConnection) {
        browser = 'chrome';
        var PeerConnection = window.PeerConnection || 
                             window.webkitPeerConnection00 || 
                             window.webkitRTCPeerConnection;
        var iceCandidate = RTCIceCandidate;
        var SessionDescription = RTCSessionDescription;
    }

    var rtc_unsupported = 0;
    var reliable_false  = 1;
    var reliable_true   = 2;

    var rtc = {
        STUN_SERVERS: { // STUN/ICE server(s) to use for PeerConnections
            iceServers: [{ url: 'stun:stun.l.google.com:19302' } ]
        },
        peerConnections: {}, // Reference to PeerConnection instance
        dataChannels: {},
        connected: {},
        streams: [],
        socket: null, // Web socket
        connected: false,
        rooms: {},
        me: null, // ID f this connection
        room: null,
        _events: {}, // Event callbacks
        is_using_otr: false
    };

    /*
     * Set callback(s) for space-deliminated event string.
     */
    rtc.on = function(event, callback) {
        var events = event.split(' ');
        for (var x = 0; x < events.length; x++) {
            if (events[x].length == 0)
                continue;
            rtc._events[events[x]] = rtc._events[events[x]] || [];
            rtc._events[events[x]].push(callback); 
        }
        return this;
    }

    /*
     * Fire callback(s) for space-deliminated event string.
     */
    rtc.fire = function(event/* ... args */) {
        var events = event.split(' ');
        var args = Array.prototype.slice.call(arguments, 1);

        for (var x = 0; x < events.length; x++) {
            var callbacks = rtc._events[events[x]] || [];
            for(var y = 0; y < callbacks.length; y++) 
                callbacks[y].apply(null, args)
        }
        return this;
    }

    /*
     * Connects to the SSE source.
     */
    rtc.connect = function(stream_url) {
        console.log('connecting to server')
        // Connect to server
        rtc.stream = new EventSource(stream_url);
        rtc.stream_url = stream_url;

        rtc.stream.onmessage = function(event) {
            var data = JSON.parse(event.data);
            if (data.event !== 'heartbeat')
                console.log(data.event + ' arrived')
            rtc.fire(data.event, data);
        }

        rtc.stream.onopen = function(event) {
            console.log(event);
            if (rtc.stream.readyState == 1) {
                rtc.connected = true;
                rtc.fire('connect');
            }
        }

        rtc.stream.onerror = function(event) {
            console.log(event);
            if (rtc.stream.readyState != 1 && rtc.connected) {
                rtc.connected = false;
                rtc.fire('disconnect');
            }
            rtc.fire('error', event);
        }
    }

    /*
     * Emit a request (event) to the server.
     */
    rtc.emit = function(event, data) {
        var type = typeof data === 'string' ? data : 'post';
        return $.ajax({
            url: '%0/%1'.f(document.location.origin, event), 
            data: data,
            dataType: 'json',
            type: type,
            headers: { "X-Stream-ID": rtc.stream_id }
        });
    }

    /*
     * Creates a new peerConnection object for a given username.
     */
    rtc.create_peer_connection = function(username) {
        var config;
        if (rtc.dataChannelSupport != rtc_unsupported) {
            config = rtc.dataChannelConfig;
        }
        console.log('create peer connection with config ', config);
        /* create a new peer connection! */
        var pc = rtc.peerConnections[username] = new PeerConnection(rtc.STUN_SERVERS, config);

        pc.onicecandidate = function(event) {
            if (event.candidate == null)  
                return 

            //TODO - does chrome want this only after onicecandidate ?? rtc.createDataChannel(username);
            //if (!rtc.dataChannels[username]) {
            //  rtc.createDataChannel(username);
            //}
            console.log(event)
            console.log(event.candidate.label) 
            rtc.emit('send_ice_candidate', {
                label: event.candidate.label,
                candidate: JSON.stringify(event.candidate),
                username: username
            });

            rtc.fire('ice_candidate', username, event.candidate);

            /* bloody hell chrome, we have to remove this handler as you send a ton of ice canidates & we only need one */
            pc.onicecandidate = null;
        };

        pc.onopen = function() {
            // TODO: Finalize this API
            rtc.fire('peer_connection_opened', username);
        };

        pc.onaddstream = function(event) {
            // TODO: Finalize this API
            rtc.fire('add_remote_stream', username,  event.stream);
        };

        pc.oniceconnectionstatechange = function(event) {
            console.log(event)
            console.log('new ICE state: %0'.f(event.target.iceConnectionState));
            if (event.target.iceConnectionState == 'connected') {
                can_close = true; /* TODO! - make per channel */
            }
        }

        //if (rtc.dataChannelSupport != rtc_unsupported) {
        /* this might need to be removed/handled differently if this is ever supported */
        pc.ondatachannel = function (evt) {
            rtc.add_data_channel(username, evt.channel); /* ? */
          //};
            
        }
        pc.onidpassertionerror = pc.onidpvalidationerror = function(e) {
            rtc.fire('pc_error', username, e)
        }
        return pc; 
    }

    rtc.create_data_channel = function(username, label) {

        var pc = rtc.peerConnections[username];
        console.log('creating data channel for '+username)
        // need a label
        var label = label || 'fileTransfer' || String(username);

        if (rtc.dataChannelSupport == reliable_false) {
            return; /* we only support reliability true options = {reliable: false};  */
        } else {
            options = {reliable: true}; /* reliability true!! */
        }
    
        try {
            console.log('createDataChannel ' + username);
            channel = pc.createDataChannel(label, options);
        } catch (error) {
            console.log('seems that DataChannel is NOT actually supported!');
            throw error;
        }

        
        return rtc.add_data_channel(username, channel);
    };

    rtc.add_data_channel = function(username, channel) {
        channel.onopen = function() {
            channel.binaryType = 'arraybuffer';
            console.log('data stream open ' + username);
            console.log(channel);
            rtc.connected[username] = true;
            rtc.fire('data_stream_open', username);
        };

        channel.onclose = function(event) {
            delete rtc.dataChannels[username];
            console.log('data stream close ' + username);
            console.log(event);
            rtc.fire('data_stream_close', username, channel);
        };

        channel.onmessage = function(message) {
            //warning - under heavy data usage the following will print out a whole lot
            //console.log('data stream message ' + username + ':'+message);
            //pass along the channel username 
            rtc.fire('data_stream_data', username, message);
        };

        channel.onerror = function(err) {
            console.log('data stream error ' + username + ': ' + err);
            rtc.fire('data_stream_error', channel, err);
        };

        // track dataChannel
        rtc.dataChannels[username] = channel;
        rtc.fire('add_data_channel', username, channel)
        return channel;
    }

    rtc.send_offer = function(username) {
        var pc = rtc.peerConnections[username];

        pc.createOffer( function(session_description) {

            //description callback? not currently supported - http://www.w3.org/TR/webrtc/#dom-peerconnection-setlocaldescription
            pc.setLocalDescription(session_description, function() { 
                rtc.fire('set_local_description', username);
            }, function(err) { 
                rtc.fire('set_local_description_error', username, errs);
            });

            rtc.emit('send_offer', {
                username: username,
                sdp: JSON.stringify(session_description)
            });
            rtc.fire('send_offer', username);
        }, function(e) {
            rtc.fire('send_offer_error', username, e);
        });
    }

    rtc.receive_offer = function(username, sdp) {
        var pc = rtc.peerConnections[username];
        var sdp_reply = new SessionDescription(JSON.parse(sdp));
        pc.setRemoteDescription(sdp_reply, function () {
            /* setRemoteDescription success */
            rtc.send_answer(username);
            rtc.fire('set_remote_description', username);
        },function(err){
            rtc.fire('set_remote_description_error', username, err);
        });
    }

    rtc.send_answer = function(username) {
        var pc = rtc.peerConnections[username];
        
        pc.createAnswer(function(session_description) {
            rtc.fire('send_offer', username)
            pc.setLocalDescription(session_description, function() { 
                rtc.emit('send_answer',{
                    username: username,
                    sdp: JSON.stringify(session_description)
                });
                rtc.fire('set_local_description', username)
            },function(err) {
                rtc.fire('set_local_description_error', username, err);
            });
        }, function(e) {
            rtc.fire('send_offer_error'. username, err);
        }); 
    }

    rtc.receive_answer = function(username, sdp_in) {
        var pc = rtc.peerConnections[username];
        var sdp = new SessionDescription(sdp_in);
        
        pc.setRemoteDescription(sdp, function() { 
            console.log('setRemoteDescription Success');
            rtc.fire('set_remote_description', username);
        },function(err) {
            console.error(err);
            rtc.fire('set_remote_description_error', username)
        }); 
    }

    rtc.set_secret = function(secret) {
        rtc.is_using_otr = !!secret;
        rtc.otr_secret = secret;
        if (rtc.is_using_otr) {
            rtc.init_otr();
        }
        rtc.emit(secret? 'otr_on' : 'otr_off')
            .done(function(){ rtc.fire('set_secret'); });
        ;
        return this;
    }

    rtc.add_streams = function() {
        for (var i = 0; i < rtc.streams.length; i++) {
            var stream = rtc.streams[i];
            for (var connection in rtc.peerConnections) {
                rtc.peerConnections[connection].addStream(stream);
            }
        }
    }

    rtc.attach_stream = function(stream, dom_id) {
        document.getElementById(dom_id).src = window.URL.createObjectURL(stream);
    }

    rtc.join_room = function(room) {
        rtc.room = room;
        if (rtc.connected)
            rtc.emit('join_room', { room: room, encryption: null })
                .done(function(json) {
                    rtc.fire('get_peers', json);
                })
        ;
    }

    rtc.set_username = function(username) {
        rtc.username = username;
        if (rtc.connected)
            rtc.emit('set_username', { username: username })
                .done(function(e) {
                    rtc.fire('set_username_success');
                })
                .fail(function(e) {
                    rtc.fire('set_username_error', data)
                })
            ;
    }

    /* WebRTC Callbacks */
    rtc.on('connect', function() {
        console.log('connected');
        rtc.connected = true;
        if (rtc.username)
            rtc.set_username(rtc.username);
    })

    .on('hello', function(data) {
        rtc.stream_id = data.stream_id
    })

    .on('disconnect', function() {
        console.log('disconnected');
        rtc.connected = false;
    }) 

    .on('get_peers', function(data) {
        console.log('get_peers');
        console.log(data);

        /* we already sanitize everything later, but rather be safe than sorry */
        for (var i = 0, len = data.usernames.length; i < len; i++) {
            data.usernames[i] = data.usernames[i].sanitize();
            rtc.create_peer_connection(data.usernames[i]);
            rtc.create_data_channel(data.usernames[i]);
            rtc.send_offer(data.usernames[i]);
        }
        rtc.rooms[data.room] = {
            connections: data.connections,
            usernames: data.usernames,
            first_connect: true
        }
       
        rtc.fire('got_peers', data);

        rtc.rooms[data.room].first_connect = false;
    })
    
    .on('set_username_success', function(data) {
        if (rtc.room)
            rtc.join_room(rtc.room);
    })

    .on('user_join', function(data) {
        //add username
        console.log(data.username+' has joined the room.', data);
       /* rtc.usernames[data.username] = sanitize(data.username); */
        var room = rtc.rooms[data.room];
        //add socket and create streams
        room.usernames.push(data.username);
        rtc.create_peer_connection(data.username);
        //rtc.create_data_channel(data.username);
        //rtc.send_offer(data.username);
        var pc = rtc.create_peer_connection(data.username);
        for (var i = 0; i < rtc.streams.length; i++) {
            var stream = rtc.streams[i];
            pc.addStream(stream);
       }
    })

    .on('remove_peer_connected', function(data) {
        console.log('remove_peer_connected', data)
        rtc.connected[data.username] = false;
        rtc.fire('disconnect stream', data.username, rtc.usernames[data.username]);
        delete rtc.dataChannels[data.username];
        delete rtc.usernames[data.username];
        delete rtc.peerConnections[data.username];
    })

    .on('receive_ice_candidate', function(data) {
        console.log('receive_ice_candidate', data);
        var candidate = new iceCandidate(JSON.parse(data.candidate));
        rtc.peerConnections[data.username].addIceCandidate(candidate);
        //rtc.fire('receive_ice_candidate', candidate);
    })

    .on('receive_offer', function(data) {
        console.log('receive_offer', data);
        rtc.receive_offer(data.username, data.sdp);
        //rtc.fire('receive offer', data);    
    })

    .on('receive_answer', function(data) {
        console.log('receive_answer');
        rtc.receive_answer(data.username, JSON.parse(data.sdp));
        //rtc.fire('receive answer', data);
    })
    ;

    window.addEventListener('beforeunload', function(event) {
    });

    rtc.dataChannelConfig = {optional: [ {'DtlsSrtpKeyAgreement': true} ] };

    // Determine Data Channel support
    try {
        /* first try reliable */
        var pc = new PeerConnection(rtc.STUN_SERVERS, rtc.dataChannelConfig);
        channel = pc.createDataChannel('supportCheck', { reliable: true }); 
        channel.close();
        console.log('data channel reliability set to true!');
        rtc.dataChannelSupport = reliable_true;
    } catch(e) {    
        try {
            /* then unreliable */
            var pc = new PeerConnection(rtc.STUN_SERVERS, rtc.dataChannelConfig);
            channel = pc.createDataChannel('supportCheck', { reliable: false }); 
            channel.close();
            console.log('data channel reliability set to false!');
            rtc.dataChannelSupport = reliable_false;
        } catch(e) {
            /* then fail :( */
            rtc.dataChannelSupport = rtc_unsupported;
        }
    }



    /*******************
     * DOM interactions *
     ********************/

    var status_div = document.getElementById('status');
    var messages_div = document.getElementById('messages');
    var login_div = document.getElementById('login');
    var login_buttom = document.getElementById('login_button');
    var username_input = document.getElementById('username');
    var mask_div = document.getElementById('mask');
    var buffer_input = document.getElementById('buffer_input');

    var print = function(message) {
        var message_div = document.createElement('div');
        message_div.setAttribute('class','message');
        message_div.innerHTML = message;
        messages_div.appendChild(message_div);
        messages.scrollTop = messages_div.scrollHeight;
    }

    rtc.on('connecting', function() {
        status_div.innerHTML = 'Connecting...';
        print('[*] Connecting to %0...'.f(rtc.socket_url));
    })

    .on ('connect', function() {
        status_div.innerHTML = 'Connected';
        print('[*] Connected.');
        if (!rtc.username) {
            print('[-] Please set your username with the /nick command.');
            buffer_input.value = '/nick ';
        }
    })

    .on ('set_username_success', function() {
        print('[+] Username successfully set.');
        if (!rtc.room) {
            print('[-] Type the name of a room to join with the /join command.');
            buffer_input.value = '/join ';
        }
    })

    .on ('set_username_error', function(data) {
        print('[-] Failed to set username: %0.'.f(data.error));
        buffer_input.value = '/nick ' + data.username;
    })

    .on ('got_peers', function(data) {
        var room = rtc.rooms[data.room];
        
        if (room.first_connect)
            print('[*] Entered ' + data.room);
        
        if (room.usernames.length == 0) 
            return print('[*] You are the only user in this room.');
        
        var users = '';
        for (var x = 0; x < room.usernames.length; x++) {
            console.log(room.usernames)
            users += room.usernames[x] + ' ';
        }
        print('[*] Users in room: ' + users);

    })

    .on ('user_join', function(data) {
        print('[*] User %0 has joined.'.f(data.username.bold()))
    })

    // Send RTC offer
    .on('send_offer', function(username) {
        print('[*] Sending RTC offer to %0...'.f(username.bold()))
    })
    .on('send_offer_error', function(username) {
        print('[-] Failed to send RTC offer to %0.'.f(username.bold()))
    })

    // Receive RTC offer
    .on ('receive_offer receive_answer', function(data) {
        print('[+] Received RTC offer from %0.'.f(data.username.bold()))
    })


    // Set Local Description for RTC
    .on('set_local_description', function(username) {
        print('[+] Set local description for %0.'.f(username.bold()))
    })
    .on('set_local_description_error', function(username, error) {
        print('[-] Failed to set local description for %0!'.f(username.bold()))
    }) 

    // set Remote Description for RTC
    .on('set_remote_description', function(username) {
        print('[+] Set remote description for %0.'.f(username.bold()))
    })
    .on('set_remote_description_error', function(username, error) {
        print('[-] Failed to set remote description for %0!'.f(username.bold()))
    }) 

    .on('ice_candidate', function(username) {
        print('[+] Received ICE Candidate for %0'.f(username.bold()))
    })

    /* PeerConnection Events */
    .on('peer_connection_opened', function(username) {
        print('[+] Peer connection opened for %0'.f(username.bold()));
    })
    .on('add_remote_stream', function(username) {
        print('[+] Remote stream added for %0'.f(username.bold()))
    })
    .on('pc_error', function(username, e) {
        print('[-] PeerConnection error when coonecting with %0'.f(username.bold()));
    })

    /* Data Stream Events */
    .on('add_data_channel', function(username) {
        print('[*] DataChannel starting for %0...'.f(username.bold()));
    })
    .on('data_stream_open', function(username) {
        print('[+] DataChannel opened for %0.'.f(username.bold()));
    })
    .on('data_stream_close', function(username, channel) {
        print('[-] DataChannel closed for %0.'.f(username.bold()));
    })


    .on('disconnect', function() {
        status_div.innerHTML = 'Disconnected';
    })
    ;

    login_button.addEventListener('click', function() {
        var username = username_input.value;
        rtc.set_username(username);
        mask_div.setAttribute('style', '');
        login_div.setAttribute('style', '');

    });

    var command_lookup = {
        connect: function(server_and_nick) {
            var split = server_and_nick.split(' ');
            var server = split[0]
            var nick = split[1] 
            if (!/^(http:\/\/|https:\/\/)/.test(server))
                server = 'http://' + server;
            rtc.connect(server + '/stream');
        },
        nick: function(username) {
            rtc.set_username(username);
        },
        join: function(room) {
            console.log('joing ' + room)
            rtc.join_room(room);
        }
    }

    buffer_input.addEventListener('keydown', function(event) {
        if (event.keyCode != 13) 
            return;
        
        var input = buffer_input.value;
        if (input.length > 0 && input[0] === '/') {
            var command = input.match(/\/(\w+) (.*)/);
            command_lookup[command[1]](command[2]);
        }
        event.preventDefault();
        setTimeout(function() {
            buffer_input.value = '';
        },1);
        return false;
    });

    window.rtc = rtc;
    rtc.connect(document.location.origin + '/stream')
})()