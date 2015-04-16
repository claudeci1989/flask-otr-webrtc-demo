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
        // Connect to server
        rtc.stream = new EventSource(stream_url);
        rtc.stream_url = stream_url;
        rtc.fire('connecting');

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

    /*
     * Creates a dataChannel instance for a peer.
     */
    rtc.create_data_channel = function(username, label) {
        console.log('creating data channel for '+username)
        var pc = rtc.peerConnections[username];
        var label = label || String(username); // need a label

        if (rtc.dataChannelSupport == reliable_false) {
            return; 
        } 
        /* else reliability true! */
    
        try {
            channel = pc.createDataChannel(label, { reliable: true });
        } catch (error) {
            rtc.fire('data_stream_error', username, error)
            throw error;
        }
        return rtc.add_data_channel(username, channel);
    };

    /*
     * Adds callbacks to a dataChannel and stores the dataChannel.
     */
    rtc.add_data_channel = function(username, channel) {
        channel.onopen = function() {
            channel.binaryType = 'arraybuffer';
            rtc.connected[username] = true;
            rtc.fire('data_stream_open', username);
        };

        channel.onclose = function(event) {
            delete rtc.dataChannels[username];
            rtc.fire('data_stream_close', username, channel);
        };

        channel.onmessage = function(message) {
            //warning - under heavy data usage the following will print out a whole lot
            //console.log('data stream message ' + username + ':'+message);
            //pass along the channel username 
            rtc.fire('data_stream_data', username, message);
        };

        channel.onerror = function(error) {
            rtc.fire('data_stream_error', username, error);
        };

        rtc.dataChannels[username] = channel;
        rtc.fire('add_data_channel', username, channel)
        return channel;
    }

    /*
     * Send intial WebRTC peerConnection offer.
     */
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

    /*
     * Receive intial WebRTC peerConnection offer.
     */
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

    /* 
     * Send WebRTC peerConnection answer back to user who sent offer.
     */
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

    /*
     * The user who sent original WebRTC offer receives final answer.
     */
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

    rtc.send = function(username, message) {
        if (rtc.is_using_otr)
            rtc.send_otr_message(username, message);
        else
            rtc.dataChannels[username].send(message)
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
                    rtc.fire('set_username_error', e)
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
    .on('data_stream_open', function(username) {
        rtc.go_otr_with(username);
    })
    .on('data_stream_data', function(username, data) {
        if (rtc.is_using_otr) {
            rtc.receive_otr_message(username, data);
        } else {

        }
    })
    ;

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

    /**********
     * Crypto *
     **********/

     // I am not a doctor.
     rtc.otr_key;
     rtc.crypto_streams = [];
     rtc.crypto_receive_symmetric_keys = [];
     rtc.crypto_send_symmetric_keys = [];
     rtc.crypto_verified = [];
     rtc.request_chunk_decrypt_rand = [];
     rtc.hashed_message = [];

     rtc.init_otr = function() {
        rtc.fire('otr_init_begin');
        setTimeout(function() {
            rtc.otr_key = new DSA();
            rtc.fire('otr_init_done');
        }, 100);
     }

     rtc.go_otr_with = function(username) {
        rtc.fire('go_otr_with', username);
        var options = {
            fragment_size: 1000,
            priv: rtc.otr_key
        }
        rtc.crypto_verified[username] = false;
        var otr_stream = rtc.crypto_streams[username] = new OTR(options);
        otr_stream.ALLOW_V2 = false; /* We need V3 b/c we want the symmetric key generated for file transfers */
        otr_stream.REQUIRE_ENCRYPTION = true;

        otr_stream.on('ui', function(message, encrypted) {
            if (encrypted) {
                if(rtc.crypto_verified[username])
                    rtc.packet_inbound(username, message);
            } else {
                console.error("Attempted to send non-encrypted message, not allowing to send!");
            }
        });

        otr_stream.on('io', function(message) {
            var channel =  rtc.dataChannels[username];
            channel.send(message);
        });

        otr_stream.on('error', function(error) {
            console.log(error)
            rtc.fire('otr_stream_error', error);
        })

        otr_stream.on('status', function(state) {
            if (state === OTR.CONST.STATUS_AKE_SUCCESS) {
                rtc.fire('otr_ake_success', username);
                console.log('AKE SUCCESS');
                /* once we have AKE Success, do file transaction if we have not yet */
                if (!rtc.crypto_send_symmetric_keys[username]) {
                    /* Step 2) Send blank file to share symmetric crypto key */
                    this.sendFile('test'); /* send a non-real filename registering a pre-shared private key */
                }
            }

            if (state === OTR.CONST.STATUS_END_OTR) {
                rtc.fire('otr_disconnect', username);
                console.error('OTR disconnect :(');
            }

        });

        otr_stream.on('file', function(type, key, file) {
            if (type === 'send') {
                rtc.crypto_send_symmetric_keys[username] = key;
                console.log('send message key: '+key);
                rtc.fire('otr_send_key', username);
            }else if (type === 'receive') {
                rtc.crypto_receive_symmetric_keys[username] = key;
                rtc.fire('otr_receive_key')
                console.log('receive message key: '+key);
            } else {
                console.error('unrecognized otr file type: '+type);
            }
            
            /* these are equal, so lets compare them to verify */
            if (rtc.crypto_receive_symmetric_keys[username] && 
                rtc.crypto_send_symmetric_keys[username]){
                if (rtc.crypto_send_symmetric_keys[username] != rtc.crypto_receive_symmetric_keys[username]) {
                    rtc.fire('otr_stream_error', 'non-matching crypto keys');
                } else {
                    /* if they are equal, then we can also want to verify identity using SMP */
                    
                    /* Step 3) Socialist Millionaire Protocol 
                     * ONLY A SINGLE HOST CAN START THIS! 
                     * We have no concept of host/initiator, so choose host with lowest ID to start 
                     * Convert both usernames into an ID number.
                     */
                    var me = rtc.username.toID(); /* remove letters and -'s */
                    var other = username.toID();
                    console.log(me, other)
                    if (parseInt(me,10) > parseInt(other,10)) {
                        console.log("starting smpSecret, other user must respond for connection");
                        this.smpSecret(rtc.otr_secret);
                        rtc.fire('otr_start_smp');
                    } else {
                        console.log("waiting for other user to send SMP message out");
                        rtc.fire('otr_wait_smp');
                    }
                }
            }
        });
        
        otr_stream.on('smp', function (type, data, act) {
            switch (type) {
                case 'question':
                    console.log("Anwsering question: "+rtc.otr_secret);
                    this.smpSecret(rtc.otr_secret);
                break
                case 'trust':

                    if (!data){
                        /* TODO - handle this better? */
                        console.error("OTR NEGOATION FAILED!");
                    }
                    if (data){
                        console.log("OTR Socialist Millionaire Protocol success.");
                        rtc.fire('otr_with', username)
                        /* Step 4) do not send messages until reached here! */
                        rtc.crypto_verified[username] = true;
                    }
                break
                case 'abort':
                    /* TODO - handle this better? */
                    console.error("OTR NEGOATION FAILED!");
                default:
                    console.log("type:"+type);
                    throw new Error('Unknown type.');
            }
        });

        otr_stream.sendQueryMsg();

     }

    rtc.send_otr_message = function(username, message) {
        console.log('sending to %0: '.f(username), message);
        if (rtc.crypto_verified[username]) {
            rtc.crypto_streams[username].sendMsg(message.data);
        }
    }

    rtc.receive_otr_message = function(username, message) {
        console.log('receiving from %0: '.f(username), message);
        rtc.crypto_streams[username].receiveMsg(message.data);
    }

    /***************
     * Crypto-JS functions 
     * note: we had to redefine CryptoJS's namespace to not conflict with OTR CryptoJS code. No other changes were made.
     *      TODO - bring Rabbit's functionality into OTR's CryptoJS namespace
     * decrpyt & encrypt: file chunks QUICKLY using CryptoJS's Rabbit stream cipher
     * key: We are going to combine the symmetric key that was created during our OTR initiation with a randomly generated value.
     * That second random bit is to avoid sending the the same encrypted text multiple times. As we're sending this random value over our OTR channel
     * when we request a chunk, we should be able to assume it's safe to use.
     ****************/

    function generate_second_half_RC4_random() {
        var wordArray = RabbitCryptoJS.lib.WordArray.random(128/8); /* want this to be fast, so let's just grab 128 bits */
        return RabbitCryptoJS.enc.Base64.stringify(wordArray);
    }

    /* decrypt an inbound file peice */
    function file_decrypt(username, message) {
        if (rtc.crypto_verified[username]) {
            hash = CryptoJS.SHA256(message).toString(CryptoJS.enc.Base64); //console.log(hash);
            
            message = RabbitCryptoJS.Rabbit.decrypt(JSON.parse(message),
                rtc.crypto_receive_symmetric_keys[username] + rtc.request_chunk_decrypt_rand[username])
                .toString(CryptoJS.enc.Utf8);
            process_binary(username, base64DecToArr(message).buffer, hash); /* send back a hash as well to send back to the original host with the next request */
        }
    }
        
    /* encrypt and send out a peice of a file */
    function file_encrypt_and_send(username, message, additional_key, chunk_num) {
        /* MUST have completed OTR first */
        if (rtc.crypto_verified[username]) {
            message = _arrayBufferToBase64(message);
            message = JSON.stringify(RabbitCryptoJS.Rabbit.encrypt(message, rtc.crypto_send_symmetric_keys[username] + additional_key));
            
            if (chunk_num == 0) {
                hashed_message[username] = [];
            }
            hashed_message[username][chunk_num] = CryptoJS.SHA256(message).toString(CryptoJS.enc.Base64); //console.log(hashed_message[username][chunk_num]);
            
            /* This is the one other place we can send directly! */
            var channel = rtc.dataChannels[username];
            if (rtc.connection_ok_to_send[username]) {
                channel.send(message);
            } else {
                console.error("somehow downloading encrypted file without datachannel online?");
            }
        }
    }

    /* check if the previous hash sent back matches up */
    function check_previous_hash(username, chunk_num, hash) {
        if (chunk_num != 0) {
            //console.log("hash comparing:"+hashed_message[username][chunk_num - 1]+" "+hash);
            if (hashed_message[username][chunk_num - 1] == hash) {
                return true; /* ok */
            } else {
                return false; /*not ok */
            }
        }
        return true; /* skip for 1st chunk */
    }


    /***************
     * base 64 functionaility for crypto operations
     ****************/

    /* credit to http://stackoverflow.com/questions/9267899/arraybuffer-to-base64-encoded-string */
    function _arrayBufferToBase64( buffer ) {
        var binary = ''
        var bytes = new Uint8Array( buffer )
        var len = bytes.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode( bytes[ i ] )
        }
        return window.btoa( binary );
    }

    /* credit to https://developer.mozilla.org/en-US/docs/Web/JavaScript/Base64_encoding_and_decoding#Solution_.232_.E2.80.93_rewriting_atob%28%29_and_btoa%28%29_using_TypedArrays_and_UTF-8 */
    function base64DecToArr (sBase64, nBlocksSize) {
        var sB64Enc = sBase64.replace(/[^A-Za-z0-9\+\/]/g, ""), nInLen = sB64Enc.length;
        var nOutLen = nBlocksSize ? Math.ceil((nInLen * 3 + 1 >> 2) / nBlocksSize) * nBlocksSize : nInLen * 3 + 1 >> 2;
        var taBytes = new Uint8Array(nOutLen);

        for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
            nMod4 = nInIdx & 3;
            nUint24 |= b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << 18 - 6 * nMod4;
            if (nMod4 === 3 || nInLen - nInIdx === 1) {
                for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
                    taBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
                }
                nUint24 = 0;
            }
        }
        return taBytes;
    }
    function b64ToUint6 (nChr) {
      return nChr > 64 && nChr < 91 ?
          nChr - 65
        : nChr > 96 && nChr < 123 ?
          nChr - 71
        : nChr > 47 && nChr < 58 ?
          nChr + 4
        : nChr === 43 ?
          62
        : nChr === 47 ?
          63
        :
          0;
    }

    rtc.on('data_stream_open', function(username) {
        rtc.go_otr_with(username);
    })


    /********************
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
        $(buffer_input).val('')
        setTimeout(function() {
            $(buffer_input).val('')
        },1);
        if (input.length > 0 && input[0] === '/') {
            var command = input.match(/\/(\w+) (.*)/);
            command_lookup[command[1]](command[2]);
        }
        event.preventDefault();
        return false;
    });

    window.rtc = rtc;
    rtc.connect(document.location.origin + '/stream');
})()