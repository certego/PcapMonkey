signature json-rpc-request-tcp {
    ip-proto == tcp
    payload /^([[:space:]]*)\{([[:space:]]*)(.*)\"method\"([[:space:]]*):([[:space:]]*)\"(.*)\"/
    tcp-state originator
    event "json-rpc-request-tcp"
}

signature json-rpc-response-tcp {
    ip-proto == tcp
    requires-reverse-signature json-rpc-request-tcp
    payload /^([[:space:]]*)\{([[:space:]]*)\"(jsonrpc|result|error|id)\"([[:space:]]*):/
    tcp-state responder
    event "json-rpc-response-tcp"
}

signature json-rpc-request-tcp-reverse {
    ip-proto == tcp
    payload /^([[:space:]]*)\{([[:space:]]*)(.*)\"method\"([[:space:]]*):([[:space:]]*)\"(.*)\"/
    tcp-state responder
    event "json-rpc-request-tcp-reverse"
}

signature json-rpc-response-tcp-reverse {
    ip-proto == tcp
    requires-reverse-signature json-rpc-request-tcp-reverse
    payload /^([[:space:]]*)\{([[:space:]]*)\"(jsonrpc|result|error|id)\"([[:space:]]*):/
    tcp-state originator
    event "json-rpc-response-tcp-reverse"
}

signature json-rpc-request-http {
    ip-proto == tcp
    http-request-body /^([[:space:]]*)\{([[:space:]]*)(.*)\"method\"([[:space:]]*):([[:space:]]*)\"(.*)\"/
    event "json-rpc-request-http"
}

signature json-rpc-response-http {
    ip-proto == tcp
    requires-reverse-signature json-rpc-request-http
    http-reply-body /^([[:space:]]*)\{([[:space:]]*)\"(jsonrpc|result|error|id)\"([[:space:]]*):/
    event "json-rpc-response-http"
}
