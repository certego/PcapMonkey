##! Detects hosts involved with Bitcoin mining (or other cryptocurrencies
##! that share the same mining protocol like Litecoin, PPCoin, etc.).
##!
##! Bitcoin mining protocols typically involve the use of
##! `JSON-RPC <http://www.jsonrpc.org/specification>`_ requests to mining
##! pool servers to request work.  JSON-RPC doesn't require the use of a
##! particular transport protocol, but the original
##! `getwork <https://en.bitcoin.it/wiki/Getwork>`_ mining protocol uses
##! HTTP as a transport.  A superceding mining protocol called
##! `getblocktemplate <https://en.bitcoin.it/wiki/Getblocktemplate>`_
##! is designed to be more extensible than "getwork" by not having to rely
##! on HTTP headers to implement extensions.  Another protocol called
##! `Stratum <http://mining.bitcoin.cz/stratum-mining/>`_ is an overlay
##! network on top of the Bitcoin P2P protocol, includes methods related
##! to mining, and is not tied to a particular transport.
##!
##! This script makes use of generic JSON-RPC signatures for TCP and HTTP
##! (the most common transports used by mining software) and then inspects
##! the method values of JSON-RPC requests in order to match connections that
##! that potentially relate to Bitcoin mining.
##!
##! Note that the Bitcoin P2P protocol is not currently detected.

@load base/frameworks/notice
@load base/frameworks/signatures/main
@load base/utils/addrs
@load base/utils/directions-and-hosts

@load-sigs ./json-rpc.sig

redef Signatures::ignored_ids += /^json-rpc-/;

module Bitcoin;

export {

	redef enum Notice::Type += {
		## Raised when a host doing Bitcoin mining is found.
		Miner,

		## Raised when a host is serving work to Bitcoin miners.
		Mining_Pool_Server,

		## Raised when a host looks like it is involved in Bitcoin mining
		## using the Stratum protocol, but the JSON-RPC request method
		## was not one of the ones in :zeek:see:`Bitcoin::stratum_client_methods`
		## or :zeek:see:`Bitcoin::stratum_server_methods`, though it did start
		## with "mining.".
		Possible_Mining,
	};

	## Names of JSON-RPC request methods for Stratum mining clients.
	const stratum_client_methods: set[string] = {
		"mining.authorize",
		"mining.get_transactions",
		"mining.subscribe",
		"mining.submit",
	} &redef;

	## Names of JSON-RPC request methods for Stratum mining servers.
	const stratum_server_methods: set[string] = {
		"mining.notify",
		"mining.set_difficulty",
	} &redef;

	## Names of JSON-RPC request methods for mining clients using
	## the getblocktemplate protocol.
	const gbt_methods: set[string] = {
		"getblocktemplate",
		"submitblock",
	} &redef;

	## Names of JSON-RPC request methods used by MinerGate application.
	const minergate_methods: set[string] = {
		"getjob",
		"job",
		"submit",
		"login",
		"eth_getWork",
		"eth_submitWork",
	} &redef;

	## Other names of JSON-RPC request methods that may be used by
	## mining clients/protocols.
	const other_methods: set[string] = {
	} &redef;

	## Type of Bitcoin mining host which, on discovery, should raise a notice.
	const notice_miner_hosts = LOCAL_HOSTS &redef;

	## Type of Bitcoin pool server host which, on discovery, should raise a
	## notice.
	const notice_pool_hosts = LOCAL_HOSTS &redef;

	## Extracts the value of the "method" key from a JSON-RPC request object.
	##
	## json_obj: A JSON-RPC request object or objects.
	##
	## Returns: set of values for the "method" keys in the JSON objects or an
	##          empty set if parsing the object failed.
	global extract_json_rpc_request_methods: function(json_obj: string): set[string];
}

function extract_json_rpc_request_methods(json_obj: string): set[string]
	{
	# grab '"method": "value"' string
	local pat = /\"method\"([[:space:]]*):([[:space:]]*)\"[^"]*\"/; # "
	local method_kv = find_all(json_obj, pat);
	local method_parts: string_vec;
	local rval: set[string] = set();

	# split by double quotes to get the value string
	for ( p in method_kv )
		{
		method_parts = split_string(p, /\"/); # "

		if ( |method_parts| == 5 )
			add rval[method_parts[3]];
		}

	return rval;
	}

type Endpoint: record {
	a: addr;
	p: port;
};

function do_notice(c: connection, miner_orig: bool, proto: string, data: string)
	{
	local miner: Endpoint;
	local server: Endpoint;

	if ( miner_orig )
		{
		miner = [$a=c$id$orig_h, $p=c$id$orig_p];
		server = [$a=c$id$resp_h, $p=c$id$resp_p];
		}
	else
		{
		miner = [$a=c$id$resp_h, $p=c$id$resp_p];
		server = [$a=c$id$orig_h, $p=c$id$orig_p];
		}

	if ( addr_matches_host(miner$a, notice_miner_hosts) )
		NOTICE([$note=Bitcoin::Miner,
		        $msg=fmt("Bitcoin miner at %s, using %s protocol", miner$a,
		                 proto),
		        $sub=data,
		        $conn=c,
		        $identifier=fmt("%s", miner$a)]);

	if ( addr_matches_host(server$a, notice_pool_hosts) )
		NOTICE([$note=Bitcoin::Mining_Pool_Server,
		        $msg=fmt("Bitcoin pool server at %s:%s, using %s protocol",
		                 addr_to_uri(server$a), server$p, proto),
		        $sub=data,
		        $conn=c,
		        $identifier=fmt("%s%s", server$a, server$p)]);
	}

event signature_match(state: signature_state, msg: string, data: string)
	&priority=-5
	{
	if ( /json-rpc-request/ !in state$sig_id ) return;

	local methods: set[string] = extract_json_rpc_request_methods(data);

	if ( |methods| == 0 )
		{
		Reporter::warning(fmt("JSON-RPC request method extraction failed: '%s'",
		                      data));
		return;
		}

	for ( method in methods )
		{
		if ( /getwork/ in method )
			do_notice(state$conn, T, "getwork", data);

		else if ( method in gbt_methods )
			do_notice(state$conn, T, "getblocktemplate", data);

		else if ( method in stratum_client_methods )
			do_notice(state$conn, /reverse/ !in state$sig_id, "Stratum", data);

		else if ( method in stratum_server_methods )
			do_notice(state$conn, /reverse/ in state$sig_id, "Stratum", data);

		else if ( /^mining\./ in method )
			NOTICE([$note=Bitcoin::Possible_Mining,
			         $msg=fmt("Possible Bitcoin mining over Stratum"),
			         $sub=data,
			         $conn=state$conn,
			         $identifier=fmt("%s%s", state$conn$id$orig_h,
			                         state$conn$id$resp_h)]);

		else if ( method in minergate_methods )
			do_notice(state$conn, T, "MinerGate", data);

		else if ( method in other_methods )
			do_notice(state$conn, T, "unknown", data);
		}
	}
