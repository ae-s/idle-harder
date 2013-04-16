-module(ircd_conn).
-behaviour(gen_server).
-author("Duncan Smith <Duncan/@xrtc.net>").

% fast stop
-export([start/2]).

% for internal use
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
-export([terminate/2, code_change/3]).

-export([send/2]).
-export([recv/2]).

-export([upgrade/0, upgrade/1]).

-compile(export_all).


% start-stop

start(Host, Port) -> gen_server:start_link({local, ?MODULE}, ?MODULE, [{host, Host}, {port, Port}], []).

handle_call(_, _, _) ->
    ok.
terminate(shutdown, State) ->
    gen_tcp:shutdown(dict:fetch(socket, State), read_write),
    ok;
terminate(tcp_closed, _State) ->
    ok.

code_change(_Old, State, _Extra) ->
    {ok, State}.

init(Opts) ->
    Dict = dict:from_list(Opts),
    Host = dict:fetch(host, Dict),
    Port = dict:fetch(port, Dict),
    io:format("connecting to ~p : ~p ( ~w )~n", [Host, Port, Opts]),
    {ok, Sock} = gen_tcp:connect(Host, Port, [{packet, line}], 2000),
    State = dict:store(socket, Sock, Dict),
    send(self(), "NICK idle-harder"),
    send(self(), "USER bar 0 * :test erlang"),
    % wait to connect
    {ok, State, 3000}.

upgrade() ->
    ircd_conn:upgrade(ok).
upgrade(ok) ->
    ok.


% ipc

% socket error conditions
handle_info(timeout, _State) ->
    {stop, ircd_timeout, timeout_kill};
handle_info({tcp_error, _Socket, Reason}, _State) ->
    {stop, {tcp_error, Reason}, tcp_kill};
handle_info({tcp_closed, _Socket}, _State) ->
    {stop, tcp_closed, tcp_kill};

% incoming irc messages
handle_info({tcp, _Socket, Data}, State) ->
    lists:map(fun(Msg) -> recv(self(), Msg) end, split_messages(Data)),
    {noreply, State}.

split_messages(Msg) when is_binary(Msg) -> split_messages(binary_to_list(Msg), []);
split_messages(Msg) when is_list(Msg) -> split_messages(Msg, []).
split_messages(Msg, Sofar) when is_list(Msg) ->
    End = string:str(Msg, "\r\n"),
    case End of
	0 -> Sofar;
	_ -> split_messages(string:substr(Msg, End+2), [string:substr(Msg, 1, End-1) | Sofar])
    end.

% from external processes
send(Srv, Msg) -> gen_server:cast(Srv, {send, Msg}).

% internal routing, throw it onto the queue
recv(Srv, Msg) -> io:format("Got message: ~p~n", [Msg]),
		  gen_server:cast(Srv, {recv, Msg}).

handle_cast({send, Msg}, State) ->
    Sock = dict:fetch(socket, State),
    _R1 = gen_tcp:send(Sock, Msg),
    _R2 = gen_tcp:send(Sock, "\r\n"),
    io:format("Sent message ~p to ~p~n", [Msg, Sock]),
    {noreply, State};
handle_cast({recv, "PING" ++ Token}, State) ->
    io:format("Ponging ~p~n", [Token]),
    send(self(), "PONG" ++ Token),
    {noreply, State};
handle_cast({recv, ":sodium.u " ++ "PONG " ++ Token}, State) ->
    io:format("Got pong for ~p~n", [Token]),
    {noreply, State};
handle_cast({recv, Msg}, State) ->
    MP = parse_line(Msg),
    io:format("Unhandled message: ~p~n", [MP]),
    {noreply, State}.


% msg-parse

% "^\(?::\([^ ]+\) \)?\([-_a-zA-Z0-9]+\) \([^ 
% ]*\) ?\(\(?>[^:][^ 
% ]* \)*\)\(?: :\(.*\)\)?$"

% basic format:
%   :from cmd to args :text
% here's what's optional:
%   [:from] cmd to [args] [:text]
%
% from: :(.*?) 

% parse incoming irc messages into some kind of match-able packet
parse_line(Msg) ->
    % TODO: consider compiling and caching this, as it may become
    % expensive to recompile for every inbound line.
    {match, [From, Cmd, To, Args, Text]} = re:run(Msg, "^(:(?<from>[^ ]*) |)(?<cmd>[A-Za-z]+|[0-9]+)(?<args>( [^:][^ ]*)+?)?( :(?<tail>.*))?$", [no_auto_capture, {capture, [from, cmd, args, text], list} ]),
    parse_cmd(Cmd, From, Args).


% Accept a parsed message from parse_line/1, and transform into a
% tuple of appropriate size and contents.  Tuples are not all the same
% size.
parse_cmd("PING", From, Args) ->
    {From, self, ping, Args};
parse_cmd("PONG", From, Args) ->
    {From, self, pong, Args};
% rfc 2812, sec 3.1.2
parse_cmd("NICK", From, Args) ->
    % TODO parse this properly
    {From, unknown, nick, Args};
% rfc 2812, sec 3.1.5 - user mode
% rfc 2812, sec 3.2.3 - channel mode
parse_cmd("MODE", From, Args) ->
    [Target, Delta | ArgTail] = string:tokens(Args, " "),
    TargetType = target_type(Target),
    case TargetType of
	channel -> % channel mode change
	    {From, Target, mode_change, parse_chan_modes(Delta, ArgTail)};
	user -> % user mode has changed, not associated with a channel (MOST LIKELY the current user)
	    {From, Target, mode_change, parse_user_modes(Delta, ArgTail)}
    end;
parse_cmd("PRIVMSG", From, Args) ->
    Routing = string:substr(Args, 1, string:str(Args, " :")),
    [To, [$: | Message]] = string:tokens(Routing, " "),
    {From, parse_multi_targets(To), privmsg, Message};

% RPL_WELCOME
% TODO
parse_cmd("001", From, Args) ->
    {From, unknown, rpl_welcome, Args};

% RPL_YOURHOST
% TODO
parse_cmd("002", From, Args) ->
    {From, unknown, rpl_yourhost, Args};

% RPL_CREATED
% TODO
parse_cmd("003", From, Args) ->
    {From, unknown, rpl_created, Args};

% RPL_MYINFO
% TODO
parse_cmd("004", From, Args) ->
    {From, unknown, rpl_myinfo, Args};

% RPL_ISUPPORT
parse_cmd("005", From, Args) ->
    [To | Items] = string:tokens(Args, " "),
    {From, To, rpl_isupport, parse_005(Items)};

% RPL_USERHOST
% TODO
parse_cmd("302", From, Args) ->
    {From, unknown, rpl_userhost, Args};

% RPL_ISON
% TODO
parse_cmd("303", From, Args) ->
    {From, unknown, rpl_ison, Args};

% RPL_AWAY
parse_cmd("301", From, Args) ->
    {From, unknown, rpl_away, Args};

parse_cmd(Type, From, Args) ->
    {From, unknown, Type, Args}.




parse_005(["PREFIX=" ++ Arg | Items]) ->
    % user prefixes, in order:
    % (cmodes)prefixes
    [$( | Modes] = string:sub_word(Arg, 1, $) ),
    Prefixes = string:sub_word(Arg, 2, $) ),
    learn_user_flags(Modes, Prefixes),
    parse_005(Items);
parse_005(["CHANTYPES=" ++ Arg | Items]) ->
    % acceptable channel prefixes, list of characters
    put(chantypes, Arg),
    parse_005(Items);
parse_005(["CHANMODES=" ++ Arg | Items]) ->
    % acceptable channel modes, four lists of mode characters
    [NickModes, SettingAlways, SettingAdd, SettingPlain] = string:tokens(Arg, ","),
    % first tuple: a mode setting that takes an argument always, which
    % is intended to be a nickname.
    lists:foreach(fun	($a) -> put({cmode, $a}, {[arg_on, arg_off], protect});
			($b) -> put({cmode, $b}, {[arg_on, arg_off], ban});
			($d) -> put({cmode, $d}, {[arg_on, arg_off], deny_name});
			($e) -> put({cmode, $e}, {[arg_on, arg_off], ban_exception});
			($I) -> put({cmode, $I}, {[arg_on, arg_off], invite});
			(MM) -> put({cmode, MM}, {[arg_on, arg_off], {unknown, MM}})
		  end,
		  NickModes),
    % second tuple: a mode setting that takes an argument always, but
    % is not a nickname
    lists:foreach(fun ($k) -> put({cmode, $k}, {[arg_on, arg_off], key});
		      (MM) -> put({cmode, MM}, {[arg_on, arg_off], {unknown, MM}})
		  end,
		  SettingAlways),
    % third tuple: a mode setting that takes an argument on +set but
    % not on -remove
    lists:foreach(fun ($f) -> put({cmode, $f}, {[arg_on], flood_limit});
		      ($j) -> put({cmode, $j}, {[arg_on], join_throttle});
		      ($l) -> put({cmode, $l}, {[arg_on], limit});
		      ($L) -> put({cmode, $L}, {[arg_on], limit_link});
		      ($R) -> put({cmode, $R}, {[arg_on], reop_hint});
		      (MM) -> put({cmode, MM}, {[arg_on], {unknown, MM}})
		  end,
		  SettingAdd),
    % fourth tuple: a mode setting that never takes an argument
    lists:foreach(fun ($a) -> put({cmode, $a}, {[], anonymous}); % conflicts with hybrid's ops-are-anonymous mode. choose rfc2811.
		      ($c) -> put({cmode, $c}, {[], block_colors});
		      ($C) -> put({cmode, $C}, {[], block_ctcp});
		      ($G) -> put({cmode, $G}, {[], censor});
		      ($H) -> put({cmode, $H}, {[], no_hiding});
		      ($i) -> put({cmode, $i}, {[], invite_only});
		      ($K) -> put({cmode, $K}, {[], no_knock});
		      ($L) -> put({cmode, $L}, {[], listed});
		      ($m) -> put({cmode, $m}, {[], moderated});
		      ($M) -> put({cmode, $M}, {[], register_to_talk});
		      ($n) -> put({cmode, $n}, {[], block_external});
		      ($O) -> put({cmode, $O}, {[], opers_only});
		      ($p) -> put({cmode, $p}, {[], private});
		      ($P) -> put({cmode, $P}, {[], permanent}); % inspircd
		      ($q) -> put({cmode, $q}, {[], quiet});
		      ($Q) -> put({cmode, $Q}, {[], no_kick});
		      % conflict between rfc2811 and bahamut.  choose rfc2811.
		      ($r) -> put({cmode, $r}, {[], reop});
		      ($R) -> put({cmode, $R}, {[], register_only});
		      ($s) -> put({cmode, $s}, {[], secret});
		      ($S) -> put({cmode, $S}, {[], strip_colors});
		      ($t) -> put({cmode, $t}, {[], topic_lock});
		      % conflict between quakenet and unreal.  choose unreal.
		      ($u) -> put({cmode, $u}, {[], auditorium});
		      ($V) -> put({cmode, $V}, {[], no_invites});
		      ($z) -> put({cmode, $z}, {[], ssl_only});
		      (MM) -> put({cmode, MM}, {[], {unknown, MM}})
		  end,
		  SettingPlain),
    parse_005(Items);
parse_005(["MODES=" ++ Arg | Items]) ->
    % maximum number of mode changes per MODE command
    {Count, _} = string:to_integer(Arg),
    put(mode_max, Count),
    parse_005(Items);
parse_005(["MAXCHANNELS=" ++ _Arg | Items]) ->
    % number of channels you can join, total
    % TODO
    parse_005(Items);
parse_005(["CHANLIMIT=" ++ _Arg | Items]) ->
    % number of channels you can join, by prefix
    % e.g.: #&:10,!+:8
    % TODO
    parse_005(Items);
parse_005(["NICKLEN=" ++ Arg | Items]) ->
    % maxiumum nickname length
    {Count, _} = string:to_integer(Arg),
    put(nicklen, Count),
    parse_005(Items);
parse_005(["MAXBANS=" ++ Arg | Items]) ->
    % quantity of bans per channel
    {Count, _} = string:to_integer(Arg),
    put(ban_max, Count),
    parse_005(Items);
parse_005(["MAXLIST=" ++ _Arg | Items]) ->
    % max number of items in list, by mode
    % e.g.: be:30,I:5
    % TODO
    parse_005(Items);
parse_005(["NETWORK=" ++ Arg | Items]) ->
    % name of current network
    put(network, Arg),
    parse_005(Items);
parse_005(["EXCEPTS" ++ _Mode | Items]) ->
    % ban exceptions supported
    put(ban_exception, true),
    parse_005(Items);
parse_005(["INVEX" ++ _Mode | Items]) ->
    % permanent invites (cmode +I) supported
    put(invite, true),
    parse_005(Items);
parse_005(["WALLCHOPS" ++ _ | Items]) ->
    % wallchops supported
    put(wallchops, true),
    parse_005(Items);
parse_005(["WALLVOICES" ++ _ | Items]) ->
    % wallvoices supported
    put(wallvoices, true),
    parse_005(Items);
parse_005(["STATUSMSG=" ++ _Arg | Items]) ->
    % supports messaging users with status, generalization of wallchops/wallvoices
    % apparently only ratbox
    % TODO
    parse_005(Items);
parse_005(["CASEMAPPING=" ++ Arg | Items]) ->
    if ("ascii" == Arg) ->
	    put(casemap, ascii);
       ("rfc1459" == Arg) ->
	    put(casemap, rfc1459);
       ("strict-rfc1459" == Arg) ->
	    put(casemap, rfc1459_strict);
       true -> ok
    end,
    parse_005(Items);
parse_005(["ELIST=" ++ _Arg | Items]) ->
    % LIST with filter
    % TODO
    parse_005(Items);
parse_005(["TOPICLEN=" ++ Arg | Items]) ->
    % channel topic length
    {Count, _} = string:to_integer(Arg),
    put(topic_max, Count),
    parse_005(Items);
parse_005(["KICKLEN=" ++ Arg | Items]) ->
    % kick message length
    {Count, _} = string:to_integer(Arg),
    put(kick_max, Count),
    parse_005(Items);
parse_005(["CHANNELLEN=" ++ Arg | Items]) ->
    % channel name length
    {Count, _} = string:to_integer(Arg),
    put(channellen, Count),
    parse_005(Items);
parse_005(["CHIDLEN=" ++ _Arg | Items]) ->
    % channel timestamp id length
    % TODO
    parse_005(Items);
parse_005(["IDCHAN=" ++ _Arg | Items]) ->
    % like CHIDLEN but broken out by channel prefix
    % TODO
    parse_005(Items);
parse_005(["STD=" ++ Arg | Items]) ->
    % standards, hahhahahaha
    parse_005(Items);
parse_005(["SILENCE=" ++ Arg | Items]) ->
    % number of entries allowed in a user's SILENCE list
    {Count, _} = string:to_integer(Arg),
    put(silence_max, Count),
    parse_005(Items);
parse_005(["RFC2812" | Items]) ->
    % server claims to comply with rfc2812
    put(rfc2812, true),
    parse_005(Items);
parse_005(["PENALTY" | Items]) ->
    % you're not allowed to talk much on this network
    % who cares
    parse_005(Items);
parse_005(["FNC" | Items]) ->
    % server may change your nick for you
    % not reliable indicator anyway
    parse_005(Items);
parse_005(["SAFELIST" | Items]) ->
    % if you issue a LIST the server won't fuck your sendq
    % nice on them
    parse_005(Items);
parse_005(["AWAYLEN=" ++ Arg | Items]) ->
    % you're afk.  we get it.
    {Count, _} = string:to_integer(Arg),
    put(awaylen, Count),
    parse_005(Items);
parse_005(["NOQUIT" | Items]) ->
    % abbreviated netsplit notification
    put(netsplit_noquit, true),
    parse_005(Items);
parse_005(["USERIP" | Items]) ->
    % oper command /userip exists
    put(userip, true),
    parse_005(Items);
parse_005(["CPRIVMSG" | Items]) ->
    % can /msg everyone in a channel? neato.
    put(cprivmsg, true),
    parse_005(Items);
parse_005(["CNOTICE" | Items]) ->
    % can /notice everyone in a channel? neato.
    put(cnotice, true),
    parse_005(Items);
parse_005([[$: | _] | _Items]) ->
    % end of structred text
    ok;
parse_005([_ | Items]) ->
    % unknown token
    parse_005(Items);
parse_005([]) ->
    % no structured text encountered
    ok.



% Parse a string of channel modes like "+mco-v"
% with arguments like ["now-op", "am-muted"].
%
% Uses info from 005 RPL_ISUPPORT as stored in the process dictionary.

parse_chan_modes(Modes, Args) -> parse_chan_modes(nil, Modes, Args, []).

parse_chan_modes(_, [], _, Result) ->
    Result;
parse_chan_modes(_, [$+ | Modes], Args, Rest) ->
    parse_chan_modes(plus, Modes, Args, Rest);
parse_chan_modes(_, [$- | Modes], Args, Rest) ->
    parse_chan_modes(minus, Modes, Args, Rest);

parse_chan_modes(plus, [M | Modes], Args, Rest) ->
    {Tags, Action} = get({cmode, M}),
    case proplists:get_bool(arg_on, Tags) of
	true ->
	    [Arg | ArgT] = Args,
	    parse_chan_modes(plus, Modes, ArgT, [{Action, enable, Arg} | Rest]);
	false ->
	    parse_chan_modes(plus, Modes, Args, [{Action, enable} | Rest])
    end;
% mrmph, copy+paste
parse_chan_modes(minus, [M | Modes], Args, Rest) ->
    {Tags, Action} = get({cmode, M}),
    case proplists:get_bool(arg_off, Tags) of
	true ->
	    [Arg | ArgT] = Args,
	    parse_chan_modes(minus, Modes, ArgT, [{Action, disable, Arg} | Rest]);
	false ->
	    parse_chan_modes(minus, Modes, Args, [{Action, disable} | Rest])
    end.

parse_user_modes(Delta, _Args) ->
    Delta.

% Parse user-related channel-modes from the 005 message's map, given
% the set of modifiers and the concomitant modes (e.g., "ov", "@+").
learn_user_flags(Modes, Prefixes) ->
    learn_user_flags(Modes, Prefixes, 0).

learn_user_flags([Mode | ModeT], [Char | PrefixT], Priority) ->
    Name = case Mode of
	       $v -> voice;
	       $h -> halfop;
	       $o -> operator;
	       $a -> protected;
	       $q -> owner;
	       $Y -> ircop;
	       _ -> unknown
	   end,
    put({user_prefix, Char}, {cmode, Mode}),
    put({cmode, Mode}, {[arg_on, arg_off, {pri, Priority}, {char, Char}], Name}),

    learn_user_flags(ModeT, PrefixT, Priority + 1);

learn_user_flags([], [], _) ->
    ok.




% What type of thing is this?  In the context of a "channel or user
% name".
target_type([H | _]) ->
    case lists:any( fun(Elem) -> H == Elem end,
		    get(chantypes)) of
	true -> channel;
	false -> user
    end.

% Split a target specification into a list of one-or-more targets.
parse_multi_targets(Targs) ->
    TargSplit = string:tokens(Targs, ",").


% Send an incoming message (received from IRC) to the right place.
%
% XXX TODO
route_incoming({_From, _To, _Type, _Args}) ->
    io:format("Got stuff ~p~n", [{_From, _To, _Type, _Args}]),
    ok.

% some design thoughts
%
% For this to be a library, it should provide just a few endpoints, or
% perhaps a callback-oriented interface.
%
% I'm not sure what proper form for an API to an outside service is in
% Erlang.  There needs to be a clean break between comms library and
% IRC client, though.
%
% Comms library parses and formats messages, but maintains no state
% other than keeping the connection up (i.e., PONG).  Comms library
% should have timestamping.  The ircd mirror process is first
% destination of all inbound messages.  It should maintain all
% necessary state, and perform message routing.
%
% Under this organization, every server mirror process has a captive
% ircd_conn.  Ought they share a supervisor?
%
% Should inbound channel messages be sent to a channel mirror for
% processing?  That sounds like the cleanest approach.  The channel
% mirror maintains all the history for that channel.
%
% Channel (and user) mirrors dribble their events to the logging
% system, and query it as-needed for backing store.
%
% Talking to the channel and user mirrors we have the various clients.




% {server,
%  [letter, argcount, atom],
%  [ etc ]
% }

%% [
%% {rfc1459,
%%  [[$o, 1, operator],
%%   [$p, 0, private],
%%   [$s, 0, secret],
%%   [$i, 0, invite],
%%   [$t, 0, topic_protect],
%%   [$n, 0, no_external],
%%   [$m, 0, moderated],
%%   [$l, 1, limit],
%%   [$b, 1, ban],
%%   [$v, 1, voice],
%%   [$k, 1, key]]
%% },
%% {rfc2812, % actual detail is in rfc2811
%%  [[$O, 1, creator],
%%   [$a, 0, anonymous],
%%   [$q, 0, quiet],
%%   [$r, 0, reop],
%%   [$e, 1, ban_exception],
%%   [$I, 1, invitation]]
%% },
%% {
